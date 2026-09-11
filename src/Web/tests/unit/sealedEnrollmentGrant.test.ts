import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { EnrollmentGrantRecipient, type GrantContext, type SealedGrantEnvelope } from '../../src/sealedEnrollmentGrant';
import { decodeBase64Url, encodeBase64Url } from '../../src/webauthn';

const context: GrantContext = { environmentId: '11223344-5566-7788-99aa-bbccddeeff00',
  operationId: 'ffeeddcc-bbaa-9988-7766-554433221100' };
const canary = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 1));
function payload(): Uint8Array<ArrayBuffer> {
  const value = new Uint8Array(116);
  value.set(new TextEncoder().encode('ADGRTOKN'), 0);
  value[9] = 1; value[11] = 1;
  value.set(new TextEncoder().encode(context.environmentId), 12);
  value.set(new TextEncoder().encode(context.operationId), 48);
  value.set(canary, 84);
  return value;
}
async function seal(recipient: EnrollmentGrantRecipient, value = payload(), hash = 'SHA-256'): Promise<SealedGrantEnvelope> {
  const key = await crypto.subtle.importKey('spki', decodeBase64Url(recipient.publicKey.subjectPublicKeyInfo),
    { name: 'RSA-OAEP', hash }, false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, value);
  return { formatVersion: 1, recipientKeyFingerprint: recipient.publicKey.fingerprint,
    ciphertext: encodeBase64Url(ciphertext) };
}

describe('sealed initial enrollment grant client', () => {
  let recipient: EnrollmentGrantRecipient;
  let envelope: SealedGrantEnvelope;
  beforeAll(async () => {
    vi.stubGlobal('isSecureContext', true);
    recipient = await EnrollmentGrantRecipient.create();
    envelope = await seal(recipient);
  });
  afterAll(() => { recipient.dispose(); vi.unstubAllGlobals(); });

  it('creates a non-exportable private key and exports only canonical public metadata', async () => {
    const generate = crypto.subtle.generateKey.bind(crypto.subtle);
    let privateKey: CryptoKey | undefined;
    const spy = vi.spyOn(crypto.subtle, 'generateKey').mockImplementation(async (...args) => {
      const pair = await generate(...args) as CryptoKeyPair;
      privateKey = pair.privateKey;
      return pair;
    });
    try {
      const other = await EnrollmentGrantRecipient.create();
      expect(privateKey?.extractable).toBe(false);
      await expect(crypto.subtle.exportKey('pkcs8', privateKey!)).rejects.toThrow();
      const der = decodeBase64Url(other.publicKey.subjectPublicKeyInfo);
      expect(der.byteLength).toBeLessThanOrEqual(512);
      expect(other.publicKey.fingerprint).toBe(encodeBase64Url(await crypto.subtle.digest('SHA-256', der)));
      expect(Object.keys(JSON.parse(JSON.stringify(other)))).toEqual(['publicKey']);
      expect(other.publicKey.fingerprint).not.toBe(recipient.publicKey.fingerprint);
      other.dispose();
    } finally { spy.mockRestore(); }
  });

  it('decodes the exact binary token, permits redelivery, and wipes callback buffers', async () => {
    let retained: Uint8Array | undefined;
    await recipient.consume(envelope, context, async token => { expect(token).toEqual(canary); retained = token; });
    expect(retained).toEqual(new Uint8Array(32));
    await recipient.consume(envelope, context, async token => { expect(token).toEqual(canary); });
  });

  it.each([
    ['environment', { ...context, environmentId: '21223344-5566-7788-99aa-bbccddeeff00' }],
    ['operation', { ...context, operationId: 'efeeddcc-bbaa-9988-7766-554433221100' }],
    ['uppercase', { ...context, environmentId: context.environmentId.toUpperCase() }],
    ['empty', { ...context, operationId: '00000000-0000-0000-0000-000000000000' }],
  ])('rejects %s context transplantation', async (_name, expected) => {
    const use = vi.fn();
    await expect(recipient.consume(envelope, expected, use)).rejects.toThrow('InvalidSealedGrant');
    expect(use).not.toHaveBeenCalled();
  });

  it.each(['magic', 'version', 'purpose', 'uppercase', 'zeroToken', 'short', 'long'])('rejects malformed plaintext: %s', async kind => {
    let value = payload();
    if (kind === 'magic') value[0] ^= 1;
    if (kind === 'version') value[9] = 2;
    if (kind === 'purpose') value[11] = 2;
    if (kind === 'uppercase') value.set(new TextEncoder().encode(context.environmentId.toUpperCase()), 12);
    if (kind === 'zeroToken') value.fill(0, 84);
    if (kind === 'short') value = value.slice(0, 115);
    if (kind === 'long') { const longer = new Uint8Array(117); longer.set(value); value = longer; }
    await expect(recipient.consume(await seal(recipient, value), context, vi.fn())).rejects.toThrow('InvalidSealedGrant');
  });

  it('rejects wrong keys, ciphertext tampering, SHA-1 padding and malformed wire values', async () => {
    const other = await EnrollmentGrantRecipient.create();
    const wrongKeyEnvelope = { ...envelope, recipientKeyFingerprint: other.publicKey.fingerprint };
    await expect(other.consume(wrongKeyEnvelope, context, vi.fn())).rejects.toThrow('InvalidSealedGrant');
    other.dispose();
    const tampered = new Uint8Array(decodeBase64Url(envelope.ciphertext)); tampered[0] ^= 1;
    for (const wire of [null, [], { ...envelope, ciphertext: encodeBase64Url(tampered.buffer) },
      { ...envelope, ciphertext: envelope.ciphertext.slice(1) }, { ...envelope, ciphertext: envelope.ciphertext + '=' },
      { ...envelope, formatVersion: 2 }, { ...envelope, token: 'forged' },
      { ...envelope, recipientKeyFingerprint: 'a'.repeat(43) }, await seal(recipient, payload(), 'SHA-1')]) {
      await expect(recipient.consume(wire, context, vi.fn())).rejects.toThrow('InvalidSealedGrant');
    }
  });

  it('wipes callback failure buffers and hides underlying errors', async () => {
    let retained: Uint8Array | undefined;
    await expect(recipient.consume(envelope, context, async token => {
      retained = token; throw new Error('secret-canary-do-not-report');
    })).rejects.toThrow(/^GrantDeliveryFailed$/);
    expect(retained).toEqual(new Uint8Array(32));
  });

  it('rejects concurrent consumption and clears active data when disposed', async () => {
    const other = await EnrollmentGrantRecipient.create();
    const wire = await seal(other);
    let release: (() => void) | undefined;
    let entered: (() => void) | undefined;
    const started = new Promise<void>(resolve => { entered = resolve; });
    let retained: Uint8Array | undefined;
    let activeSignal: AbortSignal | undefined;
    const run = other.consume(wire, context, async (token, signal) => {
      activeSignal = signal;
      retained = token; entered!(); await new Promise<void>(resolve => { release = resolve; });
    });
    await started;
    await expect(other.consume(wire, context, vi.fn())).rejects.toThrow('InvalidSealedGrant');
    other.dispose();
    expect(activeSignal?.aborted).toBe(true);
    expect(retained).toEqual(new Uint8Array(32));
    release!(); await expect(run).rejects.toMatchObject({ name: 'AbortError', message: 'GrantDeliveryCancelled' });
    await expect(other.consume(wire, context, vi.fn())).rejects.toThrow('InvalidSealedGrant');
  });

  it('cancels disposal during decryption without invoking the callback', async () => {
    const other = await EnrollmentGrantRecipient.create();
    const wire = await seal(other);
    const decrypt = crypto.subtle.decrypt.bind(crypto.subtle);
    let entered: (() => void) | undefined;
    let release: (() => void) | undefined;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    const spy = vi.spyOn(crypto.subtle, 'decrypt').mockImplementation(async (...args) => {
      const result = await decrypt(...args); entered!(); await gate; return result;
    });
    try {
      const callback = vi.fn();
      const run = other.consume(wire, context, callback);
      await started; other.dispose(); release!();
      await expect(run).rejects.toMatchObject({ name: 'AbortError', message: 'GrantDeliveryCancelled' });
      expect(callback).not.toHaveBeenCalled();
    } finally { release!(); spy.mockRestore(); other.dispose(); }
  });

  it('keeps callback cancellation distinct from invalid ciphertext without exposing its details', async () => {
    await expect(recipient.consume(envelope, context, async () => {
      throw new DOMException('private cancellation detail', 'AbortError');
    })).rejects.toMatchObject({ name: 'AbortError', message: 'GrantDeliveryCancelled' });
  });

  it('fails without a secure browser context', async () => {
    vi.stubGlobal('isSecureContext', false);
    try { await expect(EnrollmentGrantRecipient.create()).rejects.toThrow(/^InvalidSealedGrant$/); }
    finally { vi.stubGlobal('isSecureContext', true); }
  });
});
