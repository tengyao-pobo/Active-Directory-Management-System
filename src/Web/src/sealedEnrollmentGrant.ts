import { decodeBase64Url, encodeBase64Url } from './webauthn';

export type GrantContext = Readonly<{ environmentId: string; operationId: string }>;
export type SealedGrantEnvelope = Readonly<{
  formatVersion: 1; recipientKeyFingerprint: string; ciphertext: string;
}>;

const rejected = () => new Error('InvalidSealedGrant');
const cancelled = () => new DOMException('GrantDeliveryCancelled', 'AbortError');
const canonicalId = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const emptyId = '00000000-0000-0000-0000-000000000000';
const magic = new TextEncoder().encode('ADGRTOKN');

function validId(value: unknown): value is string {
  return typeof value === 'string' && canonicalId.test(value) && value !== emptyId;
}

function decodeExact(value: unknown, length: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || value.length !== Math.ceil(length * 4 / 3)) throw rejected();
  const result = new Uint8Array(decodeBase64Url(value));
  if (result.length !== length || encodeBase64Url(result.buffer) !== value) throw rejected();
  return result;
}

/** Dormant delivery primitive. It does not authorize operations, call an API, or persist keys. */
export class EnrollmentGrantRecipient {
  #key: CryptoKey | undefined;
  #busy = false;
  #disposed = false;
  #activeToken: Uint8Array<ArrayBuffer> | undefined;
  #activeAbort: AbortController | undefined;
  readonly publicKey: Readonly<{ subjectPublicKeyInfo: string; fingerprint: string }>;

  private constructor(key: CryptoKey, spki: ArrayBuffer, fingerprint: ArrayBuffer) {
    this.#key = key;
    this.publicKey = Object.freeze({
      subjectPublicKeyInfo: encodeBase64Url(spki), fingerprint: encodeBase64Url(fingerprint),
    });
  }

  static async create(): Promise<EnrollmentGrantRecipient> {
    try {
      if (globalThis.isSecureContext !== true || !globalThis.crypto?.subtle) throw rejected();
      const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 3072,
        publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, false, ['encrypt', 'decrypt']);
      if (pair.privateKey.extractable) throw rejected();
      const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
      const fingerprint = await crypto.subtle.digest('SHA-256', spki);
      return new EnrollmentGrantRecipient(pair.privateKey, spki, fingerprint);
    } catch { throw rejected(); }
  }

  /** Call on ACK, revocation, expiry, session/environment change, or leaving the delivery flow. */
  dispose(): void {
    this.#disposed = true;
    this.#key = undefined;
    this.#activeToken?.fill(0);
    this.#activeAbort?.abort();
  }

  /**
   * expected must come from the authenticated operation/session, never from the envelope.
   * The callback must not log, stringify, persist, or retain token copies. Its buffer is wiped
   * on completion. This helper intentionally exposes no base64 bearer string or private key.
   */
  async consume(envelope: unknown, expected: GrantContext,
    consumeToken: (token: Uint8Array<ArrayBuffer>, signal: AbortSignal) => Promise<void>): Promise<void> {
    if (this.#busy || this.#disposed || !this.#key) throw rejected();
    this.#busy = true;
    const abort = new AbortController();
    this.#activeAbort = abort;
    let plaintext: Uint8Array<ArrayBuffer> | undefined;
    let token: Uint8Array<ArrayBuffer> | undefined;
    try {
      try {
        const environmentId = expected.environmentId;
        const operationId = expected.operationId;
        if (!validId(environmentId) || !validId(operationId) ||
          !envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw rejected();
        const wire = envelope as Record<string, unknown>;
        if (Object.keys(wire).sort().join(',') !== 'ciphertext,formatVersion,recipientKeyFingerprint' ||
          wire.formatVersion !== 1 || wire.recipientKeyFingerprint !== this.publicKey.fingerprint) throw rejected();
        decodeExact(wire.recipientKeyFingerprint, 32);
        const ciphertext = decodeExact(wire.ciphertext, 384);
        plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, this.#key, ciphertext));
        if (plaintext.length !== 116 ||
          !magic.every((byte, index) => plaintext![index] === byte) ||
          plaintext[8] !== 0 || plaintext[9] !== 1 || plaintext[10] !== 0 || plaintext[11] !== 1) throw rejected();
        const environmentBytes = new TextEncoder().encode(environmentId);
        const operationBytes = new TextEncoder().encode(operationId);
        if (!environmentBytes.every((byte, index) => plaintext![12 + index] === byte) ||
          !operationBytes.every((byte, index) => plaintext![48 + index] === byte)) throw rejected();
        token = plaintext.slice(84);
        if (!token.some(byte => byte !== 0)) throw rejected();
        plaintext.fill(0);
      } catch {
        if (abort.signal.aborted) throw cancelled();
        throw rejected();
      }
      if (abort.signal.aborted) throw cancelled();
      this.#activeToken = token;
      try { await consumeToken(token, abort.signal); }
      catch (error) {
        if (abort.signal.aborted || (error instanceof DOMException && error.name === 'AbortError')) throw cancelled();
        // Callback errors may contain token material; never retain their message or cause.
        // eslint-disable-next-line preserve-caught-error
        throw new Error('GrantDeliveryFailed');
      }
      if (abort.signal.aborted) throw cancelled();
    } finally {
      token?.fill(0); plaintext?.fill(0); this.#activeToken = undefined; this.#activeAbort = undefined; this.#busy = false;
    }
  }
}
