import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { afterAll, beforeAll, expect, it, vi } from 'vitest';
import { EnrollmentGrantRecipient } from '../../src/sealedEnrollmentGrant';
import { encodeBase64Url } from '../../src/webauthn';

beforeAll(() => { vi.stubGlobal('isSecureContext', true); });
afterAll(() => { vi.unstubAllGlobals(); });

it('consumes a production .NET envelope with the actual non-exportable WebCrypto recipient', async () => {
  const recipient = await EnrollmentGrantRecipient.create();
  try {
    const context = { environmentId: '11223344-5566-7788-99aa-bbccddeeff00',
      operationId: 'ffeeddcc-bbaa-9988-7766-554433221100' };
    const request = { subjectPublicKeyInfo: recipient.publicKey.subjectPublicKeyInfo, ...context };
    const dotnet = process.env.DOTNET_ROOT ? resolve(process.env.DOTNET_ROOT, process.platform === 'win32' ? 'dotnet.exe' : 'dotnet') : 'dotnet';
    const dll = resolve(process.cwd(), '../../tests/EnrollmentGrantInterop/bin/Release/net10.0/EnrollmentGrantInterop.dll');
    const response = await new Promise<string>((resolveResponse, reject) => {
      const child = spawn(dotnet, [dll], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
      let output = '';
      const timeout = setTimeout(() => { child.kill(); reject(new Error('InteropTimeout')); }, 15000);
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (chunk: string) => {
        output += chunk;
        if (output.length > 4096) { child.kill(); reject(new Error('InteropOutputLimit')); }
      });
      child.stderr.resume();
      child.on('error', () => { clearTimeout(timeout); reject(new Error('InteropProcessUnavailable')); });
      child.on('close', code => { clearTimeout(timeout); if (code === 0) resolveResponse(output); else reject(new Error('InteropFailed')); });
      child.stdin.on('error', () => { /* The process close/error determines the result. */ });
      child.stdin.end(JSON.stringify(request));
    });
    const wire = JSON.parse(response) as { formatVersion: 1; recipientKeyFingerprint: string; ciphertext: string; tokenSha256: string };
    const envelope = { formatVersion: wire.formatVersion, recipientKeyFingerprint: wire.recipientKeyFingerprint, ciphertext: wire.ciphertext };
    let retained: Uint8Array | undefined;
    await recipient.consume(envelope, context, async token => {
      expect(encodeBase64Url(await crypto.subtle.digest('SHA-256', token))).toBe(wire.tokenSha256);
      retained = token;
    });
    expect(retained).toEqual(new Uint8Array(32));
    await expect(recipient.consume(envelope, { ...context, operationId: context.environmentId }, vi.fn())).rejects.toThrow('InvalidSealedGrant');
  } finally { recipient.dispose(); }
});
