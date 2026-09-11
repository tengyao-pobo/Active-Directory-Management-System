import { describe, it, expect } from 'vitest';
import { creationOptions, requestOptions, encodeBase64Url, decodeBase64Url } from '../../src/webauthn';

describe('WebAuthn wire conversion', () => {
  it('round-trips binary credential identifiers without losing zero/high bytes', () => {
    const bytes = new Uint8Array([0, 1, 255, 254, 128, 64]);
    expect(new Uint8Array(decodeBase64Url(encodeBase64Url(bytes.buffer)))).toEqual(bytes);
  });
  it('preserves RP, UV policy and challenge while decoding allow-list IDs', () => {
    const options = requestOptions({ challenge: 'AAH_', rpId: 'console.example.test', userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: 'AQI' }] });
    expect(options.userVerification).toBe('required');
    expect(options.rpId).toBe('console.example.test');
    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(new Uint8Array([0, 1, 255]));
    expect(new Uint8Array(options.allowCredentials![0].id as ArrayBuffer)).toEqual(new Uint8Array([1, 2]));
  });
  it('decodes user handles for registration without replacing server selection policy', () => {
    const options = creationOptions({ challenge: 'AQI', user: { id: 'AAH_', name: 'synthetic', displayName: 'Synthetic' },
      rp: { name: 'Console', id: 'console.example.test' }, pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'required' } });
    expect(new Uint8Array(options.user.id as ArrayBuffer)).toEqual(new Uint8Array([0, 1, 255]));
    expect(options.authenticatorSelection?.residentKey).toBe('required');
  });
  it('rejects invalid and excessive base64url input', () => {
    expect(() => decodeBase64Url('not!base64')).toThrow();
    expect(() => decodeBase64Url('a'.repeat(65537))).toThrow();
  });
});
