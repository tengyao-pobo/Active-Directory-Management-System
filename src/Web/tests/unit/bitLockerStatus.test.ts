import { describe, expect, it } from 'vitest';
import { bitLockerStatusKey, type BitLockerStatusField } from '../../src/bitLockerStatus';

describe('BitLocker provider observations', () => {
  it('preserves meaningful zero values without treating them as unknown', () => {
    expect(bitLockerStatusKey('protectionStatus', 0)).toBe('bitlocker.protection.off');
    expect(bitLockerStatusKey('conversionStatus', 0)).toBe('bitlocker.conversion.decrypted');
    expect(bitLockerStatusKey('encryptionMethod', 0)).toBe('bitlocker.method.none');
    expect(bitLockerStatusKey('volumeType', 0)).toBe('bitlocker.volume.system');
  });
  it('does not label unknown, future or invalid codes as protected', () => {
    const fields: BitLockerStatusField[] = ['volumeType', 'protectionStatus', 'conversionStatus', 'encryptionMethod'];
    for (const field of fields) for (const code of [null, -1, 1.5, 999, 0xffffffff, NaN, Infinity])
      expect(bitLockerStatusKey(field, code)).toBe('bitlocker.unknown');
    expect(bitLockerStatusKey('protectionStatus', 2)).toBe('bitlocker.unknown');
  });
});
