export type BitLockerStatusField = 'volumeType' | 'protectionStatus' | 'conversionStatus' | 'encryptionMethod';

const labels: Record<BitLockerStatusField, Readonly<Record<number, string>>> = {
  volumeType: { 0: 'bitlocker.volume.system', 1: 'bitlocker.volume.fixed', 2: 'bitlocker.volume.removable' },
  protectionStatus: { 0: 'bitlocker.protection.off', 1: 'bitlocker.protection.on', 2: 'bitlocker.unknown' },
  conversionStatus: { 0: 'bitlocker.conversion.decrypted', 1: 'bitlocker.conversion.encrypted', 2: 'bitlocker.conversion.encrypting',
    3: 'bitlocker.conversion.decrypting', 4: 'bitlocker.conversion.encryptionPaused', 5: 'bitlocker.conversion.decryptionPaused' },
  encryptionMethod: { 0: 'bitlocker.method.none', 1: 'bitlocker.method.aes128Diffuser', 2: 'bitlocker.method.aes256Diffuser',
    3: 'bitlocker.method.aes128', 4: 'bitlocker.method.aes256', 5: 'bitlocker.method.hardware',
    6: 'bitlocker.method.xts128', 7: 'bitlocker.method.xts256' },
};

// Unknown future provider codes remain unknown; they must never fall through to Off or a healthy state.
export function bitLockerStatusKey(field: BitLockerStatusField, value: number | null): string {
  return value !== null && Number.isInteger(value) && value >= 0 && value <= 0xffffffff
    ? labels[field][value] ?? 'bitlocker.unknown' : 'bitlocker.unknown';
}
