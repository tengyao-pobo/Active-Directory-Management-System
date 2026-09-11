export const hardwareFields = {
  System: ['Manufacturer', 'Model', 'TotalPhysicalMemory'],
  Product: ['UUID'],
  Bios: ['Manufacturer', 'SerialNumber', 'SMBIOSBIOSVersion', 'ReleaseDate'],
  OperatingSystem: ['Caption', 'Version', 'BuildNumber', 'InstallDate', 'LastBootUpTime'],
  Processor: ['Name', 'Manufacturer', 'NumberOfCores', 'NumberOfLogicalProcessors'],
  Memory: ['BankLabel', 'DeviceLocator', 'Capacity', 'Speed'],
  Video: ['Name', 'AdapterRAM'],
  Disk: ['Model', 'SerialNumber', 'Size', 'MediaType'],
  Battery: ['Name', 'EstimatedChargeRemaining', 'DesignCapacity', 'FullChargeCapacity'],
} as const;
export type HardwareKind = keyof typeof hardwareFields;

// Counts from WMI can exceed JavaScript's safe integer range. The API contract uses decimal strings.
export function formatInventoryBytes(value: string | null | undefined): string | null {
  if (value == null || !/^(0|[1-9][0-9]{0,19})$/.test(value)) return null;
  const bytes = BigInt(value);
  if (bytes > 18446744073709551615n) return null;
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']; let scale = 1n; let unit = 0;
  while (unit < units.length - 1 && bytes >= scale * 1024n) { scale *= 1024n; unit++; }
  if (unit === 0) return `${bytes} B`;
  const tenths = bytes * 10n / scale;
  return `${tenths / 10n}.${tenths % 10n} ${units[unit]}`;
}

export function reportedInstallDate(value: string | null | undefined): string | null {
  if (!value || !/^[0-9]{8}$/.test(value)) return null;
  const year = Number(value.slice(0, 4)), month = Number(value.slice(4, 6)), day = Number(value.slice(6, 8));
  if (year < 1000 || month < 1 || month > 12 || day < 1 || day > 31) return null;
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year && date.getUTCMonth() === month - 1 && date.getUTCDate() === day
    ? `${value.slice(0, 4)}-${value.slice(4, 6)}-${value.slice(6, 8)}` : null;
}
