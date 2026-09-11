import { describe, expect, it } from 'vitest';
import { formatInventoryBytes, reportedInstallDate } from '../../src/inventoryDisplay';

describe('inventory values', () => {
  it('keeps zero and exact uint64 counts without unsafe Number conversion', () => {
    expect(formatInventoryBytes('0')).toBe('0 B');
    expect(formatInventoryBytes('1023')).toBe('1023 B');
    expect(formatInventoryBytes('1024')).toBe('1.0 KiB');
    expect(formatInventoryBytes('17179869184')).toBe('16.0 GiB');
    expect(formatInventoryBytes('18446744073709551615')).toBe('15.9 EiB');
  });
  it('rejects ambiguous or invalid counts rather than reporting zero capacity', () => {
    for (const value of [null, undefined, '', '01', '-1', '1.5', '1e3', ' 1024', '18446744073709551616'])
      expect(formatInventoryBytes(value)).toBeNull();
  });
  it('only presents an actual reported calendar date', () => {
    expect(reportedInstallDate('20240229')).toBe('2024-02-29');
    expect(reportedInstallDate('20260912')).toBe('2026-09-12');
    for (const value of [null, undefined, '', '20230229', '20260431', '20260001', '20261301', '00000101', '2026-09-12'])
      expect(reportedInstallDate(value)).toBeNull();
  });
});
