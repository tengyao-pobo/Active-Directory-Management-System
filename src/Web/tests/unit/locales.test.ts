import { describe, it, expect } from 'vitest';
import zh from '../../src/locales/zh-TW.json';
import en from '../../src/locales/en-US.json';
describe('Language resources', () => {
  it('keeps every key and interpolation placeholder identical across languages', () => {
    expect(Object.keys(en).sort()).toEqual(Object.keys(zh).sort());
    for (const key of Object.keys(zh) as (keyof typeof zh)[]) {
      expect(en[key].trim()).not.toBe('');
      expect(en[key].match(/\{\w+\}/g)?.sort() ?? []).toEqual(zh[key].match(/\{\w+\}/g)?.sort() ?? []);
    }
  });
});
