import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import zh from './locales/zh-TW.json';
import en from './locales/en-US.json';
export type Locale = 'zh-TW' | 'en-US';
export const dictionaries: Record<Locale, Record<string, string>> = { 'zh-TW': zh, 'en-US': en };
export function translate(locale: Locale, key: string, vars: Record<string, string | number> = {}) {
  return (dictionaries[locale][key] ?? dictionaries['zh-TW'][key] ?? key)
    .replace(/\{(\w+)\}/g, (_, name: string) => String(vars[name] ?? `{${name}}`));
}
function initialLocale(): Locale {
  try { return localStorage.getItem('itmc.locale') === 'en-US' ? 'en-US' : 'zh-TW'; }
  catch { return 'zh-TW'; }
}
const Context = createContext<{ locale: Locale; setLocale: (locale: Locale) => void; t: (key: string, vars?: Record<string, string | number>) => string } | null>(null);
export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, updateLocale] = useState<Locale>(initialLocale);
  const setLocale = useCallback((next: Locale) => {
    if (next !== 'zh-TW' && next !== 'en-US') return;
    updateLocale(next);
    try { localStorage.setItem('itmc.locale', next); } catch { /* Private browsing may reject storage. */ }
  }, []);
  useEffect(() => { document.documentElement.lang = locale; }, [locale]);
  const t = useCallback((key: string, vars?: Record<string, string | number>) => translate(locale, key, vars), [locale]);
  return <Context.Provider value={{ locale, setLocale, t }}>{children}</Context.Provider>;
}
export function useI18n() {
  const context = useContext(Context);
  if (!context) throw new Error('I18nProvider missing');
  return context;
}
