import { useState, type FormEvent } from 'react';
import DirectoryView from './DirectoryView';
import { useI18n } from './i18n';
import type { DirectoryKind } from './api';

const kinds: DirectoryKind[] = ['User', 'Group', 'Computer', 'OrganizationalUnit'];

export default function DirectorySearch({ environmentId }: { environmentId: string }) {
  const { t } = useI18n();
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState<{ text: string; revision: number } | null>(null);
  function submit(event: FormEvent) {
    event.preventDefault();
    const text = draft.trim();
    if (text) setQuery(previous => ({ text, revision: (previous?.revision ?? 0) + 1 }));
  }
  return <section className="global-directory-search" aria-labelledby="global-search-title">
    <header className="directory-header"><div><span className="eyebrow">{t('directory.eyebrow')}</span><h1 id="global-search-title">{t('nav.search')}</h1><p>{t('globalSearch.description')}</p></div></header>
    <form className="directory-search" role="search" onSubmit={submit}>
      <label htmlFor="global-query">{t('globalSearch.label')}</label>
      <div><input id="global-query" maxLength={128} value={draft} onChange={event => setDraft(event.target.value)} placeholder={t('directory.searchPlaceholder')} />
        <button className="secondary-button" type="submit" disabled={!draft.trim()}>{t('directory.searchAction')}</button>
        {query && <button className="secondary-button" type="button" onClick={() => { setDraft(''); setQuery(null); }}>{t('directory.clearSearch')}</button>}
      </div>
    </form>
    {!query && <p role="status">{t('globalSearch.hint')}</p>}
    {query && <div key={`${environmentId}:${query.revision}`} className="global-directory-results">
      <p role="status">{t('globalSearch.results', { query: query.text })}</p>
      {kinds.map(kind => <DirectoryView key={kind} environmentId={environmentId} kind={kind} initialSearch={query.text} />)}
    </div>}
  </section>;
}
