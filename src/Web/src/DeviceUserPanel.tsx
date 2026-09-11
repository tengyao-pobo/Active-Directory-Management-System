import { useEffect, useRef, useState } from 'react';
import { ApiError, getDirectoryObjects, request, type DirectoryObject } from './api';
import { useI18n } from './i18n';

interface Link { user: { id: string; name: string } | null; version: number; updatedAt: string | null; canEdit: boolean }
interface Page { items: { id: string; name: string; updatedAt: string }[]; nextCursor: string | null }
export default function DeviceUserPanel({ environmentId, id, kind }: { environmentId: string; id: string; kind: 'User' | 'Computer' }) {
  const { t, locale } = useI18n();
  const [link, setLink] = useState<Link | null>(null);
  const [page, setPage] = useState<Page | null>(null);
  const [query, setQuery] = useState('');
  const [candidates, setCandidates] = useState<DirectoryObject[]>([]);
  const [candidateMore, setCandidateMore] = useState(false);
  const [selected, setSelected] = useState<{ id: string; name: string } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const pending = useRef<AbortController | null>(null);
  const base = `/api/v1/environments/${encodeURIComponent(environmentId)}`;
  const path = kind === 'Computer' ? `${base}/devices/${encodeURIComponent(id)}/user` : `${base}/users/${encodeURIComponent(id)}/devices`;
  useEffect(() => {
    const controller = new AbortController(); pending.current = controller;
    setLink(null); setPage(null); setError(''); setCandidates([]); setSelected(null); setQuery(''); setBusy(true);
    void request<Link | Page>(path, { signal: controller.signal }).then(value => {
      if (controller.signal.aborted) return;
      if ('version' in value) { setLink(value); setSelected(value.user); } else setPage(value);
    }).catch(() => { if (!controller.signal.aborted) setError('links.unavailable'); })
      .finally(() => { if (!controller.signal.aborted) setBusy(false); });
    return () => { controller.abort(); pending.current?.abort(); };
  }, [path, revision]);
  async function search() {
    pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    setCandidates([]); setSelected(null); setBusy(true); setError('');
    try {
      const result = await getDirectoryObjects(environmentId, 'User', query.trim(), undefined, controller.signal);
      if (!controller.signal.aborted) { setCandidates(result.items); setCandidateMore(Boolean(result.nextCursor)); }
    } catch { if (!controller.signal.aborted) setError('links.unavailable'); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }
  async function save(user: { id: string; name: string } | null) {
    pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    setBusy(true); setError('');
    try {
      const { token } = await request<{ token: string }>('/api/v1/session/csrf', { signal: controller.signal });
      await request(path, { method: 'PUT', signal: controller.signal, headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': token, 'If-Match': `"${link?.version ?? 0}"` }, body: JSON.stringify({ userId: user?.id ?? null }) });
      if (!controller.signal.aborted) setRevision(value => value + 1);
    } catch (failure) {
      if (!controller.signal.aborted) {
        setError(failure instanceof ApiError && [409, 412].includes(failure.status) ? 'asset.conflict' : 'asset.saveFailed');
        setLink(null); setCandidates([]); setSelected(null);
      }
    } finally { if (!controller.signal.aborted) setBusy(false); }
  }
  async function next() {
    if (!page?.nextCursor) return;
    const cursor = page.nextCursor; const controller = new AbortController(); pending.current = controller;
    setPage(null); setBusy(true); setError('');
    try { const value = await request<Page>(`${path}?cursor=${encodeURIComponent(cursor)}`, { signal: controller.signal }); if (!controller.signal.aborted) setPage(value); }
    catch (failure) { if (!controller.signal.aborted) setError(failure instanceof ApiError && failure.status === 409 ? 'links.changed' : 'links.unavailable'); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  }
  const date = (value: string) => new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
  return <section className="asset-panel" aria-label={t('links.title')}>
    <h3>{t('links.title')}</h3><p>{t('links.description')}</p>
    {busy && <p role="status">{t('directory.loadingDetails')}</p>}{error && <p role="alert">{t(error)}</p>}
    {link && <>
      <p>{t('links.current')}: <strong>{link.user?.name ?? t('links.none')}</strong></p>
      {link.updatedAt && <p>{t('links.updated', { date: date(link.updatedAt) })}</p>}
      {link.canEdit && <>
        <label>{t('links.search')}<input aria-label={t('links.search')} value={query} maxLength={128} disabled={busy} onChange={e => { setQuery(e.target.value); setCandidates([]); setSelected(null); }} /></label>
        <button type="button" className="secondary-button" disabled={busy || !query.trim()} onClick={() => void search()}>{t('directory.searchAction')}</button>
        {candidates.map(user => <button type="button" className="secondary-button" key={user.id} aria-pressed={selected?.id === user.id} onClick={() => setSelected(user)}>{user.name} ({user.samAccountName ?? user.id})</button>)}
        {candidateMore && <p>{t('links.refine')}</p>}
        {selected && <p>{t('links.selected', { name: selected.name })}</p>}
        <button type="button" className="secondary-button" disabled={busy || !selected || selected.id === link.user?.id} onClick={() => void save(selected)}>{t('links.assign')}</button>
        <button type="button" className="secondary-button" disabled={busy || !link.user} onClick={() => void save(null)}>{t('links.clear')}</button>
      </>}
    </>}
    {page && <>{page.items.length === 0 && <p>{t('links.empty')}</p>}<ul>{page.items.map(item => <li key={item.id}><strong>{item.name}</strong><p>{t('links.updated', { date: date(item.updatedAt) })}</p></li>)}</ul><button type="button" className="secondary-button" disabled={busy || !page.nextCursor} onClick={() => void next()}>{t('directory.next')}</button></>}
    <button type="button" className="secondary-button" disabled={busy} onClick={() => setRevision(value => value + 1)}>{t('links.reload')}</button>
  </section>;
}
