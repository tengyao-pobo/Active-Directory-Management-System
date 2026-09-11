import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ApiError, request, type DirectoryKind } from './api';
import DirectoryView from './DirectoryView';
import { useI18n } from './i18n';

interface Definition { schemaVersion: 1; name: string; kind: DirectoryKind; search: string; tagId: string | null }
interface SavedFilter extends Definition { id: string; version: number; createdAt: string; updatedAt: string }
interface Tag { id: string; key: string; archivedAt: string | null }
const empty: Definition = { schemaVersion: 1, name: '', kind: 'Computer', search: '', tagId: null };
const kinds: DirectoryKind[] = ['Computer', 'User', 'Group', 'OrganizationalUnit'];

export default function SavedFiltersView({ environmentId }: { environmentId: string }) {
  return <Content key={environmentId} environmentId={environmentId} />;
}
function Content({ environmentId }: { environmentId: string }) {
  const { t } = useI18n();
  const [items, setItems] = useState<SavedFilter[] | null>(null);
  const [tags, setTags] = useState<Tag[]>([]);
  const [draft, setDraft] = useState<Definition>({ ...empty });
  const [editing, setEditing] = useState<SavedFilter | null>(null);
  const [running, setRunning] = useState<SavedFilter | null>(null);
  const [runRevision, setRunRevision] = useState(0);
  const [remove, setRemove] = useState<SavedFilter | null>(null);
  const [revision, setRevision] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const alive = useRef(true);
  const operation = useRef<AbortController | null>(null);
  const path = `/api/v1/environments/${encodeURIComponent(environmentId)}/saved-filters`;
  useEffect(() => { alive.current = true; return () => { alive.current = false; operation.current?.abort(); }; }, []);
  useEffect(() => {
    const controller = new AbortController();
    setItems(null); setTags([]); setRunning(null); setEditing(null); setRemove(null); setDraft({ ...empty }); setError('');
    void Promise.all([
      request<{ items: SavedFilter[] }>(path, { signal: controller.signal }),
      request<{ items: Tag[] }>(`/api/v1/environments/${encodeURIComponent(environmentId)}/device-tags`, { signal: controller.signal }),
    ]).then(([filters, catalog]) => { if (!controller.signal.aborted) { setItems(filters.items); setTags(catalog.items); } })
      .catch(() => { if (!controller.signal.aborted) setError('filters.unavailable'); });
    return () => controller.abort();
  }, [path, environmentId, revision]);
  async function mutate(method: 'POST' | 'PUT' | 'DELETE', target?: SavedFilter) {
    if (busy) return;
    const controller = new AbortController(); operation.current = controller;
    setBusy(true); setError(''); setNotice(''); setRunning(null);
    try {
      const { token } = await request<{ token: string }>('/api/v1/session/csrf', { signal: controller.signal });
      await request(`${path}${target ? `/${encodeURIComponent(target.id)}` : ''}`, { method, signal: controller.signal,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': token, ...(target ? { 'If-Match': `"${target.version}"` } : {}) },
        ...(method === 'DELETE' ? {} : { body: JSON.stringify({ ...draft, name: draft.name.trim(), search: draft.search.trim(), tagId: draft.kind === 'Computer' ? draft.tagId : null }) }) });
      if (!alive.current || controller.signal.aborted) return;
      setNotice(method === 'DELETE' ? 'filters.removed' : 'filters.saved'); setRevision(value => value + 1);
    } catch (failure) {
      if (!alive.current || controller.signal.aborted) return;
      setItems(null); setRunning(null); setEditing(null); setRemove(null);
      setError(failure instanceof ApiError && failure.code === 'SavedFilterLimitReached' ? 'filters.limit' :
        failure instanceof ApiError && [409, 412].includes(failure.status) ? 'filters.conflict' : 'filters.failed');
    } finally { if (alive.current && !controller.signal.aborted) setBusy(false); }
  }
  function edit(item: SavedFilter) {
    setEditing(item); setRunning(null); setRemove(null); setNotice('');
    setDraft({ schemaVersion: 1, name: item.name, kind: item.kind, search: item.search, tagId: item.tagId });
  }
  function save(event: FormEvent) { event.preventDefault(); void mutate(editing ? 'PUT' : 'POST', editing ?? undefined); }
  return <div className="saved-filters">
    <section className="panel" aria-label={t('filters.title')}><h1>{t('filters.title')}</h1><p>{t('filters.description')}</p>
      <p>{t('filters.supported')}</p><p>{t('filters.future')}</p>
      {notice && <p role="status">{t(notice)}</p>}{error && <p role="alert">{t(error)}</p>}
      {!items && !error && <p role="status">{t('directory.loadingDetails')}</p>}
      <button type="button" className="secondary-button" disabled={busy} onClick={() => { setNotice(''); setRevision(value => value + 1); }}>{t('filters.refresh')}</button>
      {items && <div className="filter-management">
        <section aria-label={t('filters.list')}><h2>{t('filters.list')}</h2><p>{t('filters.capacity', { count: items.length })}</p>
          {items.length === 0 && <p>{t('filters.empty')}</p>}
          <ul className="saved-filter-list">{items.map(item => <li key={item.id}><h3>{item.name}</h3><p>{t(`directory.title.${item.kind}`)}{item.search && ` · ${item.search}`}{item.tagId && ` · ${t(`tags.key.${tags.find(tag => tag.id === item.tagId)?.key ?? 'Unknown'}`)}`}</p>
            <div className="tag-action-row"><button type="button" disabled={busy} onClick={() => { setRunning(item); setRunRevision(value => value + 1); setRemove(null); }}>{t('filters.run')}</button>
              <button type="button" disabled={busy} onClick={() => edit(item)}>{t('filters.edit')}</button>
              <button type="button" disabled={busy} onClick={() => { setRemove(item); setRunning(null); }}>{t('filters.remove')}</button></div>
          </li>)}</ul>
          {remove && <div className="filter-removal" role="group" aria-label={t('filters.confirmRemove')}><p>{t('filters.removePrompt', { name: remove.name })}</p>
            <button type="button" disabled={busy} onClick={() => void mutate('DELETE', remove)}>{t('filters.confirmRemove')}</button>
            <button type="button" disabled={busy} onClick={() => setRemove(null)}>{t('filters.cancel')}</button></div>}
        </section>
        <form onSubmit={save} aria-label={t(editing ? 'filters.editTitle' : 'filters.createTitle')}><h2>{t(editing ? 'filters.editTitle' : 'filters.createTitle')}</h2>
          <fieldset disabled={busy}><legend>{t('filters.definition')}</legend>
            <label>{t('filters.name')}<input required maxLength={128} value={draft.name} onChange={event => setDraft(value => ({ ...value, name: event.target.value }))} /></label>
            <label>{t('filters.kind')}<select value={draft.kind} onChange={event => setDraft(value => ({ ...value, kind: event.target.value as DirectoryKind, tagId: null }))}>{kinds.map(kind => <option key={kind} value={kind}>{t(`directory.title.${kind}`)}</option>)}</select></label>
            <label>{t('filters.search')}<input maxLength={128} value={draft.search} onChange={event => setDraft(value => ({ ...value, search: event.target.value }))} /></label>
            {draft.kind === 'Computer' && <label>{t('tags.filter')}<select value={draft.tagId ?? ''} onChange={event => setDraft(value => ({ ...value, tagId: event.target.value || null }))}><option value="">{t('tags.all')}</option>{tags.map(tag => <option key={tag.id} value={tag.id}>{t(`tags.key.${tag.key}`)}{tag.archivedAt ? ` (${t('tags.archived')})` : ''}</option>)}</select></label>}
            <button type="submit" disabled={!draft.name.trim() || (!editing && items.length >= 50)}>{t(editing ? 'filters.update' : 'filters.create')}</button>
            {editing && <button type="button" onClick={() => { setEditing(null); setDraft({ ...empty }); }}>{t('filters.cancel')}</button>}
          </fieldset>
        </form>
      </div>}
    </section>
    {running && <section className="saved-filter-results" aria-label={t('filters.results')}><h2>{t('filters.resultsFor', { name: running.name })}</h2><p>{t('filters.currentAccess')}</p>
      <DirectoryView key={`${running.id}:${running.version}:${runRevision}`} environmentId={environmentId} kind={running.kind} initialSearch={running.search}
        savedFilter={{ id: running.id, version: running.version }} />
    </section>}
  </div>;
}
