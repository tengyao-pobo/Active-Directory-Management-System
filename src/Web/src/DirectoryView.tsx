import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ApiError, getDirectoryObject, getDirectoryObjects, getDirectoryStatus } from './api';
import { useI18n } from './i18n';
import './directory.css';
import DeviceTabs from './DeviceTabs';
import DeviceUserPanel from './DeviceUserPanel';
import DirectoryProposal from './DirectoryProposal';
import FavoriteButton from './FavoriteButton';

export type DirectoryKind = 'User' | 'Group' | 'Computer' | 'OrganizationalUnit';

export interface DirectoryViewProps {
  kind: DirectoryKind;
  environmentId: string;
  initialSearch?: string;
}

interface DirectoryObject {
  id: string;
  kind: DirectoryKind;
  name: string;
  distinguishedName: string;
  samAccountName?: string | null;
  department?: string | null;
  objectSid?: string | null;
  usnChanged: number;
  isProtected: boolean;
  protectionKnown: boolean;
  parentOuId?: string | null;
}

interface DirectoryStatus {
  status: string;
  stale: boolean;
  completedAt?: string | null;
  attemptedAt?: string | null;
  errorCode?: string | null;
  mutationAvailable: boolean;
}

type ViewPhase = 'loading' | 'ready' | 'unconfigured' | 'syncing' | 'failed' | 'unavailable' | 'error';

function errorPhase(error: unknown): 'forbidden' | 'notFound' | 'unavailable' | 'error' {
  if (!(error instanceof ApiError)) return 'error';
  if (error.status === 403) return 'forbidden';
  if (error.status === 404) return 'notFound';
  if (error.status === 503) return 'unavailable';
  return 'error';
}

function statusPhase(status: DirectoryStatus): ViewPhase {
  if (status.status === 'Unconfigured') return 'unconfigured';
  if (status.status === 'Failed') return 'failed';
  if (status.status !== 'Ready') return 'syncing';
  return status.stale ? 'unavailable' : 'ready';
}

function DirectoryViewContent({ kind, environmentId, initialSearch }: DirectoryViewProps) {
  const { t, locale } = useI18n();
  const [phase, setPhase] = useState<ViewPhase>('loading');
  const [status, setStatus] = useState<DirectoryStatus | null>(null);
  const [statusError, setStatusError] = useState<unknown>(null);
  const [draftSearch, setDraftSearch] = useState(initialSearch ?? '');
  const [committedSearch, setCommittedSearch] = useState(initialSearch ?? '');
  const [items, setItems] = useState<DirectoryObject[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [cursorStack, setCursorStack] = useState<(string | null)[]>([null]);
  const [pageIndex, setPageIndex] = useState(0);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState<unknown>(null);
  const [restartNotice, setRestartNotice] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<DirectoryObject | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<unknown>(null);
  const [detailAsOf, setDetailAsOf] = useState<string | null>(null);
  const [sourceAsOf, setSourceAsOf] = useState<string | null>(null);
  const listRequest = useRef(0);
  const detailRequest = useRef(0);
  const listAbort = useRef<AbortController | null>(null);
  const detailAbort = useRef<AbortController | null>(null);

  const clearDetail = () => {
    detailAbort.current?.abort();
    detailRequest.current += 1;
    setSelectedId(null);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(false);
    setDetailAsOf(null);
  };

  const loadPage = async (cursor: string | null, search: string, stack: (string | null)[], index: number, retrySnapshot = true) => {
    listAbort.current?.abort();
    const controller = new AbortController();
    listAbort.current = controller;
    const requestId = ++listRequest.current;
    clearDetail();
    setListLoading(true);
    setListError(null);
    setItems([]);
    try {
      const result = await getDirectoryObjects(environmentId, kind, search, cursor ?? undefined, controller.signal);
      if (requestId !== listRequest.current) return;
      setItems(result.items as DirectoryObject[]);
      setNextCursor(result.nextCursor);
      setSourceAsOf(result.asOf);
      setCursorStack(stack);
      setPageIndex(index);
    } catch (error) {
      if (controller.signal.aborted || requestId !== listRequest.current) return;
      if (retrySnapshot && error instanceof ApiError && error.status === 409) {
        setRestartNotice(true);
        void loadPage(null, search, [null], 0, false);
        return;
      }
      setListError(error);
    } finally {
      if (requestId === listRequest.current) setListLoading(false);
    }
  };

  useEffect(() => {
    const controller = new AbortController();
    const initialRequest = ++listRequest.current;
    setPhase('loading');
    void (async () => {
      try {
        const result = await getDirectoryStatus(environmentId, controller.signal) as DirectoryStatus;
        if (controller.signal.aborted || initialRequest !== listRequest.current) return;
        setStatus(result);
        const nextPhase = statusPhase(result);
        setPhase(nextPhase);
        if (nextPhase === 'ready') void loadPage(null, initialSearch ?? '', [null], 0);
      } catch (error) {
        if (controller.signal.aborted || initialRequest !== listRequest.current) return;
        setStatusError(error);
        setPhase('error');
      }
    })();
    return () => {
      controller.abort();
      listAbort.current?.abort();
      detailAbort.current?.abort();
      listRequest.current += 1;
      detailRequest.current += 1;
    };
    // The keyed wrapper remounts this content whenever environment or kind changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    const search = draftSearch.trim();
    setCommittedSearch(search);
    setRestartNotice(false);
    void loadPage(null, search, [null], 0);
  };

  const clearSearch = () => {
    setDraftSearch('');
    setCommittedSearch('');
    setRestartNotice(false);
    void loadPage(null, '', [null], 0);
  };

  const selectObject = async (id: string) => {
    detailAbort.current?.abort();
    const controller = new AbortController();
    detailAbort.current = controller;
    const requestId = ++detailRequest.current;
    setSelectedId(id);
    setDetail(null);
    setDetailError(null);
    setDetailAsOf(null);
    setDetailLoading(true);
    try {
      const result = await getDirectoryObject(environmentId, id, controller.signal);
      if (controller.signal.aborted || requestId !== detailRequest.current) return;
      setDetail(result.item as DirectoryObject);
      setDetailAsOf(result.asOf);
    } catch (error) {
      if (controller.signal.aborted || requestId !== detailRequest.current) return;
      setDetailError(error);
    } finally {
      if (requestId === detailRequest.current) setDetailLoading(false);
    }
  };

  const formattedDate = (value: string | null | undefined) => {
    if (!value) return null;
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? null : new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
  };

  const stateCopy = (current: ViewPhase, error?: unknown) => {
    const errorKind = current === 'error' ? errorPhase(error) : null;
    if (errorKind === 'forbidden') return [t('directory.forbiddenTitle'), t('directory.forbiddenBody')];
    if (errorKind === 'notFound') return [t('directory.notFoundTitle'), t('directory.notFoundBody')];
    if (errorKind === 'unavailable') return [t('directory.unavailableTitle'), t('directory.unavailableBody')];
    if (current === 'unconfigured') return [t('directory.unconfiguredTitle'), t('directory.unconfiguredBody')];
    if (current === 'syncing') return [t('directory.syncingTitle'), t('directory.syncingBody')];
    if (current === 'failed') return [t('directory.failedTitle'), t('directory.failedBody')];
    if (current === 'unavailable') return [t('directory.unavailableTitle'), t('directory.unavailableBody')];
    return [t('directory.errorTitle'), t('directory.errorBody')];
  };

  const sourceDate = formattedDate(sourceAsOf ?? status?.completedAt);
  const statusLabel = phase === 'ready' && !listError ? t('directory.statusReady')
    : phase === 'unconfigured' ? t('directory.statusUnconfigured')
      : phase === 'failed' ? t('directory.statusFailed')
        : phase === 'syncing' ? t('directory.statusSyncing') : t('directory.statusStale');

  return (
    <section className="directory-view" aria-labelledby={`directory-heading-${kind}`}>
      <header className="directory-header">
        <div>
          <span className="eyebrow">{t('directory.eyebrow')}</span>
          <h1 id={`directory-heading-${kind}`}>{t(`directory.title.${kind}`)}</h1>
          <p>{t('directory.description')}</p>
        </div>
        {phase !== 'loading' && (
          <div className={`directory-source ${phase === 'ready' && !listError ? 'ready' : 'warning'}`}>
            <span className="status-dot" aria-hidden="true" />
            <span><strong>{statusLabel}</strong><small>{sourceDate ? t('directory.asOf', { date: sourceDate }) : t('directory.asOfUnknown')}</small></span>
          </div>
        )}
      </header>

      {phase === 'loading' && <DirectoryState loading title={t('directory.loading')} />}
      {phase !== 'loading' && phase !== 'ready' && (() => {
        const [title, body] = stateCopy(phase, statusError);
        return <DirectoryState title={title} body={body} error={phase === 'error' || phase === 'failed'} code={status?.errorCode} t={t} />;
      })()}

      {phase === 'ready' && (
        <>
          {initialSearch === undefined && <form className="directory-search" role="search" onSubmit={submitSearch}>
            <label htmlFor={`directory-search-input-${kind}`}>{t('directory.searchLabel')}</label>
            <div>
              <input id={`directory-search-input-${kind}`} value={draftSearch} maxLength={128} onChange={(event) => setDraftSearch(event.target.value)} placeholder={t('directory.searchPlaceholder')} />
              {committedSearch && <button type="button" className="directory-clear" onClick={clearSearch}>{t('directory.clearSearch')}</button>}
              <button type="submit" className="secondary-button" disabled={listLoading}>{t('directory.searchAction')}</button>
            </div>
          </form>}

          {restartNotice && <div className="directory-notice" role="status">{t('directory.restartNotice')}</div>}

          <div className={`directory-layout ${selectedId ? 'has-detail' : ''}`}>
            <div className="directory-table-panel" aria-busy={listLoading}>
              <div className="directory-table-heading">
                <strong>{t('directory.resultsLabel')}</strong>
                {sourceDate && <small>{t('directory.asOf', { date: sourceDate })}</small>}
              </div>
              {listLoading && <DirectoryState loading compact title={t('directory.loading')} />}
              {!listLoading && Boolean(listError) && (() => {
                const [title, body] = stateCopy('error', listError);
                return <DirectoryState compact title={title} body={body} error />;
              })()}
              {!listLoading && !listError && items.length === 0 && (
                <DirectoryState compact title={t('directory.emptyTitle')} body={t(committedSearch ? 'directory.emptySearchBody' : 'directory.emptyBody')} />
              )}
              {!listLoading && !listError && items.length > 0 && (
                <div className="directory-table-scroll">
                  <table>
                    <thead><tr><th>{t('directory.columnName')}</th><th>{t('directory.columnAccount')}</th><th>{t('directory.columnDepartment')}</th><th>{t('directory.columnProtection')}</th></tr></thead>
                    <tbody>{items.map((item) => (
                      <tr key={item.id} className={selectedId === item.id ? 'selected' : undefined}>
                        <td data-label={t('directory.columnName')}><button type="button" className="directory-object-link" onClick={() => void selectObject(item.id)} aria-pressed={selectedId === item.id}><strong>{item.name}</strong><small>{item.distinguishedName}</small></button></td>
                        <td data-label={t('directory.columnAccount')}>{item.samAccountName ?? t('directory.notAvailable')}</td>
                        <td data-label={t('directory.columnDepartment')}>{item.department ?? t('directory.notAvailable')}</td>
                        <td data-label={t('directory.columnProtection')}><Protection item={item} t={t} /></td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
              )}
              {!listLoading && !listError && items.length > 0 && (
                <nav className="directory-pagination" aria-label={t('directory.page', { page: pageIndex + 1 })}>
                  <button type="button" className="secondary-button" disabled={pageIndex === 0} onClick={() => {
                    const index = pageIndex - 1;
                    const stack = cursorStack.slice(0, pageIndex);
                    void loadPage(stack[index], committedSearch, stack, index);
                  }}>{t('directory.previous')}</button>
                  <span>{t('directory.page', { page: pageIndex + 1 })}</span>
                  <button type="button" className="secondary-button" disabled={!nextCursor} onClick={() => {
                    if (!nextCursor) return;
                    const stack = [...cursorStack.slice(0, pageIndex + 1), nextCursor];
                    void loadPage(nextCursor, committedSearch, stack, pageIndex + 1);
                  }}>{t('directory.next')}</button>
                </nav>
              )}
            </div>

            {selectedId && (
              <aside className="directory-detail" aria-labelledby={`directory-detail-title-${kind}`} aria-live="polite">
                <div className="directory-detail-header"><h2 id={`directory-detail-title-${kind}`}>{t('directory.detailsTitle')}</h2><button type="button" className="directory-close" onClick={clearDetail} aria-label={t('directory.closeDetails')}>×</button></div>
                {detailLoading && <DirectoryState loading compact title={t('directory.loadingDetails')} />}
                {!detailLoading && detail && <FavoriteButton environmentId={environmentId} id={detail.id} />}
                {!detailLoading && Boolean(detailError) && (() => {
                  const [title, body] = stateCopy('error', detailError);
                  return <DirectoryState compact error title={title} body={body ?? t('directory.detailsError')} />;
                })()}
                {!detailLoading && detail?.kind === 'Computer' && <><a className="device-open-link" href={`#/device?environment=${encodeURIComponent(environmentId)}&id=${encodeURIComponent(detail.id)}`}>{t('device.open')}</a><DeviceTabs key={`${environmentId}:${detail.id}`} environmentId={environmentId} id={detail.id} ad={<DetailFields item={detail} asOf={formattedDate(detailAsOf)} t={t} />} /></>}
                {!detailLoading && detail && detail.kind !== 'Computer' && <DetailFields item={detail} asOf={formattedDate(detailAsOf)} t={t} />}
                {!detailLoading && detail?.kind === 'User' && <><DirectoryProposal key={`proposal:${environmentId}:${detail.id}`} environmentId={environmentId} id={detail.id} /><DeviceUserPanel key={`links:${environmentId}:${detail.id}`} environmentId={environmentId} id={detail.id} kind="User" /></>}
              </aside>
            )}
          </div>
        </>
      )}
    </section>
  );
}

function Protection({ item, t }: { item: DirectoryObject; t: ReturnType<typeof useI18n>['t'] }) {
  const key = !item.protectionKnown ? 'directory.protectionUnknown' : item.isProtected ? 'directory.protected' : 'directory.notProtected';
  return <span className={`directory-protection ${!item.protectionKnown ? 'unknown' : item.isProtected ? 'protected' : ''}`}>{t(key)}</span>;
}

export function DetailFields({ item, asOf, t }: { item: DirectoryObject; asOf: string | null; t: ReturnType<typeof useI18n>['t'] }) {
  const fields: [string, string | number | null | undefined][] = [
    ['directory.fieldKind', t(`directory.title.${item.kind}`)], ['directory.fieldName', item.name],
    ['directory.fieldDn', item.distinguishedName], ['directory.fieldAccount', item.samAccountName],
    ['directory.fieldDepartment', item.department], ['directory.fieldSid', item.objectSid],
    ['directory.fieldUsn', item.usnChanged], ['directory.fieldParentOu', item.parentOuId],
  ];
  return <div><dl className="directory-detail-fields">{fields.map(([label, value]) => <div key={label}><dt>{t(label)}</dt><dd>{value ?? t('directory.notAvailable')}</dd></div>)}<div><dt>{t('directory.columnProtection')}</dt><dd><Protection item={item} t={t} /></dd></div></dl><p className="directory-detail-asof">{asOf ? t('directory.asOf', { date: asOf }) : t('directory.asOfUnknown')}</p></div>;
}

function DirectoryState({ title, body, loading = false, error = false, compact = false, code, t }: { title: string; body?: string; loading?: boolean; error?: boolean; compact?: boolean; code?: string | null; t?: ReturnType<typeof useI18n>['t'] }) {
  return <div className={`directory-state ${compact ? 'compact' : ''} ${error ? 'error' : ''}`} role={error ? 'alert' : 'status'}>{loading ? <span className="spinner" aria-hidden="true" /> : <span className="directory-state-icon" aria-hidden="true">{error ? '!' : 'i'}</span>}<h2>{title}</h2>{body && <p>{body}</p>}{code && t && <small>{t('directory.errorCode', { code })}</small>}</div>;
}

export default function DirectoryView(props: DirectoryViewProps) {
  const { t } = useI18n();
  const [revision, setRevision] = useState(0);
  return <div className="directory-wrapper"><button type="button" className="secondary-button" onClick={() => setRevision(value => value + 1)}>{t('directory.refresh')}</button><DirectoryViewContent key={`${props.environmentId}:${props.kind}:${props.initialSearch ?? ''}:${revision}`} {...props} /></div>;
}
