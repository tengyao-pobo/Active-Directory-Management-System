import { useEffect, useState } from 'react';
import { ApiError, getDirectoryObject, getFavorites, type DirectoryObject, type FavoritesPage } from './api';
import { useI18n } from './i18n';
import { DetailFields } from './DirectoryView';
import FavoriteButton from './FavoriteButton';

function FavoriteDetails({ environmentId, id, onChanged, onClose }: { environmentId: string; id: string; onChanged: () => void; onClose: () => void }) {
  const { t, locale } = useI18n();
  const [detail, setDetail] = useState<{ item: DirectoryObject; asOf: string } | null>(null);
  const [error, setError] = useState(false);
  useEffect(() => {
    const controller = new AbortController();
    void getDirectoryObject(environmentId, id, controller.signal).then(value => { if (!controller.signal.aborted) setDetail(value); })
      .catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [environmentId, id]);
  if (error) return <p role="alert">{t('favorites.unavailable')}</p>;
  if (!detail) return <p role="status">{t('directory.loadingDetails')}</p>;
  return <aside className="directory-detail"><div className="directory-detail-header"><h2>{detail.item.name}</h2><button type="button" className="directory-close" onClick={onClose} aria-label={t('directory.closeDetails')}>×</button></div><FavoriteButton environmentId={environmentId} id={id} onChanged={onChanged} />
    {detail.item.kind === 'Computer' && <a className="device-open-link" href={`#/device?environment=${encodeURIComponent(environmentId)}&id=${encodeURIComponent(id)}`}>{t('device.open')}</a>}
    <DetailFields item={detail.item} asOf={new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(detail.asOf))} t={t} />
  </aside>;
}

function FavoritesContent({ environmentId }: { environmentId: string }) {
  const { t } = useI18n();
  const [page, setPage] = useState<FavoritesPage | null>(null); const [error, setError] = useState('');
  const [cursor, setCursor] = useState<string | undefined>(); const [revision, setRevision] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  useEffect(() => {
    const controller = new AbortController(); setPage(null); setSelected(null); setError('');
    void getFavorites(environmentId, cursor, controller.signal).then(value => { if (!controller.signal.aborted) setPage(value); })
      .catch(failure => { if (!controller.signal.aborted) setError(failure instanceof ApiError && failure.code === 'DirectorySnapshotChanged' ? 'favorites.changed' : 'favorites.unavailable'); });
    return () => controller.abort();
  }, [environmentId, cursor, revision]);
  function refresh() { setCursor(undefined); setRevision(value => value + 1); }
  return <section className="directory-view" aria-labelledby="favorites-title"><header className="directory-header"><div><h1 id="favorites-title">{t('nav.favorites')}</h1><p>{t('favorites.description')}</p></div>
    <button type="button" className="secondary-button" onClick={refresh}>{t('favorites.refresh')}</button></header>
    {error ? <p role="alert">{t(error)}</p> : !page ? <p role="status">{t('state.loadingData')}</p> : <>
      {!page.items.length ? <p role="status">{t('favorites.empty')}</p> : <div className={`directory-layout ${selected ? 'has-detail' : ''}`}><div className="directory-table-panel"><table><thead><tr><th>{t('directory.columnName')}</th><th>{t('directory.fieldKind')}</th></tr></thead>
        <tbody>{page.items.map(item => <tr key={item.id}><td data-label={t('directory.columnName')}><button className="directory-object-link" type="button" aria-pressed={selected === item.id} onClick={() => setSelected(item.id)}><strong>{item.name}</strong><small>{item.distinguishedName}</small></button></td><td data-label={t('directory.fieldKind')}>{t(`directory.title.${item.kind}`)}</td></tr>)}</tbody></table></div>
        {selected && <FavoriteDetails key={`${environmentId}:${selected}`} environmentId={environmentId} id={selected} onChanged={refresh} onClose={() => setSelected(null)} />}</div>}
      <nav className="directory-pagination"><button type="button" className="secondary-button" disabled={!cursor} onClick={refresh}>{t('favorites.first')}</button>
        <button type="button" className="secondary-button" disabled={!page.nextCursor} onClick={() => { setSelected(null); setPage(null); setCursor(page.nextCursor ?? undefined); }}>{t('directory.next')}</button></nav>
    </>}
  </section>;
}
export default function FavoritesView({ environmentId }: { environmentId: string }) {
  return <FavoritesContent key={environmentId} environmentId={environmentId} />;
}
