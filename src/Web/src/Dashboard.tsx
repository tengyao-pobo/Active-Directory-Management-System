import { useEffect, useState } from 'react';
import { ApiError, request } from './api';
import { useI18n } from './i18n';

interface Summary {
  counts: Record<string, number>; lifecycle: Record<string, number>;
  repairs: { id: string; name: string }[]; nextCursor: string | null; asOf: string; queriedAt: string;
}
export default function Dashboard({ environmentId }: { environmentId: string }) {
  const { t, locale } = useI18n();
  const [data, setData] = useState<Summary | null>(null);
  const [error, setError] = useState('');
  const [cursor, setCursor] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setData(null); setError('');
    const path = `/api/v1/environments/${encodeURIComponent(environmentId)}/dashboard${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`;
    void request<Summary>(path, { signal: controller.signal }).then(value => { if (!controller.signal.aborted) setData(value); })
      .catch(failure => { if (!controller.signal.aborted) setError(failure instanceof ApiError && failure.status === 409 ? 'dashboard.changed' : 'dashboard.unavailable'); });
    return () => controller.abort();
  }, [environmentId, cursor, revision]);
  const date = (value: string) => new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
  return <section className="panel dashboard-panel" aria-label={t('dashboard.title')}>
    <h2>{t('dashboard.title')}</h2><p>{t('dashboard.scope')}</p>
    {error && <p role="alert">{t(error)}</p>}
    {!data && !error && <p role="status">{t('directory.loading')}</p>}
    {data && <>
      <p>{t('dashboard.asOf', { date: date(data.asOf) })}</p>
      <div className="metric-grid">{['User', 'Group', 'Computer', 'OrganizationalUnit'].map(kind => <article className="metric-card" key={kind}><span>{t(`directory.title.${kind}`)}</span><strong>{data.counts[kind]}</strong></article>)}</div>
      <h3>{t('dashboard.lifecycle')}</h3>
      <dl className="definition-grid">{['Unknown', 'Active', 'Spare', 'Repair', 'Retired'].map(state => <div key={state}><dt>{t(`asset.state.${state}`)}</dt><dd>{data.lifecycle[state]}</dd></div>)}</dl>
      <p>{t('dashboard.queriedAt', { date: date(data.queriedAt) })}</p>
      <h3>{t('dashboard.repairs', { count: data.lifecycle.Repair })}</h3>
      <p>{t('dashboard.repairHint')}</p>
      {data.repairs.length === 0 ? <p>{t(cursor ? 'dashboard.end' : 'dashboard.empty')}</p> : <ul>{data.repairs.map(item => <li key={item.id}><strong>{item.name}</strong><small> {item.id}</small></li>)}</ul>}
      <button type="button" className="secondary-button" disabled={!data.nextCursor} onClick={() => setCursor(data.nextCursor)}>{t('directory.next')}</button>
    </>}
    <button type="button" className="secondary-button" onClick={() => { setCursor(null); setRevision(value => value + 1); }}>{t('dashboard.refresh')}</button>
    <p>{t('dashboard.noHealth')}</p>
  </section>;
}
