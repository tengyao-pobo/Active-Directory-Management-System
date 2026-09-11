import { useEffect, useState } from 'react';
import { ApiError, request } from './api';
import { useI18n } from './i18n';

interface Readiness { status: 'Eligible' | 'MappingRequired'; queriedAt: string }
function Content({ environmentId, id }: { environmentId: string; id: string }) {
  const { t, locale } = useI18n();
  const [data, setData] = useState<Readiness | null>(null);
  const [error, setError] = useState(false); const [hidden, setHidden] = useState(false);
  const [shown, setShown] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setData(null); setError(false); setHidden(false);
    void request<Readiness>(`/api/v1/environments/${encodeURIComponent(environmentId)}/devices/${encodeURIComponent(id)}/enrollment-target`, { signal: controller.signal })
      .then(value => {
        if (controller.signal.aborted) return;
        setShown(true);
        if (!value || (value.status !== 'Eligible' && value.status !== 'MappingRequired') ||
            typeof value.queriedAt !== 'string' || !Number.isFinite(new Date(value.queriedAt).getTime())) {
          setError(true); return;
        }
        setData(value);
      }).catch(failure => {
        if (controller.signal.aborted) return;
        if (failure instanceof ApiError && (failure.status === 404 || failure.status === 401)) setHidden(true);
        else { setShown(true); setError(true); }
      });
    return () => controller.abort();
  }, [environmentId, id, revision]);
  if (hidden || !shown) return null;
  return <section className="asset-panel" aria-label={t('enrollment.title')}>
    <h3>{t('enrollment.title')}</h3>
    {error ? <p role="alert">{t('enrollment.unavailable')}</p> : !data ? <p role="status">{t('enrollment.checking')}</p> : <>
      <p role="status">{t(data.status === 'Eligible' ? 'enrollment.eligible' : 'enrollment.mappingRequired')}</p>
      <p>{t('enrollment.readinessOnly')}</p>
      <p>{t('enrollment.queriedAt', { time: new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(data.queriedAt)) })}</p>
    </>}
    <button type="button" className="secondary-button" disabled={!data && !error}
      onClick={() => { setData(null); setError(false); setRevision(value => value + 1); }}>{t('enrollment.refresh')}</button>
  </section>;
}

export default function DeviceEnrollmentPanel(props: { environmentId: string; id: string }) {
  return <Content key={`${props.environmentId}:${props.id}`} {...props} />;
}
