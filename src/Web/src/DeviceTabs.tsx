import { useEffect, useId, useState, type ReactNode } from 'react';
import DeviceAssetPanel from './DeviceAssetPanel';
import DeviceUserPanel from './DeviceUserPanel';
import { useI18n } from './i18n';
import { ApiError, request } from './api';

const tabs = ['ad', 'asset', 'user', 'audit', 'inventory'] as const;
export default function DeviceTabs({ environmentId, id, ad }: { environmentId: string; id: string; ad: ReactNode }) {
  const { t } = useI18n(); const prefix = useId();
  const [selected, setSelected] = useState<typeof tabs[number]>('ad');
  return <div className="device-tabs">
    <p className="device-tab-hint">{t('device.draftHint')}</p>
    <div role="tablist" aria-label={t('device.tabs')}>
      {tabs.map((tab, index) => <button key={tab} id={`${prefix}-${tab}`} type="button" role="tab" aria-selected={selected === tab} aria-controls={`${prefix}-panel`} tabIndex={selected === tab ? 0 : -1}
        onClick={() => setSelected(tab)} onKeyDown={event => {
          const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null;
          if (next !== null) { event.preventDefault(); setSelected(tabs[next]); document.getElementById(`${prefix}-${tabs[next]}`)?.focus(); }
        }}>{t(`device.tab.${tab}`)}</button>)}
    </div>
    <div role="tabpanel" id={`${prefix}-panel`} aria-labelledby={`${prefix}-${selected}`}>
      {selected === 'ad' && ad}
      {selected === 'asset' && <DeviceAssetPanel environmentId={environmentId} id={id} />}
      {selected === 'user' && <DeviceUserPanel environmentId={environmentId} id={id} kind="Computer" />}
      {selected === 'audit' && <DeviceAudit environmentId={environmentId} id={id} />}
      {selected === 'inventory' && <div className="asset-panel"><h3>{t('device.inventoryTitle')}</h3><p>{t('device.inventoryBody')}</p></div>}
    </div>
  </div>;
}
function DeviceAudit({ environmentId, id }: { environmentId: string; id: string }) {
  const { t, locale } = useI18n();
  const [data, setData] = useState<{ items: { id: string; action: string; result: string; occurredAt: string }[]; nextCursor: string | null } | null>(null);
  const [cursor, setCursor] = useState<string | null>(null); const [revision, setRevision] = useState(0); const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController(); setData(null); setError('');
    void request<NonNullable<typeof data>>(`/api/v1/environments/${encodeURIComponent(environmentId)}/devices/${encodeURIComponent(id)}/audit${cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setData(value); }).catch(failure => { if (!controller.signal.aborted) setError(failure instanceof ApiError && failure.status === 409 ? 'device.auditChanged' : 'device.auditUnavailable'); });
    return () => controller.abort();
  }, [environmentId, id, cursor, revision]);
  return <div className="asset-panel"><h3>{t('device.tab.audit')}</h3><p>{t('device.auditScope')}</p>
    {error && <p role="alert">{t(error)}</p>}{!data && !error && <p role="status">{t('directory.loadingDetails')}</p>}
    {data && <>{data.items.length === 0 && <p>{t('device.auditEmpty')}</p>}<ul>{data.items.map(item => <li key={item.id}>{new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(item.occurredAt))} — {item.action} ({item.result})</li>)}</ul>
      <button type="button" className="secondary-button" disabled={!data.nextCursor} onClick={() => setCursor(data.nextCursor)}>{t('directory.next')}</button></>}
    <button type="button" className="secondary-button" onClick={() => { setCursor(null); setRevision(value => value + 1); }}>{t('device.auditRefresh')}</button>
  </div>;
}
