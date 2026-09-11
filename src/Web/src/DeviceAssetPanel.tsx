import { useEffect, useRef, useState } from 'react';
import { ApiError, request } from './api';
import { useI18n } from './i18n';
import { deviceLifecycleStates } from './deviceLifecycle';

interface Asset { lifecycle: string; notes: string; version: number; updatedAt: string }
interface AssetResponse { item: Asset | null; canEdit: boolean }
export default function DeviceAssetPanel({ environmentId, id }: { environmentId: string; id: string }) {
  const { t } = useI18n();
  const [data, setData] = useState<AssetResponse | null>(null);
  const [lifecycle, setLifecycle] = useState('Unknown');
  const [notes, setNotes] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [saved, setSaved] = useState(false);
  const [revision, setRevision] = useState(0);
  const path = `/api/v1/environments/${encodeURIComponent(environmentId)}/devices/${encodeURIComponent(id)}/asset`;
  useEffect(() => {
    const controller = new AbortController();
    setData(null); setNotes(''); setError(''); setSaved(false);
    void request<AssetResponse>(path, { signal: controller.signal }).then(value => {
      if (controller.signal.aborted) return;
      setData(value); setLifecycle(value.item?.lifecycle ?? 'Unknown'); setNotes(value.item?.notes ?? '');
    }).catch(() => { if (!controller.signal.aborted) setError('asset.unavailable'); });
    return () => controller.abort();
  }, [path, revision]);
  const pendingSave = useRef<AbortController | null>(null);
  useEffect(() => () => { pendingSave.current?.abort(); }, []);
  async function save() {
    const saveController = new AbortController();
    pendingSave.current = saveController;
    setBusy(true); setError(''); setSaved(false);
    try {
      const { token } = await request<{ token: string }>('/api/v1/session/csrf', { signal: saveController.signal });
      const value = await request<AssetResponse>(path, { method: 'PUT', signal: saveController.signal,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': token, 'If-Match': `"${data?.item?.version ?? 0}"` }, body: JSON.stringify({ lifecycle, notes }) });
      if (!saveController.signal.aborted) { setData(value); setSaved(true); }
    } catch (failure) {
      if (!saveController.signal.aborted) setError(failure instanceof ApiError && [409, 412].includes(failure.status) ? 'asset.conflict' : 'asset.saveFailed');
    } finally { if (!saveController.signal.aborted) setBusy(false); }
  }
  return <section className="asset-panel" aria-label={t('asset.title')}>
    <h3>{t('asset.title')}</h3><p>{t('asset.description')}</p>
    {error && <p role="alert">{t(error)}</p>}
    {saved && <p role="status">{t('asset.saved')}</p>}
    {!data && !error && <p role="status">{t('directory.loadingDetails')}</p>}
    {data && <>
      <label>{t('asset.lifecycle')}<select aria-label={t('asset.lifecycle')} value={lifecycle} disabled={!data.canEdit || busy} onChange={e => { setLifecycle(e.target.value); setSaved(false); }}>
        {deviceLifecycleStates.map(state => <option key={state} value={state}>{t(`asset.state.${state}`)}</option>)}
      </select></label>
      <label>{t('asset.notes')}<textarea aria-label={t('asset.notes')} value={notes} maxLength={4000} rows={6} readOnly={!data.canEdit} disabled={busy} onChange={e => { setNotes(e.target.value); setSaved(false); }} /></label>
      {data.item && <p>{t('asset.version', { version: data.item.version })}</p>}
      {data.canEdit && <button type="button" className="secondary-button" disabled={busy} onClick={() => void save()}>{t('asset.save')}</button>}
    </>}
    <button type="button" className="secondary-button" disabled={busy} onClick={() => setRevision(value => value + 1)}>{t('asset.reload')}</button>
  </section>;
}
