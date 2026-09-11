import { useEffect, useState } from 'react';
import { request } from './api';
import { useI18n } from './i18n';
import { bitLockerStatusKey } from './bitLockerStatus';

interface Volume {
  driveLetter: string | null; volumeType: number | null; protectionStatus: number | null;
  conversionStatus: number | null; encryptionMethod: number | null; isVolumeInitializedForProtection: boolean | null;
}
interface Snapshot {
  state: 'Current' | 'Stale' | 'Missing'; queriedAt: string; sourceObservedAt?: string; collectedAt?: string;
  receivedAt?: string; lastSeenAt?: string | null; source?: string; isTruncated?: boolean; volumes: Volume[];
}

function PanelContent({ environmentId, id }: { environmentId: string; id: string }) {
  const { t, locale } = useI18n();
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null); const [error, setError] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setSnapshot(null); setError(false);
    void request<Snapshot>(`/api/v1/environments/${encodeURIComponent(environmentId)}/devices/${encodeURIComponent(id)}/bitlocker`, { signal: controller.signal })
      .then(value => {
        if (!controller.signal.aborted) {
          if (!['Current', 'Stale', 'Missing'].includes(value.state)) setError(true);
          else setSnapshot(value);
        }
      }).catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [environmentId, id, revision]);
  const date = (value?: string | null) => value ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) : t('bitlocker.unknown');
  return <div className="asset-panel bitlocker-panel"><h3>{t('bitlocker.title')}</h3><p>{t('bitlocker.scope')}</p>
    <button type="button" className="secondary-button" onClick={() => setRevision(value => value + 1)}>{t('bitlocker.refresh')}</button>
    {error ? <p role="alert">{t('bitlocker.unavailable')}</p> : !snapshot ? <p role="status">{t('directory.loadingDetails')}</p> : <>
      {snapshot.state === 'Missing' ? <p role="status">{t('bitlocker.missing')}</p> : <>
        {snapshot.state === 'Stale' && <p className="directory-notice" role="status">{t('bitlocker.stale')}</p>}
        {snapshot.isTruncated && <p className="directory-notice" role="status">{t('bitlocker.incomplete')}</p>}
        <dl className="directory-detail-fields">
          <div><dt>{t('bitlocker.collectedAt')}</dt><dd>{date(snapshot.collectedAt)}</dd></div>
          <div><dt>{t('bitlocker.observedAt')}</dt><dd>{date(snapshot.sourceObservedAt)}</dd></div>
          <div><dt>{t('bitlocker.receivedAt')}</dt><dd>{date(snapshot.receivedAt)}</dd></div>
          <div><dt>{t('bitlocker.lastSeen')}</dt><dd>{date(snapshot.lastSeenAt)}</dd></div>
        </dl>
        {snapshot.volumes.length === 0 ? <p role="status">{t('bitlocker.noInstances')}</p> : snapshot.volumes.map((volume, index) => <section key={index} className="bitlocker-volume">
          <h4>{volume.driveLetter ?? t('bitlocker.unnamedVolume', { number: index + 1 })}</h4>
          <dl className="directory-detail-fields">
            <div><dt>{t('bitlocker.volumeType')}</dt><dd>{t(bitLockerStatusKey('volumeType', volume.volumeType))}</dd></div>
            <div><dt>{t('bitlocker.protection')}</dt><dd>{t(bitLockerStatusKey('protectionStatus', volume.protectionStatus))}</dd></div>
            <div><dt>{t('bitlocker.conversion')}</dt><dd>{t(bitLockerStatusKey('conversionStatus', volume.conversionStatus))}</dd></div>
            <div><dt>{t('bitlocker.method')}</dt><dd>{t(bitLockerStatusKey('encryptionMethod', volume.encryptionMethod))}</dd></div>
            <div><dt>{t('bitlocker.initialized')}</dt><dd>{t(typeof volume.isVolumeInitializedForProtection !== 'boolean' ? 'bitlocker.unknown' : volume.isVolumeInitializedForProtection ? 'bitlocker.yes' : 'bitlocker.no')}</dd></div>
          </dl>
        </section>)}
        <p>{t('bitlocker.notObserved')}</p>
      </>}
    </>}
  </div>;
}
export default function DeviceBitLockerPanel(props: { environmentId: string; id: string }) {
  return <PanelContent key={`${props.environmentId}:${props.id}`} {...props} />;
}
