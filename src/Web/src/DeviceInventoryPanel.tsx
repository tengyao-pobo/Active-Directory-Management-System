import { useEffect, useState } from 'react';
import { request } from './api';
import { useI18n } from './i18n';
import { BasicInventoryView, HardwareInventoryView, InventorySourceNote, SoftwareInventoryView,
  type BasicInventoryData, type HardwareSectionView, type InventorySource, type SoftwareApplicationView } from './InventoryViews';

interface Snapshot {
  queriedAt: string; collectedAt: string | null; receivedAt: string | null; lastSeenAt: string | null;
  basic: InventorySource & { data: BasicInventoryData | null };
  hardware: InventorySource & { sections: HardwareSectionView[] };
  software: InventorySource & { applications: SoftwareApplicationView[] };
}
function Content({ environmentId, id }: { environmentId: string; id: string }) {
  const { t, locale } = useI18n(); const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState(false); const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController(); setSnapshot(null); setError(false);
    void request<Snapshot>(`/api/v1/environments/${encodeURIComponent(environmentId)}/devices/${encodeURIComponent(id)}/inventory`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setSnapshot(value); })
      .catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [environmentId, id, revision]);
  const date = (value: string | null) => {
    const parsed = value ? new Date(value) : null;
    return parsed && Number.isFinite(parsed.getTime()) ? new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(parsed) : t('inventory.unknown');
  };
  return <div className="asset-panel inventory-panel"><h3>{t('inventory.title')}</h3><p>{t('inventory.scope')}</p>
    <button type="button" className="secondary-button" onClick={() => setRevision(value => value + 1)}>{t('inventory.refresh')}</button>
    {error ? <p role="alert">{t('inventory.unavailable')}</p> : !snapshot ? <p role="status">{t('directory.loadingDetails')}</p> : <>
      <dl className="directory-detail-fields">
        <div><dt>{t('inventory.snapshotAt')}</dt><dd>{date(snapshot.collectedAt)}</dd></div>
        <div><dt>{t('inventory.receivedAt')}</dt><dd>{date(snapshot.receivedAt)}</dd></div>
        <div><dt>{t('inventory.lastSeen')}</dt><dd>{date(snapshot.lastSeenAt)}</dd></div>
      </dl>
      <BasicInventoryView source={snapshot.basic} data={snapshot.basic.data} />
      <section><h4>{t('inventory.hardware')}</h4><InventorySourceNote source={snapshot.hardware} />
        {snapshot.hardware.availability === 'Observed' && <HardwareInventoryView sections={snapshot.hardware.sections} />}
      </section>
      <SoftwareInventoryView source={snapshot.software} applications={snapshot.software.applications} />
    </>}
  </div>;
}
export default function DeviceInventoryPanel(props: { environmentId: string; id: string }) {
  return <Content key={`${props.environmentId}:${props.id}`} {...props} />;
}
