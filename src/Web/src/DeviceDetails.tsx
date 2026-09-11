import { useEffect, useState } from 'react';
import { getDirectoryObject, type DirectoryObject } from './api';
import { DetailFields } from './DirectoryView';
import DeviceTabs from './DeviceTabs';
import { useI18n } from './i18n';

export default function DeviceDetails({ environmentId, targetEnvironment, id }: { environmentId: string; targetEnvironment: string; id: string }) {
  const { t, locale } = useI18n(); const [detail, setDetail] = useState<{ item: DirectoryObject; asOf: string } | null>(null); const [error, setError] = useState(false);
  const valid = Boolean(id) && id.length <= 128 && targetEnvironment === environmentId;
  useEffect(() => {
    const controller = new AbortController(); setDetail(null); setError(false);
    if (valid) void getDirectoryObject(environmentId, id, controller.signal).then(value => {
      if (!controller.signal.aborted) { if (value.item.kind === 'Computer') setDetail(value); else setError(true); }
    }).catch(() => { if (!controller.signal.aborted) setError(true); });
    return () => controller.abort();
  }, [environmentId, id, valid]);
  return <section className="panel device-full-page"><a href="#/computers">{t('device.back')}</a>
    {!valid || error ? <p role="alert">{t(!valid ? 'device.environmentMismatch' : 'device.unavailable')}</p> : !detail ? <p role="status">{t('directory.loadingDetails')}</p> : <>
      <h1>{detail.item.name}</h1><DeviceTabs key={`${environmentId}:${id}`} environmentId={environmentId} id={id} ad={<DetailFields item={detail.item} asOf={new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(detail.asOf))} t={t} />} />
    </>}
  </section>;
}
