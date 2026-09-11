import { useEffect, useRef, useState } from 'react';
import { ApiError, request, stepUp } from './api';
import { useI18n } from './i18n';

export const tagKeys = ['VIP', 'Finance', 'Shared', 'MeetingRoom', 'ServerRoom', 'Critical', 'Test', 'Replacement'] as const;
export interface DeviceTag { id: string; key: string; version: number; archivedAt: string | null }
interface Catalog { items: DeviceTag[]; version: number; canManage: boolean; canApprove: boolean }
interface Change { kind: string; tagId?: string; tagKey?: string; objectId?: string; expectedTagVersion?: number }
interface Plan { id: string; requesterId: string; action: string; change: Change; planHash: string; policyVersion: number; expiresAt: string; state: string; reason: string }

export default function DeviceTagPanel(props: { environmentId: string; id?: string }) {
  return <TagContent key={`${props.environmentId}:${props.id}`} {...props} />;
}
function TagContent({ environmentId, id }: { environmentId: string; id?: string }) {
  const { t, locale } = useI18n();
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [assigned, setAssigned] = useState<string[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [plansQueriedAt, setPlansQueriedAt] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [actor, setActor] = useState('');
  const alive = useRef(true);
  const operation = useRef<AbortController | null>(null);
  const path = `/api/v1/environments/${encodeURIComponent(environmentId)}`;
  useEffect(() => { alive.current = true; return () => { alive.current = false; operation.current?.abort(); }; }, []);
  useEffect(() => {
    const controller = new AbortController();
    setCatalog(null); setAssigned([]); setPlans([]); setError('');
    void (async () => {
      const [data, tags, principal] = await Promise.all([
        request<Catalog>(`${path}/device-tags`, { signal: controller.signal }),
        id ? request<{ items: DeviceTag[] }>(`${path}/devices/${encodeURIComponent(id)}/tags`, { signal: controller.signal }) : Promise.resolve({ items: [] }),
        request<{ id: string }>('/api/v1/session/me', { signal: controller.signal }),
      ]);
      const pending = data.canManage || data.canApprove
        ? await request<{ items: Plan[]; queriedAt: string }>(`${path}/device-tags/plans`, { signal: controller.signal }) : { items: [], queriedAt: '' };
      if (controller.signal.aborted) return;
      setCatalog(data); setAssigned(tags.items.map(tag => tag.id)); setActor(principal.id); setPlans(pending.items); setPlansQueriedAt(pending.queriedAt);
    })().catch(() => { if (!controller.signal.aborted) setError('tags.unavailable'); });
    return () => controller.abort();
  }, [path, id, revision]);

  async function mutate(url: string, body: unknown) {
    if (busy) return;
    const controller = new AbortController(); operation.current = controller;
    setBusy(true); setError(''); setNotice('');
    try {
      await stepUp();
      if (!alive.current || controller.signal.aborted) return;
      const { token } = await request<{ token: string }>('/api/v1/session/csrf', { signal: controller.signal });
      await request(url, { method: 'POST', signal: controller.signal,
        headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': token }, body: JSON.stringify(body) });
      if (!alive.current || controller.signal.aborted) return;
      setNotice('tags.saved'); setReason(''); setRevision(value => value + 1);
    } catch (failure) {
      if (!alive.current || controller.signal.aborted) return;
      // Clear all actionable state after an uncertain or rejected mutation; refresh is explicit.
      setCatalog(null); setAssigned([]); setPlans([]);
      setError(failure instanceof ApiError && [409, 412].includes(failure.status) ? 'tags.conflict' : 'tags.failed');
    } finally { if (alive.current && !controller.signal.aborted) setBusy(false); }
  }
  const propose = (change: Change) => void mutate(`${path}/change-plans`, { change, expectedVersion: catalog!.version, reason: reason.trim() });
  const label = (key: string) => t(`tags.key.${key}`);
  const action = (kind: string) => t(`tags.action.${kind.replace('device-tag.', '')}`);
  return <section className="asset-panel device-tags" aria-label={t('tags.title')}>
    <h3>{t('tags.title')}</h3><p>{t('tags.description')}</p>
    {error && <p role="alert">{t(error)}</p>}{notice && <p role="status">{t(notice)}</p>}
    {!catalog && !error && <p role="status">{t('directory.loadingDetails')}</p>}
    {catalog && <>
      <ul>{catalog.items.filter(tag => assigned.includes(tag.id)).map(tag => <li key={tag.id}>{label(tag.key)} {tag.archivedAt && <span>({t('tags.archived')})</span>}</li>)}</ul>
      {id && assigned.length === 0 && <p>{t('tags.empty')}</p>}
      {catalog.canManage && <details><summary>{t('tags.manage')}</summary><p>{t('tags.approvalHint')}</p>
        <label>{t('tags.reason')}<textarea value={reason} maxLength={512} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
        <fieldset disabled={busy || reason.trim().length < 5}>
          <legend>{t('tags.catalog')}</legend>
          {tagKeys.map(key => {
            const tag = catalog.items.find(value => value.key === key);
            return <div key={key} className="tag-action-row"><strong>{label(key)}</strong>{tag ? <>
              <button type="button" onClick={() => propose({ kind: tag.archivedAt ? 'device-tag.reactivate' : 'device-tag.archive', tagId: tag.id, expectedTagVersion: tag.version })}>{t(tag.archivedAt ? 'tags.reactivate' : 'tags.archive')}</button>
              {id && (assigned.includes(tag.id) || !tag.archivedAt) && <button type="button" onClick={() => propose({ kind: assigned.includes(tag.id) ? 'device-tag.unassign' : 'device-tag.assign', tagId: tag.id, objectId: id, expectedTagVersion: tag.version })}>{t(assigned.includes(tag.id) ? 'tags.unassign' : 'tags.assign')}</button>}
            </> : <button type="button" onClick={() => propose({ kind: 'device-tag.create', tagKey: key })}>{t('tags.create')}</button>}</div>;
          })}
        </fieldset>
      </details>}
      {(catalog.canManage || catalog.canApprove) && <details><summary>{t('tags.plans')}</summary><p>{t('tags.planLimit')}</p>
        {plans.length === 0 && <p>{t('tags.noPlans')}</p>}
        {plans.map(plan => {
          const tag = catalog.items.find(value => value.id === plan.change.tagId);
          const expired = Date.parse(plan.expiresAt) <= Date.parse(plansQueriedAt);
          return <article key={plan.id} className="tag-plan"><h4>{action(plan.action)} — {label(plan.change.tagKey ?? tag?.key ?? 'Unknown')}</h4>
            <dl><dt>{t('tags.planId')}</dt><dd>{plan.id}</dd><dt>{t('tags.reason')}</dt><dd>{plan.reason}</dd>
              <dt>{t('tags.target')}</dt><dd>{plan.change.objectId ?? t('tags.catalogTarget')}</dd>
              <dt>{t('tags.state')}</dt><dd>{t(`tags.state.${expired && plan.state !== 'Executed' ? 'Expired' : plan.state}`)}</dd>
              <dt>{t('tags.expires')}</dt><dd>{new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'short' }).format(new Date(plan.expiresAt))}</dd>
              <dt>{t('tags.hash')}</dt><dd className="tag-hash">{plan.planHash}</dd></dl>
            {catalog.canApprove && actor !== plan.requesterId && plan.state === 'PendingApproval' && !expired && <button type="button" disabled={busy} onClick={() => void mutate(`${path}/change-plans/${plan.id}/approval`, { planHash: plan.planHash })}>{t('tags.approve')}</button>}
            {catalog.canManage && actor === plan.requesterId && plan.state === 'Approved' && !expired && <button type="button" disabled={busy} onClick={() => void mutate(`${path}/change-plans/${plan.id}/execution`, {})}>{t('tags.execute')}</button>}
          </article>;
        })}
      </details>}
    </>}
    <button type="button" className="secondary-button" disabled={busy} onClick={() => { setNotice(''); setRevision(value => value + 1); }}>{t('tags.refresh')}</button>
  </section>;
}
