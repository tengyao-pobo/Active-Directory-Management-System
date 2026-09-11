import { useEffect, useRef, useState } from 'react';
import { ApiError, getEnvironments, getSession, request, stepUp } from './api';
import { EnrollmentGrantRecipient } from './sealedEnrollmentGrant';
import { useI18n } from './i18n';

interface Plan {
  id: string; environmentId: string; directoryObjectId: string; requesterId: string; requestId: string;
  recipientKeyFingerprint: string; planHash: string; policyVersion: number; directoryGeneration: string;
  expiresAt: string; queriedAt: string; state: 'PendingApproval' | 'Approved' | 'Rejected' | 'Expired';
  reason: string; canApprove: boolean; canRequest: boolean;
}
interface Proposal {
  requestId: string; expectedEnvironmentVersion: number; expectedDirectoryGeneration: string;
  recipientSpki: string; reason: string;
}
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const validId = (value: unknown): value is string => typeof value === 'string' && uuid.test(value) && value !== '00000000-0000-0000-0000-000000000000';
function validPlan(value: Plan, environmentId: string, directoryId: string): boolean {
  const fields = ['id', 'environmentId', 'directoryObjectId', 'requesterId', 'requestId', 'recipientKeyFingerprint', 'planHash',
    'policyVersion', 'directoryGeneration', 'expiresAt', 'queriedAt', 'state', 'reason', 'canApprove', 'canRequest'];
  return !!value && typeof value === 'object' && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).length === fields.length && Object.keys(value).every(field => fields.includes(field)) &&
    validId(value.id) && value.environmentId === environmentId && value.directoryObjectId === directoryId &&
    validId(value.requesterId) && validId(value.requestId) && validId(value.directoryGeneration) &&
    typeof value.planHash === 'string' && /^[0-9a-f]{64}$/.test(value.planHash) &&
    typeof value.recipientKeyFingerprint === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value.recipientKeyFingerprint) &&
    Number.isSafeInteger(value.policyVersion) && value.policyVersion > 0 &&
    typeof value.expiresAt === 'string' && Number.isFinite(Date.parse(value.expiresAt)) &&
    typeof value.queriedAt === 'string' && Number.isFinite(Date.parse(value.queriedAt)) &&
    ['PendingApproval', 'Approved', 'Rejected', 'Expired'].includes(value.state) &&
    typeof value.reason === 'string' && value.reason.length >= 5 && value.reason.length <= 512 &&
    typeof value.canApprove === 'boolean' && typeof value.canRequest === 'boolean';
}

export default function DeviceEnrollmentPlans({ environmentId, id, canRequest }: { environmentId: string; id: string; canRequest: boolean }) {
  const { t, locale } = useI18n();
  const [reason, setReason] = useState(''); const [lookup, setLookup] = useState('');
  const [plan, setPlan] = useState<Plan | null>(null); const [error, setError] = useState('');
  const [busy, setBusy] = useState(false); const [retry, setRetry] = useState(false); const [expired, setExpired] = useState(false);
  const [actorId, setActorId] = useState(''); const actor = useRef<string | null>(null);
  const key = useRef<EnrollmentGrantRecipient | null>(null);
  const keyPlanId = useRef<string | null>(null);
  const keyDeadline = useRef(0);
  const attempt = useRef<Proposal | null>(null);
  const active = useRef<AbortController | null>(null); const alive = useRef(true);
  const expiry = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const planExpiry = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const path = `/api/v1/environments/${encodeURIComponent(environmentId)}`;
  const discardKey = () => { clearTimeout(expiry.current); key.current?.dispose(); key.current = null; keyPlanId.current = null; keyDeadline.current = 0; };
  useEffect(() => {
    alive.current = true;
    const dispose = () => { alive.current = false; active.current?.abort(); clearTimeout(expiry.current); clearTimeout(planExpiry.current); key.current?.dispose(); key.current = null; attempt.current = null; };
    window.addEventListener('itmc:session-expired', dispose);
    return () => { window.removeEventListener('itmc:session-expired', dispose); dispose(); };
  }, []);

  function expire() {
    discardKey(); attempt.current = null; active.current?.abort(); active.current = null;
    if (alive.current) { setBusy(false); setRetry(false); setExpired(true); setError('enrollmentPlans.localExpired'); }
  }

  function accept(value: Plan, startedAt: number, expectedId?: string, loading = false) {
    if (!validPlan(value, environmentId, id) || (expectedId && value.id !== expectedId)) throw new Error('InvalidPlan');
    if (attempt.current && (value.requestId !== attempt.current.requestId || value.recipientKeyFingerprint !== key.current?.publicKey.fingerprint)) {
      if (!loading || keyPlanId.current === value.id) throw new Error('InvalidPlan');
      discardKey(); attempt.current = null;
    }
    if (key.current && attempt.current) keyPlanId.current = value.id;
    clearTimeout(planExpiry.current);
    const remaining = Math.min(
      Math.min(600_000, Date.parse(value.expiresAt) - Date.parse(value.queriedAt)) - (performance.now() - startedAt),
      key.current ? keyDeadline.current - performance.now() : Infinity);
    const elapsed = remaining <= 0 || value.state === 'Expired' || value.state === 'Rejected';
    setExpired(elapsed); setPlan(value); setLookup(value.id); setRetry(false);
    if (elapsed) { discardKey(); attempt.current = null; }
    else if (key.current) { clearTimeout(expiry.current); expiry.current = setTimeout(expire, remaining); }
    else planExpiry.current = setTimeout(() => { if (alive.current) setExpired(true); }, remaining);
  }

  async function run(kind: 'propose' | 'load' | 'approve') {
    if (active.current || (kind === 'load' && !validId(lookup)) || (kind === 'approve' && (!plan?.canApprove || expired || lookup !== plan.id))) return;
    const controller = new AbortController(); active.current = controller;
    const previous = plan;
    let submitted = false;
    clearTimeout(planExpiry.current);
    setBusy(true); setError(''); setPlan(null);
    const options = { signal: controller.signal };
    try {
      if (kind !== 'load') await stepUp();
      if (!alive.current || controller.signal.aborted) return;
      const principal = await getSession(controller.signal);
      if (!alive.current || controller.signal.aborted) return;
      if (!validId(principal.id)) throw new Error('InvalidActor');
      setActorId(principal.id);
      if (actor.current !== null && actor.current !== principal.id) {
        clearTimeout(expiry.current); discardKey(); attempt.current = null; setRetry(false); actor.current = principal.id;
        window.dispatchEvent(new Event('itmc:session-expired'));
        throw new Error('ActorChanged');
      }
      actor.current = principal.id;
      if (kind === 'propose' && !attempt.current) {
        const [environments, directory] = await Promise.all([
          getEnvironments(controller.signal),
          request<{ generation: string }>(`${path}/directory/objects?kind=Computer&limit=1`, options),
        ]);
        const environment = environments.find(row => row.id === environmentId);
        if (!environment || !Number.isSafeInteger(environment.version) || environment.version < 1 || !validId(directory.generation)) throw new Error('Unavailable');
        if (!alive.current || controller.signal.aborted) return;
        const recipient = await EnrollmentGrantRecipient.create();
        if (!alive.current || controller.signal.aborted) { recipient.dispose(); return; }
        discardKey(); key.current = recipient; keyDeadline.current = performance.now() + 600_000;
        clearTimeout(expiry.current); expiry.current = setTimeout(expire, 600_000);
        attempt.current = { requestId: crypto.randomUUID(), expectedEnvironmentVersion: environment.version,
          expectedDirectoryGeneration: directory.generation, recipientSpki: recipient.publicKey.subjectPublicKeyInfo, reason: reason.trim() };
      }
      if (!alive.current || controller.signal.aborted) return;
      let value: Plan; const startedAt = performance.now();
      if (kind === 'load') {
        value = await request<Plan>(`${path}/enrollment-grant-plans/${encodeURIComponent(lookup)}`, options);
      } else {
        const { token } = await request<{ token: string }>('/api/v1/session/csrf', options);
        if (!alive.current || controller.signal.aborted) return;
        const target = kind === 'propose' ? `${path}/devices/${encodeURIComponent(id)}/enrollment-grant-plans`
          : `${path}/enrollment-grant-plans/${previous!.id}/approval`;
        submitted = kind === 'propose';
        value = await request<Plan>(target, { ...options, method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': token },
          body: JSON.stringify(kind === 'propose' ? attempt.current : { planHash: previous!.planHash }) });
      }
      if (!alive.current || controller.signal.aborted) return;
      if (kind === 'approve') {
        const immutable = ['id', 'environmentId', 'directoryObjectId', 'requesterId', 'requestId', 'recipientKeyFingerprint',
          'planHash', 'policyVersion', 'directoryGeneration', 'expiresAt', 'reason'] as const;
        if (!validPlan(value, environmentId, id) || value.state !== 'Approved' || immutable.some(field => value[field] !== previous![field]))
          throw new Error('ApprovalResponseChanged');
      }
      accept(value, startedAt, kind === 'propose' ? undefined : kind === 'load' ? lookup : previous!.id, kind === 'load');
    } catch (failure) {
      if (!alive.current || controller.signal.aborted) return;
      setPlan(null);
      const definiteRejection = submitted && failure instanceof ApiError && failure.status >= 400 && failure.status < 500;
      setRetry(kind === 'propose' && attempt.current !== null && !definiteRejection);
      setError(failure instanceof ApiError && [409, 412].includes(failure.status) ? 'enrollmentPlans.changed' : 'enrollmentPlans.failed');
    } finally {
      if (alive.current && !controller.signal.aborted) setBusy(false);
      if (active.current === controller) active.current = null;
    }
  }

  function clear() {
    clearTimeout(planExpiry.current); discardKey(); attempt.current = null;
    setPlan(null); setLookup(''); setReason(''); setRetry(false); setExpired(false); setError('');
  }
  return <section className="asset-panel enrollment-plans" aria-label={t('enrollmentPlans.title')}>
    <h3>{t('enrollmentPlans.title')}</h3><p>{t('enrollmentPlans.description')}</p>
    {error && <p role="alert">{t(error)}</p>}
    {busy && <p role="status">{t('enrollmentPlans.busy')}</p>}
    {key.current && <p role="status">{t('enrollmentPlans.keyRetained')}</p>}
    {canRequest && !plan && !retry && !attempt.current && <form onSubmit={event => { event.preventDefault(); setExpired(false); void run('propose'); }}>
      <label>{t('enrollmentPlans.reason')}<input value={reason} maxLength={512} disabled={busy} onChange={event => setReason(event.target.value)} /></label>
      <button disabled={busy || reason.trim().length < 5}>{t('enrollmentPlans.create')}</button>
    </form>}
    {retry && <><p>{t('enrollmentPlans.uncertain')}</p><button disabled={busy} onClick={() => void run('propose')}>{t('enrollmentPlans.retry')}</button></>}
    <form onSubmit={event => { event.preventDefault(); void run('load'); }}>
      <label>{t('enrollmentPlans.lookup')}<input value={lookup} disabled={busy} maxLength={36} onChange={event => { clearTimeout(planExpiry.current); setLookup(event.target.value.trim().toLowerCase()); setPlan(null); }} /></label>
      <button type="submit" className="secondary-button" disabled={busy || !validId(lookup)}>{t('enrollmentPlans.load')}</button>
    </form>
    {plan && <>
      <dl><dt>{t('enrollmentPlans.lookup')}</dt><dd className="tag-hash">{plan.id}</dd>
        <dt>{t('enrollmentPlans.device')}</dt><dd>{plan.directoryObjectId}</dd>
        <dt>{t('enrollmentPlans.reason')}</dt><dd>{plan.reason}</dd>
        <dt>{t('enrollmentPlans.fingerprint')}</dt><dd className="tag-hash">{plan.recipientKeyFingerprint}</dd>
        <dt>{t('enrollmentPlans.hash')}</dt><dd className="tag-hash">{plan.planHash}</dd>
        <dt>{t('enrollmentPlans.expiry')}</dt><dd>{new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(plan.expiresAt))}</dd>
        <dt>{t('enrollmentPlans.state')}</dt><dd>{t(`tags.state.${expired ? 'Expired' : plan.state}`)}</dd></dl>
      {plan.canApprove && plan.state === 'PendingApproval' && !expired && <button disabled={busy} onClick={() => void run('approve')}>{t('enrollmentPlans.approve')}</button>}
      <p>{t('enrollmentPlans.noExecution')}</p>
      {plan.requesterId === actorId && !key.current && <p role="status">{t('enrollmentPlans.keyUnavailable')}</p>}
    </>}
    {key.current && <p>{t('enrollmentPlans.keyLifetime')}</p>}
    {(plan || retry || attempt.current) && <>
      <button className="secondary-button" disabled={busy} onClick={clear}>{t('enrollmentPlans.clear')}</button></>}
  </section>;
}
