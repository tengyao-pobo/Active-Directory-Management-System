import { useEffect, useRef, useState, type FormEvent } from 'react';
import { request } from './api';
import { useI18n } from './i18n';

interface Proposal {
  environmentId: string; target: { id: string; name: string; distinguishedName: string; usnChanged: number };
  kind: string; before: string | null; after: string; asOf: string; snapshotValidUntil: string;
  approvalAvailable: false; executionAvailable: false; blockers: string[];
}

export default function DirectoryProposal({ environmentId, id }: { environmentId: string; id: string }) {
  const { t } = useI18n();
  const [department, setDepartment] = useState('');
  const [proposal, setProposal] = useState<Proposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);
  const [expired, setExpired] = useState(false);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  useEffect(() => {
    if (!proposal) return;
    const remaining = Date.parse(proposal.snapshotValidUntil) - Date.now();
    const timer = window.setTimeout(() => { setProposal(null); setExpired(true); }, Math.max(0, remaining));
    return () => window.clearTimeout(timer);
  }, [proposal]);
  const preview = async (event: FormEvent) => {
    event.preventDefault(); active.current?.abort();
    const controller = new AbortController(); active.current = controller;
    setProposal(null); setError(false); setExpired(false); setBusy(true);
    try {
      const { token } = await request<{ token: string }>('/api/v1/session/csrf', { signal: controller.signal });
      const result = await request<Proposal>(`/api/v1/environments/${encodeURIComponent(environmentId)}/directory/users/${encodeURIComponent(id)}/proposal`, {
        method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json', 'X-CSRF-TOKEN': token },
        body: JSON.stringify({ kind: 'SetUserDepartment', department: department.trim() }),
      });
      if (controller.signal.aborted) return;
      if (result.environmentId !== environmentId || result.target.id !== id || result.kind !== 'SetUserDepartment' ||
          !Number.isFinite(Date.parse(result.snapshotValidUntil))) throw new Error('InvalidProposal');
      if (Date.parse(result.snapshotValidUntil) <= Date.now()) { setExpired(true); return; }
      setProposal(result);
    } catch { if (!controller.signal.aborted) setError(true); }
    finally { if (!controller.signal.aborted) setBusy(false); }
  };
  return <section className="directory-proposal" aria-label={t('proposal.title')}>
    <h3>{t('proposal.title')}</h3><p>{t('proposal.help')}</p>
    <form onSubmit={event => void preview(event)}>
      <label>{t('proposal.department')}<input required maxLength={128} value={department} disabled={busy} onChange={event => { setDepartment(event.target.value); setProposal(null); setExpired(false); setError(false); }} /></label>
      <button className="secondary-button" disabled={busy || !department.trim()}>{t(busy ? 'proposal.loading' : 'proposal.preview')}</button>
    </form>
    {error && <p role="alert">{t('proposal.error')}</p>}
    {expired && <p role="status">{t('proposal.expired')}</p>}
    {proposal && <div className="proposal-review" role="region" aria-label={t('proposal.review')}>
      <h4>{t('proposal.review')}</h4>
      <dl className="definition-grid">
        <div><dt>{t('proposal.target')}</dt><dd>{proposal.target.name}<br />{proposal.target.id}<br />{proposal.target.distinguishedName}</dd></div>
        <div><dt>{t('proposal.before')}</dt><dd>{proposal.before ?? '—'}</dd></div>
        <div><dt>{t('proposal.after')}</dt><dd>{proposal.after}</dd></div>
        <div><dt>{t('proposal.asOf')}</dt><dd>{proposal.asOf}</dd></div>
      </dl>
      <p>{t('proposal.noChange')}</p>
      <ul>{proposal.blockers.map(code => <li key={code}>{t(`proposal.blocker.${code}`)}</li>)}</ul>
      <button className="secondary-button" disabled>{t('proposal.approve')}</button>
    </div>}
  </section>;
}
