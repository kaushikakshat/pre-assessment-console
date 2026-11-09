import { useState } from 'react';
import { api, ApiError } from '../lib/api';
import type { Finding, Job } from '../lib/types';
import { Banner } from './Banner';
import { Button } from './Button';
import { SeverityBadge, StatusBadge } from './Badges';
import { DataTable } from './DataTable';
import { Checkbox } from './Fields';
import { Modal } from './Overlay';

/** False-positive and accepted-risk findings cannot be retested (backend answers 422). */
export const retestable = (f: Finding) => f.state !== 'false-positive' && f.state !== 'accepted-risk';

const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`);

// DESIGN_SYSTEM §7.7
export function RetestModal({ assessmentId, target, findings, moduleName, blocked, onClose, onQueued }: {
  assessmentId: string; target: string; findings: Finding[]; moduleName: (k: string) => string; blocked: string | null; onClose: () => void; onQueued: (j: Job) => void;
}) {
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [key] = useState(uuid); // a retry returns the same job
  // Mirrors the backend rule: reach + the findings' modules, crawl for engine findings, auth for credentialed ones.
  const hasCred = findings.some((f) => f.credential_id);
  const known = findings.every((f) => 'credential_id' in f);
  const engine = findings.some((f) => ['crawl', 'dast', 'api'].includes(f.module));
  const modules = [...new Set(['reach', ...findings.map((f) => f.module), ...(engine ? ['crawl'] : []), ...(hasCred ? ['auth'] : [])])];
  const n = findings.length;

  const submit = async () => {
    setBusy(true); setError(null);
    try {
      onQueued(await api<Job>(`/assessments/${assessmentId}/retest`, { method: 'POST', body: { finding_ids: findings.map((f) => f.id), authorized: true, idempotency_key: key } }));
    } catch (e) {
      setError(e instanceof ApiError ? e.detail : 'The retest was not queued. Try again.');
    } finally { setBusy(false); }
  };

  return (
    <Modal open wide title={`Request retest of ${n} ${n === 1 ? 'finding' : 'findings'}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!authorized || !!blocked || n === 0} busy={busy} busyLabel="Queuing…" onClick={submit}>Queue retest</Button></>}>
      <DataTable caption="Selected findings" rows={findings} rowKey={(f) => f.id} empty={{ title: 'No findings selected' }}
        columns={[
          { key: 's', header: 'Severity', render: (f) => <SeverityBadge severity={f.severity} compact /> },
          { key: 't', header: 'Finding', render: (f) => <>{f.title}<br /><small className="muted mono">{f.id}</small></> },
          { key: 'st', header: 'State', render: (f) => <StatusBadge kind="finding" status={f.state} /> },
        ]} />
      <p>{known ? 'Modules to run' : 'Includes at least'}</p>
      <p className="chips">{modules.map((m) => <span key={m} className="chip">{moduleName(m)}</span>)}</p>
      <p>Scope: <span className="mono">{target}</span></p>
      <p className="muted">Other findings from these modules that the retest does not observe will be marked &lsquo;Not retested&rsquo;.</p>
      {blocked && <Banner tone="warn" title="Submissions are paused">{blocked}</Banner>}
      {error && <Banner tone="danger" title="Not queued">{error}</Banner>}
      <Checkbox checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} label="I confirm I am still authorized to test this target within the scope above." />
    </Modal>
  );
}
