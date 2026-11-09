import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../lib/api';
import { ApprovalDecision, Banner, Button, DataTable, LoadError, Loading, Modal, OptionCard, ReasonConfirm, Select, StatusBadge, Tabs, Textarea, useToast, type Column } from '../../components';
import { formatIST, relativeTime } from '../../lib/format';
import { PROFILE_NAMES } from '../../lib/status';
import { useLoad } from '../../lib/useLoad';
import { PRIORITIES, type Assessment, type Priority } from '../../lib/types';
import { ownerName, useAct, type AdminJob } from './common';

interface Approval { assessment: Assessment; requested_at: string; own: boolean }
const run = (j: AdminJob) => (j.profile ? PROFILE_NAMES[j.profile] : 'Individual modules');
const done = (s: string) => s === 'completed' || s === 'completed-warnings';
const REVIEW = { resumed: 'Resumed', 'rerun-advised': 'Full rerun advised', closed: 'Closed as interrupted' } as const;
const FILTERS = [['active', 'Queued and running'], ['interrupted', 'Interrupted'], ['all', 'All']] as const;
const OUTCOMES = [
  ['resume', 'Resume safe modules', 'Starts a new linked job with only the unfinished modules, under the current policy.'],
  ['rerun-advised', 'Advise a full rerun', 'Leaves this job as it is and tells the owner to run the whole scan again.'],
  ['closed', 'Close as interrupted', 'Marks the review done with no follow-up scan.'],
] as const;

export function AdminJobs() {
  const approvals = useLoad<Approval[]>('/admin/approvals');
  const interrupted = useLoad<AdminJob[]>('/admin/jobs?filter=interrupted');
  const unreviewed = interrupted.data?.filter((j) => j.review === null).length;
  return (
    <div className="stack-lg">
      <h1>Assessments / Jobs</h1>
      <Tabs tabs={[{ key: 'approvals', label: 'Approval requests', count: approvals.data?.length }, { key: 'interrupted', label: 'Interrupted', count: unreviewed }, { key: 'jobs', label: 'Jobs' }]}>
        {(tab) => tab === 'approvals' ? <Approvals load={approvals} /> : tab === 'interrupted' ? <Interrupted load={interrupted} /> : <Jobs onChanged={interrupted.reload} />}
      </Tabs>
    </div>
  );
}

function Approvals({ load }: { load: ReturnType<typeof useLoad<Approval[]>> }) {
  const [open, setOpen] = useState<Approval | null>(null);
  const toast = useToast();
  const cols: Column<Approval>[] = [
    { key: 'a', header: 'Assessment', render: (r) => <>
      <Link to={`/assessments/${r.assessment.id}`}>{r.assessment.name}</Link>
      {r.own && <> <span className="badge tone-warn">Your own request</span></>}</> },
    { key: 't', header: 'Target', mono: true, render: (r) => r.assessment.target },
    { key: 'e', header: 'Environment', render: (r) => r.assessment.env },
    { key: 'o', header: 'Owner', render: (r) => r.assessment.owner.name },
    { key: 'r', header: 'Requested', render: (r) => relativeTime(r.requested_at) },
    { key: 'x', header: <span className="sr-only">Decision</span>, render: (r) => <Button size="sm" variant="primary" aria-label={`Decide on ${r.assessment.name}`} onClick={() => setOpen(r)}>Decide</Button> },
  ];
  return (
    <div className="stack">
      {load.error && !load.data && <LoadError error={load.error} thing="approval requests" onRetry={load.reload} />}
      {!load.data && !load.error && <Loading />}
      {load.data && <DataTable caption="Approval requests" columns={cols} rows={load.data} rowKey={(r) => r.assessment.id} empty={{ title: 'No approval requests', text: 'Targets that need approval appear here.' }} />}
      <p className="muted">Approval never overrides safety invariants or scope.</p>
      {open && <ApprovalDecision assessment={open.assessment} own={open.own} onClose={() => setOpen(null)}
        onDecided={(d) => { setOpen(null); toast(d === 'approve' ? 'Target approved.' : 'Target refused.'); load.reload(); }} />}
    </div>
  );
}

function Interrupted({ load }: { load: ReturnType<typeof useLoad<AdminJob[]>> }) {
  const [job, setJob] = useState<AdminJob | null>(null);
  const cols: Column<AdminJob>[] = [
    { key: 'j', header: 'Job', mono: true, render: (j) => j.id },
    { key: 'a', header: 'Assessment', render: (j) => <Link to={`/assessments/${j.assessment_id}`}>{j.assessment_name}</Link> },
    { key: 'o', header: 'Owner', render: (j) => ownerName(j.owner) },
    { key: 's', header: 'Stopped', render: (j) => formatIST(j.ended_at ?? j.started_at) },
    { key: 'u', header: 'Unfinished modules', render: (j) => j.modules.filter((m) => !done(m.state)).length },
    { key: 'r', header: 'Review', render: (j) => (j.review ? REVIEW[j.review] : 'Needs review') },
    { key: 'x', header: <span className="sr-only">Review</span>, render: (j) => !j.review && <Button size="sm" aria-label={`Review ${j.id}`} onClick={() => setJob(j)}>Review</Button> },
  ];
  return (
    <div className="stack">
      {load.error && !load.data && <LoadError error={load.error} thing="interrupted jobs" onRetry={load.reload} />}
      {!load.data && !load.error && <Loading />}
      {load.data && <DataTable caption="Interrupted jobs" columns={cols} rows={load.data} rowKey={(j) => j.id} empty={{ title: 'No interrupted jobs' }} />}
      {job && <ReviewModal job={job} onClose={() => setJob(null)} onDone={() => { setJob(null); load.reload(); }} />}
    </div>
  );
}

function ReviewModal({ job, onClose, onDone }: { job: AdminJob; onClose: () => void; onDone: () => void }) {
  const [outcome, setOutcome] = useState<string | null>(null);
  const [reason, setReason] = useState('');
  const act = useAct();
  const names = (finished: boolean) => job.modules.filter((m) => done(m.state) === finished);
  const list = (title: string, ms: typeof job.modules) => (
    <div><h3>{title}</h3>{ms.length ? <ul>{ms.map((m) => <li key={m.key}>{m.name} · <StatusBadge kind="module" status={m.state} /></li>)}</ul> : <p className="muted">None.</p>}</div>
  );
  const save = async () => { if (await act.run(() => api(`/admin/jobs/${job.id}/review`, { method: 'POST', body: { outcome, reason: reason.trim() } }), `${job.id} reviewed.`)) onDone(); };
  return (
    <Modal open wide title={`Review ${job.id}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={act.busy} disabled={!outcome || !reason.trim()} onClick={save}>Save review</Button></>}>
      <div className="f2">{list('Completed', names(true))}{list('Not finished', names(false))}</div>
      <div role="radiogroup" aria-label="Review outcome" className="stack">
        {OUTCOMES.map(([k, t, d]) => <OptionCard key={k} type="radio" name="outcome" title={t} description={d} checked={outcome === k} onChange={() => setOutcome(k)} />)}
      </div>
      <Textarea id="review-reason" label="Reason" required hint="Recorded in the audit log." value={reason} onChange={(e) => setReason(e.target.value)} />
      {act.failure && <Banner tone="danger" title="Not saved">{act.failure}</Banner>}
    </Modal>
  );
}

function Jobs({ onChanged }: { onChanged: () => void }) {
  const [filter, setFilter] = useState<string>('active');
  const load = useLoad<AdminJob[]>(`/admin/jobs?filter=${filter}`);
  const [pri, setPri] = useState<AdminJob | null>(null);
  const [cancel, setCancel] = useState<AdminJob | null>(null);
  const act = useAct();
  const doCancel = async (reason: string) => {
    if (await act.run(() => api(`/admin/jobs/${cancel!.id}/cancel`, { method: 'POST', body: { reason } }), `${cancel!.id} cancel requested.`)) { setCancel(null); load.reload(); onChanged(); }
  };
  const cols: Column<AdminJob>[] = [
    { key: 'j', header: 'Job', render: (j) => <><span className="mono">{j.id}</span>{j.resume_of && <><br /><span className="muted">resumes {j.resume_of}</span></>}</> },
    { key: 'a', header: 'Assessment · target', render: (j) => <><Link to={`/assessments/${j.assessment_id}`}>{j.assessment_name}</Link><br /><span className="mono muted">{j.target}</span></> },
    { key: 'o', header: 'Owner', render: (j) => ownerName(j.owner) },
    { key: 'r', header: 'Run', render: run },
    { key: 'p', header: 'Priority', render: (j) => (j.state === 'queued'
      ? <button type="button" className="link-btn" aria-label={`Change priority of ${j.id}`} onClick={() => { act.clear(); setPri(j); }}>{j.priority}</button> : j.priority) },
    { key: 's', header: 'Submitted', render: (j) => relativeTime(j.submitted_at) },
    { key: 'st', header: 'Status', render: (j) => <StatusBadge kind="job" status={j.state} /> },
    { key: 'x', header: <span className="sr-only">Cancel</span>, render: (j) => ['queued', 'validating', 'scheduled', 'running'].includes(j.state)
      && <Button size="sm" variant="danger-outline" aria-label={`Cancel ${j.id}`} onClick={() => { act.clear(); setCancel(j); }}>Cancel</Button> },
  ];
  return (
    <div className="stack">
      <Select id="job-filter" label="Show" value={filter} onChange={(e) => setFilter(e.target.value)}>
        {FILTERS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
      </Select>
      {load.error && !load.data && <LoadError error={load.error} thing="jobs" onRetry={load.reload} />}
      {!load.data && !load.error && <Loading />}
      {load.data && <DataTable caption="Jobs" columns={cols} rows={load.data} rowKey={(j) => j.id} empty={{ title: 'No jobs match this filter' }} />}
      <p className="muted">Priority can be changed on queued jobs only, by administrators. It never bypasses authorization, scope or capacity.</p>
      {pri && <PriorityModal job={pri} onClose={() => setPri(null)} onDone={() => { setPri(null); load.reload(); }} />}
      {cancel && (
        <ReasonConfirm open tone="danger" title={`Cancel ${cancel.id}?`} cancelLabel="Keep scanning" confirmLabel="Cancel scan" busy={act.busy}
          onCancel={() => setCancel(null)} onConfirm={doCancel} extra={act.failure && <Banner tone="danger" title="Not cancelled">{act.failure}</Banner>}>
          The owner is notified. A running scan stops after its current step; a queued scan leaves the queue.
        </ReasonConfirm>
      )}
    </div>
  );
}

function PriorityModal({ job, onClose, onDone }: { job: AdminJob; onClose: () => void; onDone: () => void }) {
  const [p, setP] = useState<Priority>(job.priority);
  const [reason, setReason] = useState('');
  const act = useAct();
  const save = async () => { if (await act.run(() => api(`/admin/jobs/${job.id}/priority`, { method: 'POST', body: { priority: p, reason: reason.trim() } }), `${job.id} priority set to ${p}.`)) onDone(); };
  return (
    <Modal open title={`Change priority of ${job.id}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={act.busy} disabled={!reason.trim() || p === job.priority} onClick={save}>Save priority</Button></>}>
      <div className="seg-ctl" role="group" aria-label="Priority">
        {PRIORITIES.map((x) => <button key={x} type="button" aria-pressed={p === x} onClick={() => setP(x)}>{x}</button>)}
      </div>
      <Textarea id="pri-reason" label="Reason" required hint="Recorded in the audit log." value={reason} onChange={(e) => setReason(e.target.value)} />
      {act.failure && <Banner tone="danger" title="Not saved">{act.failure}</Banner>}
    </Modal>
  );
}
