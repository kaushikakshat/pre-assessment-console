import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import {
  Banner, Button, Card, ConfidenceTag, DataTable, Disclaimer, EmptyState, KeyValue, LoadError, Loading, ModuleProgress, SeverityBadge,
  SeverityBar, Select, StatusBadge, Tabs, Timeline, Checkbox, type Column,
} from '../components';
import { formatIST, relativeTime } from '../lib/format';
import { can } from '../lib/perm';
import { BLOCKED_COPY, PROFILE_NAMES } from '../lib/status';
import { useLoad } from '../lib/useLoad';
import {
  CONFIDENCES, FINDING_STATES, SEVERITIES, type Assessment, type AuditEvent, type Capacity, type Finding, type FindingState, type Job, type Severity,
} from '../lib/types';
import { SEVERITY } from '../lib/status';
import { FindingDrawer } from './FindingDrawer';

const ACTIVE = ['queued', 'validating', 'scheduled', 'running', 'cancelling'];
const NEEDS_ACTION: FindingState[] = ['new', 'open', 'under-review', 'reopened'];
const REVIEW_TEXT = { resumed: 'An administrator resumed the unfinished modules.', 'rerun-advised': 'An administrator advised running the scan again.', closed: 'An administrator closed this scan as is.' };
const runName = (j: Job) => (j.profile ? PROFILE_NAMES[j.profile] : 'Individual modules');

export function AssessmentDetail() {
  const { id = '' } = useParams();
  const nav = useNavigate();
  const [params, setParams] = useSearchParams();
  const a = useLoad<Assessment>(`/assessments/${id}`);
  const jobs = useLoad<Job[]>(`/assessments/${id}/jobs`);
  const findings = useLoad<Finding[]>(`/assessments/${id}/findings`);
  const queue = useLoad<{ capacity: Capacity }>('/queue');

  const activeId = jobs.data?.find((j) => ACTIVE.includes(j.state))?.id ?? null;
  const live = useLoad<Job>(activeId ? `/jobs/${activeId}` : null, (j) => (ACTIVE.includes(j.state) ? 3000 : 0));
  const liveState = live.data?.state;
  const { reload: reloadJobs } = jobs;
  const { reload: reloadFindings } = findings;
  const { reload: reloadAssessment } = a;
  useEffect(() => {
    if (liveState && !ACTIVE.includes(liveState)) { reloadJobs(); reloadFindings(); reloadAssessment(); }
  }, [liveState, reloadJobs, reloadFindings, reloadAssessment]);

  if (a.error && !a.data) return <LoadError error={a.error} thing={`assessment ${id}`} onRetry={a.reload} />;
  if (!a.data) return <Loading />;
  const as = a.data;
  const level = as.access;
  const latestRaw = jobs.data?.[0];
  const latest = latestRaw && live.data?.id === latestRaw.id ? live.data : latestRaw;
  const blocked = queue.data?.capacity.blocked_reason ?? null;
  const scanReason = as.status === 'awaiting-approval' ? 'Waiting for an administrator to approve this target.'
    : blocked ? BLOCKED_COPY[blocked] : null;
  const moduleName = (k: string) => latest?.modules.find((m) => m.key === k)?.name ?? k;
  const finding = params.get('finding');
  const closeDrawer = () => { const n = new URLSearchParams(params); n.delete('finding'); setParams(n, { replace: true }); };

  return (
    <div className="stack-lg">
      <div className="page-head">
        <div className="stack">
          <h1>{as.name}</h1>
          <div className="sub">
            {as.status !== 'active' && <StatusBadge kind="assessment" status={as.status} />}
            <span className="mono">{as.target}</span>
            <span>{as.env}</span>
            <span>Owner: {as.owner.name}</span>
            {level === 'admin' && <span className="badge tone-info">Administrator view</span>}
          </div>
        </div>
        {can(level, 'new-scan') && (
          <div className="stack">
            {as.status === 'draft' || as.status === 'blocked'
              ? <Link className="btn btn-primary btn-md btn-link" to={`/assessments/new?from=${as.id}`}>Edit & revalidate</Link>
              : <Button variant="primary" icon="plus" disabled={as.status !== 'active' || !!blocked} onClick={() => nav(`/assessments/${as.id}/scan`)}>New scan</Button>}
            {scanReason && <small className="muted">{scanReason}</small>}
          </div>
        )}
      </div>

      {as.status === 'awaiting-approval' && <Banner tone="warn" title="Awaiting approval">An administrator must approve this target before it can be scanned. No scan traffic is sent until then.</Banner>}
      {as.status === 'blocked' && <Banner tone="danger" title="Target blocked">{as.approval?.state === 'refused' ? `An administrator refused this target${as.approval.note ? `: ${as.approval.note}` : '.'} ` : ''}Target validation failed — no scan traffic was sent. Edit the target and validate again.</Banner>}
      {level === 'admin' && <Banner tone="info" title="Administrator view">This assessment belongs to {as.owner.name}. You can read it, but only the owner can change findings or start scans.</Banner>}
      {latest?.state === 'interrupted' && (
        <Banner tone="warn" title="Scan interrupted — partial results have been preserved">
          Completed modules and their findings are kept. Unfinished modules are reported as not tested. {latest.review ? REVIEW_TEXT[latest.review] : 'An administrator will review it.'}
        </Banner>
      )}
      {latest?.state === 'queued' && (
        <Banner tone="info" title="Waiting for capacity">
          Scan queued — another scan is using the available capacity.{latest.queue_position !== null && ` #${latest.queue_position} in queue`}
          {latest.wait_estimate && `, approx. ${latest.wait_estimate.lo_min}–${latest.wait_estimate.hi_min} min`}.
        </Banner>
      )}

      <Tabs tabs={[
        { key: 'overview', label: 'Overview' },
        { key: 'findings', label: 'Findings', count: findings.data?.length },
        { key: 'modules', label: 'Modules' },
        { key: 'history', label: 'Scan history' },
        { key: 'activity', label: 'Activity' },
      ]}>
        {(tab) => (
          <div className="stack-lg" style={{ marginTop: 'var(--space-4)' }}>
            {tab === 'overview' && <Overview as={as} latest={latest} findings={findings.data} />}
            {tab === 'findings' && (findings.error && !findings.data ? <LoadError error={findings.error} thing="findings" onRetry={findings.reload} /> : findings.data ? <Findings rows={findings.data} moduleName={moduleName} /> : <Loading />)}
            {tab === 'modules' && (latest ? <ModulesTab job={latest} /> : <Card><EmptyState title="No scan yet">Modules appear here after the first scan.</EmptyState></Card>)}
            {tab === 'history' && <History jobs={jobs.data} />}
            {tab === 'activity' && can(level, 'activity-tab') && <Activity id={as.id} />}
          </div>
        )}
      </Tabs>

      {finding && (
        <FindingDrawer key={finding} id={finding} access={level} ownerName={as.owner.name} moduleName={moduleName} onClose={closeDrawer} onChanged={reloadFindings} />
      )}
    </div>
  );
}

function Overview({ as, latest, findings }: { as: Assessment; latest?: Job; findings: Finding[] | null }) {
  const list = findings ?? [];
  const sev = Object.fromEntries(SEVERITIES.map((s) => [s, list.filter((f) => f.severity === s).length])) as Record<Severity, number>;
  const open = list.filter((f) => NEEDS_ACTION.includes(f.state)).length;
  return (
    <div className="grid2">
      <div className="stack-lg">
        <Card title="Findings summary">
          {!findings ? <Loading /> : (
            <>
              <SeverityBar counts={sev} />
              <p>{CONFIDENCES.map((c) => `${list.filter((f) => f.confidence === c).length} ${c}`).join(' · ')}</p>
              <p className="chips">
                {FINDING_STATES.filter((s) => list.some((f) => f.state === s)).map((s) => (
                  <span key={s} className="chip">{list.filter((f) => f.state === s).length} <StatusBadge kind="finding" status={s} /></span>
                ))}
              </p>
              <p><b>{open} {open === 1 ? 'finding still needs' : 'findings still need'} action</b></p>
            </>
          )}
        </Card>
        {latest ? (
          <>
            <h2>{ACTIVE.includes(latest.state) ? 'Current scan' : 'Latest scan'} · <StatusBadge kind="job" status={latest.state} live /></h2>
            <ModuleProgress job={latest} />
          </>
        ) : <Card title="Latest scan"><EmptyState title="No scan has run yet">Start a scan once the target is allowed.</EmptyState></Card>}
      </div>
      <div className="stack-lg">
        <Card title="Scope">
          <KeyValue items={[
            { label: 'Target', value: as.target, mono: true },
            { label: 'Environment', value: as.env },
            { label: 'Hosts', value: as.hosts, mono: true },
            { label: 'Paths', value: as.paths, mono: true },
            { label: 'Ports', value: as.ports, mono: true },
            { label: 'Exclusions', value: as.exclusions || '—', mono: true },
            { label: 'Validation', value: as.validation ? <StatusBadge kind="validation" status={as.validation.outcome} /> : 'Not validated' },
            { label: 'Policy', value: as.validation?.policy_version ?? '—', mono: true },
            { label: 'Notes', value: as.notes ?? '—' },
          ]} />
        </Card>
        <Disclaimer />
      </div>
    </div>
  );
}

function Findings({ rows, moduleName }: { rows: Finding[]; moduleName: (k: string) => string }) {
  const [params] = useSearchParams();
  const [f, setF] = useState({ severity: '', state: '', module: '', confidence: '' });
  const [group, setGroup] = useState(false);
  const modules = useMemo(() => [...new Set(rows.map((r) => r.module))], [rows]);
  const shown = rows.filter((r) => (!f.severity || r.severity === f.severity) && (!f.state || r.state === f.state) && (!f.module || r.module === f.module) && (!f.confidence || r.confidence === f.confidence));
  const open = (id: string) => { const n = new URLSearchParams(params); n.set('finding', id); return `?${n}`; };
  const cols: Column<Finding>[] = [
    { key: 'sev', header: 'Severity', render: (r) => <SeverityBadge severity={r.severity} compact /> },
    { key: 'title', header: 'Finding', render: (r) => <><Link to={open(r.id)}>{r.title}</Link><br /><small className="muted mono">{r.id} · {moduleName(r.module)}</small></> },
    { key: 'asset', header: 'Asset / endpoint', mono: true, render: (r) => r.asset },
    { key: 'conf', header: 'Confidence', render: (r) => <ConfidenceTag confidence={r.confidence} /> },
    { key: 'state', header: 'State', render: (r) => <StatusBadge kind="finding" status={r.state} /> },
  ];
  const pick = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const table = (rs: Finding[], caption: string) => (
    <DataTable key={caption} caption={caption} columns={cols} rows={rs} rowKey={(r) => r.id} empty={{ title: 'Nothing here' }} />
  );
  const filtered = Object.values(f).some(Boolean);
  return (
    <>
      <div className="filters">
        <Select id="f-sev" label="Severity" value={f.severity} onChange={pick('severity')}><option value="">All</option>{SEVERITIES.map((s) => <option key={s} value={s}>{SEVERITY[s].label}</option>)}</Select>
        <Select id="f-state" label="State" value={f.state} onChange={pick('state')}><option value="">All</option>{FINDING_STATES.map((s) => <option key={s} value={s}>{s}</option>)}</Select>
        <Select id="f-mod" label="Module" value={f.module} onChange={pick('module')}><option value="">All</option>{modules.map((m) => <option key={m} value={m}>{moduleName(m)}</option>)}</Select>
        <Select id="f-conf" label="Confidence" value={f.confidence} onChange={pick('confidence')}><option value="">All</option>{CONFIDENCES.map((c) => <option key={c} value={c}>{c}</option>)}</Select>
        <Checkbox checked={group} onChange={(e) => setGroup(e.target.checked)} label="Group by module" />
      </div>
      {shown.length === 0 ? (
        <Card><EmptyState title={filtered ? 'No findings match these filters' : 'No findings yet'}
          action={filtered ? <Button onClick={() => setF({ severity: '', state: '', module: '', confidence: '' })}>Clear filters</Button> : undefined}>
          {filtered ? 'Change or clear the filters to see more.' : 'Findings appear here after a scan finishes.'}
        </EmptyState></Card>
      ) : group
        ? modules.filter((m) => shown.some((r) => r.module === m)).map((m) => <div key={m} className="stack"><h2 className="group-title">{moduleName(m)}</h2>{table(shown.filter((r) => r.module === m), moduleName(m))}</div>)
        : table(shown, 'Findings')}
    </>
  );
}

function ModulesTab({ job }: { job: Job }) {
  const cols: Column<Job['modules'][number]>[] = [
    { key: 'name', header: 'Module', render: (m) => m.name },
    { key: 'state', header: 'State', render: (m) => <StatusBadge kind="module" status={m.state} /> },
    { key: 'detail', header: 'Detail', render: (m) => m.detail ?? '—' },
  ];
  return <><p className="muted">Modules of <span className="mono">{job.id}</span></p><DataTable caption="Modules" columns={cols} rows={job.modules} rowKey={(m) => m.key} empty={{ title: 'No modules' }} /></>;
}

function History({ jobs }: { jobs: Job[] | null }) {
  if (!jobs) return <Loading />;
  const cols: Column<Job>[] = [
    { key: 'id', header: 'Job', mono: true, render: (j) => j.id },
    { key: 'run', header: 'Run', render: runName },
    { key: 'sub', header: 'Submitted', render: (j) => `${formatIST(j.submitted_at)} (${relativeTime(j.submitted_at)})` },
    { key: 'end', header: 'Finished', render: (j) => formatIST(j.ended_at) },
    { key: 'by', header: 'Requested by', render: (j) => j.requested_by },
    { key: 'st', header: 'State', render: (j) => <StatusBadge kind="job" status={j.state} /> },
  ];
  return <DataTable caption="Scan history" columns={cols} rows={jobs} rowKey={(j) => j.id} empty={{ title: 'No scans yet', text: 'Scans you run on this assessment are listed here.' }} />;
}

function Activity({ id }: { id: string }) {
  const { data, error, reload } = useLoad<AuditEvent[]>(`/assessments/${id}/activity`);
  if (error && !data) return <LoadError error={error} thing="activity" onRetry={reload} />;
  if (!data) return <Loading />;
  return (
    <Card title="Activity">
      <Timeline rows={data.map((e) => ({ at: e.at, text: <>{e.actor} · {e.action} · <span className="mono">{e.object}</span>{e.detail && <span className="muted"> — {e.detail}</span>}</> }))} />
    </Card>
  );
}
