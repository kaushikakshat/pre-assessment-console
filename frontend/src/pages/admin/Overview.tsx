import { Link, useNavigate } from 'react-router-dom';
import { Card, CapacityMeter, DataTable, LiveNote, LoadError, Loading, StatCard, StatusBadge, type Column } from '../../components';
import { formatIST } from '../../lib/format';
import { PROFILE_NAMES } from '../../lib/status';
import { useLoad } from '../../lib/useLoad';
import type { AuditEvent, Capacity, Worker } from '../../lib/types';
import { AREAS, OutcomeBadge, ownerName, type AdminJob } from './common';

interface Overview { capacity: Capacity; workers: Worker[]; approvals_pending: number; interrupted_unreviewed: number; running: AdminJob[]; recent_audit: AuditEvent[] }

export function AdminOverview() {
  const { data, error, stalled, reload } = useLoad<Overview>('/admin/overview', () => 5000);
  const go = useNavigate();
  if (error && !data) return <LoadError error={error} thing="the admin overview" onRetry={reload} />;
  if (!data) return <Loading />;
  const needs = data.approvals_pending + data.interrupted_unreviewed;
  const running: Column<AdminJob>[] = [
    { key: 'job', header: 'Job', mono: true, render: (j) => j.id },
    { key: 'a', header: 'Assessment · target', render: (j) => <><Link to={`/assessments/${j.assessment_id}`}>{j.assessment_name}</Link><br /><span className="mono muted">{j.target}</span></> },
    { key: 'o', header: 'Owner', render: (j) => ownerName(j.owner) },
    { key: 'run', header: 'Run', render: (j) => (j.profile ? PROFILE_NAMES[j.profile] : 'Individual modules') },
    { key: 'st', header: 'Status', render: (j) => <StatusBadge kind="job" status={j.state} /> },
  ];
  const events: Column<AuditEvent>[] = [
    { key: 'at', header: 'When', render: (e) => formatIST(e.at) },
    { key: 'who', header: 'Actor', render: (e) => e.actor },
    { key: 'area', header: 'Area', render: (e) => AREAS[e.area] ?? e.area },
    { key: 'act', header: 'Action', render: (e) => e.action },
    { key: 'obj', header: 'Object', mono: true, render: (e) => e.object },
    { key: 'out', header: 'Outcome', render: (e) => <OutcomeBadge outcome={e.outcome} /> },
  ];
  return (
    <div className="stack-lg">
      <h1>Admin overview</h1>
      <LiveNote stalled={stalled} />
      <div className="stats stats-3">
        <StatCard label="Active · queued" value={`${data.capacity.active} · ${data.capacity.queued}`} context="Scans running now · waiting" onClick={() => go('/admin/jobs?tab=jobs')} />
        <StatCard label="Healthy workers" value={data.capacity.healthy_workers} context={`of ${data.workers.length} registered`} onClick={() => go('/admin/capacity')} />
        <StatCard label="Needs a decision" value={needs} tone={needs ? 'danger' : undefined} context={`${data.approvals_pending} approvals · ${data.interrupted_unreviewed} interrupted`}
          onClick={() => go(`/admin/jobs?tab=${data.approvals_pending ? 'approvals' : 'interrupted'}`)} />
      </div>
      <Card title="Scanning now">
        <div className="stack">
          <CapacityMeter capacity={data.capacity} />
          <DataTable caption="Running scans" columns={running} rows={data.running} rowKey={(j) => j.id} empty={{ title: 'No scans are running' }} />
        </div>
      </Card>
      <h2>Recent administrative events</h2>
      <DataTable caption="Recent administrative events" columns={events} rows={data.recent_audit} rowKey={(e) => e.id} empty={{ title: 'No events yet' }} />
    </div>
  );
}
