import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, ApiError } from '../lib/api';
import { Banner, Button, CapacityMeter, ConfirmDialog, DataTable, LiveNote, LoadError, Loading, StatusBadge, useToast, type Column } from '../components';
import { relativeTime } from '../lib/format';
import { BLOCKED_COPY, PROFILE_NAMES } from '../lib/status';
import { useLoad } from '../lib/useLoad';
import type { Capacity, Job, JobState } from '../lib/types';

interface QueueData {
  capacity: Capacity; mine: Job[]; recent: Job[];
  platform: { position: number; mine: boolean; state: JobState; job_id: string | null }[];
}
type Slot = QueueData['platform'][number];

const run = (j: Job) => (j.profile ? PROFILE_NAMES[j.profile] : 'Individual modules');
const jobLink = (j: Job) => <Link to={`/assessments/${j.assessment_id}`}>{j.assessment_name}</Link>;

export function Queue() {
  const { data, error, stalled, reload } = useLoad<QueueData>('/queue', () => 5000);
  const toast = useToast();
  const [cancelling, setCancelling] = useState<Job | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const cancel = async () => {
    if (!cancelling) return;
    setBusy(true);
    try {
      await api(`/jobs/${cancelling.id}/cancel`, { method: 'POST' });
      toast(`${cancelling.id} cancel requested.`);
      setFailure(null);
      reload();
    } catch (e) {
      setFailure(e instanceof ApiError ? e.detail : 'The scan could not be cancelled. Try again.');
    }
    setBusy(false);
    setCancelling(null);
  };

  const mineCols: Column<Job>[] = [
    { key: 'job', header: 'Job', mono: true, render: (j) => j.id },
    { key: 'a', header: 'Assessment', render: jobLink },
    { key: 'run', header: 'Run', render: run },
    { key: 'pri', header: 'Priority', render: (j) => j.priority },
    { key: 'sub', header: 'Submitted', render: (j) => relativeTime(j.submitted_at) },
    { key: 'pos', header: 'Position · wait', render: (j) => (j.queue_position === null ? '—' : `#${j.queue_position}${j.wait_estimate ? ` · approx. ${j.wait_estimate.lo_min}–${j.wait_estimate.hi_min} min` : ''}`) },
    { key: 'st', header: 'Status', render: (j) => <StatusBadge kind="job" status={j.state} /> },
    { key: 'x', header: <span className="sr-only">Actions</span>, render: (j) => (
      <Button size="sm" variant="danger-outline" aria-label={`Cancel ${j.id}`} disabled={j.state === 'cancelling'} onClick={() => setCancelling(j)}>Cancel</Button>
    ) },
  ];
  const platformCols: Column<Slot>[] = [
    { key: 'slot', header: 'Slot', render: (s) => `#${s.position}` },
    { key: 'job', header: 'Job', render: (s) => (s.mine && s.job_id ? <span className="mono">{s.job_id}</span> : "Another user's scan") },
    { key: 'st', header: 'Status', render: (s) => <StatusBadge kind="job" status={s.state} /> },
  ];
  const recentCols: Column<Job>[] = [
    { key: 'job', header: 'Job', mono: true, render: (j) => j.id },
    { key: 'a', header: 'Assessment', render: jobLink },
    { key: 'run', header: 'Run', render: run },
    { key: 'end', header: 'Finished', render: (j) => (j.ended_at ? relativeTime(j.ended_at) : '—') },
    { key: 'st', header: 'Status', render: (j) => <StatusBadge kind="job" status={j.state} /> },
  ];

  return (
    <div className="stack-lg">
      <h1>Scan Queue</h1>
      {error && !data && <LoadError error={error} thing="the scan queue" onRetry={reload} />}
      {!data && !error && <Loading />}
      <LiveNote stalled={stalled} />
      {failure && <Banner tone="danger" title="Cancel failed">{failure} Check the queue below, then try again.</Banner>}
      {data && (
        <>
          {data.capacity.blocked_reason && <Banner tone="danger" title="New scans are blocked">{BLOCKED_COPY[data.capacity.blocked_reason]} Queued jobs keep their place.</Banner>}
          <CapacityMeter capacity={data.capacity} />
          <p className="muted">Order: authorised and eligible jobs by priority (High, Normal, Low), then by submission sequence. Waiting jobs can gain priority over time, as set by an administrator.</p>
          <h2>Your queued and running jobs</h2>
          <DataTable caption="Your queued and running jobs" columns={mineCols} rows={data.mine} rowKey={(j) => j.id} empty={{ title: 'Nothing queued or running', text: 'Scans you submit appear here until they finish.' }} />
          <h2>Platform queue</h2>
          <DataTable caption="Platform queue" columns={platformCols} rows={data.platform} rowKey={(s) => String(s.position)} empty={{ title: 'The queue is empty' }} />
          <h2>Your recent finished jobs</h2>
          <DataTable caption="Your recent finished jobs" columns={recentCols} rows={data.recent} rowKey={(j) => j.id} empty={{ title: 'No finished jobs yet' }} />
        </>
      )}
      <ConfirmDialog
        open={!!cancelling} title={`Cancel ${cancelling?.id}?`} tone="danger" busy={busy}
        cancelLabel="Keep scanning" confirmLabel="Cancel scan" onCancel={() => setCancelling(null)} onConfirm={cancel}
      >
        {cancelling?.state === 'running'
          ? 'The scan stops after its current step. Results found so far are kept.'
          : 'The scan leaves the queue and its modules are skipped.'}
      </ConfirmDialog>
    </div>
  );
}
