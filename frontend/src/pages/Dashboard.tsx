import { Link, useNavigate } from 'react-router-dom';
import { Banner, Card, CapacityMeter, Disclaimer, LiveNote, LoadError, Loading, ModuleProgress, StatCard, StatusBadge } from '../components';
import { BLOCKED_COPY } from '../lib/status';
import { useLoad } from '../lib/useLoad';
import type { Dashboard as DashboardData } from '../lib/types';
import { AssessmentTable, NewAssessmentLink } from './Assessments';

export function Dashboard() {
  const nav = useNavigate();
  const { data, error, stalled, reload } = useLoad<DashboardData>('/dashboard', (d) => (d.active_job ? 5000 : 0));
  const job = data?.active_job;
  return (
    <div className="stack-lg">
      <div className="page-head">
        <h1>Dashboard</h1>
        <NewAssessmentLink />
      </div>
      <Disclaimer />
      {error && !data && <LoadError error={error} thing="the dashboard" onRetry={reload} />}
      {!data && !error && <Loading />}
      <LiveNote stalled={stalled} />
      {data && (
        <>
          {data.capacity.blocked_reason && (
            <Banner tone="danger" title="New scans are blocked">{BLOCKED_COPY[data.capacity.blocked_reason]}</Banner>
          )}
          <div className="stats stats-3">
            <StatCard label="My assessments" value={data.counts.assessments} onClick={() => nav('/assessments')} />
            <StatCard label="Open findings" value={data.counts.open_findings} onClick={() => nav('/assessments')} />
            <StatCard label="Active jobs" value={data.counts.active_jobs} onClick={() => nav('/queue')} />
          </div>
          <Card title="Active scan" action={job && <StatusBadge kind="job" status={job.state} live />}>
            {job ? (
              <>
                <p><Link to={`/assessments/${job.assessment_id}`}>{job.assessment_name}</Link> · <span className="mono">{job.id}</span></p>
                <ModuleProgress job={job} compact />
                {job.queue_position !== null && <p className="muted">#{job.queue_position} in queue</p>}
              </>
            ) : <p className="muted">No scan is running or queued.</p>}
            <CapacityMeter capacity={data.capacity} />
          </Card>
          <h2>Recent assessments</h2>
          <AssessmentTable rows={data.recent} />
        </>
      )}
    </div>
  );
}
