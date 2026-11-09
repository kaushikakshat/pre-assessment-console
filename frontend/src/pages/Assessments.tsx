import { Link } from 'react-router-dom';
import { DataTable, LoadError, Loading, StatusBadge, type Column } from '../components';
import { relativeTime } from '../lib/format';
import { useLoad } from '../lib/useLoad';
import type { AssessmentSummary } from '../lib/types';

export const NewAssessmentLink = ({ primary = true }: { primary?: boolean }) => (
  <Link to="/assessments/new" className={`btn btn-md btn-link ${primary ? 'btn-primary' : 'btn-secondary'}`}>New assessment</Link>
);

// §5.5: assessment status when not active, otherwise the latest job's state; an active target with no scan yet shows "Allowed".
function Status({ a }: { a: AssessmentSummary }) {
  if (a.status !== 'active') return <StatusBadge kind="assessment" status={a.status} />;
  if (a.last_job) return <StatusBadge kind="job" status={a.last_job.state} />;
  return <StatusBadge kind="validation" status="allowed" />;
}

const columns: Column<AssessmentSummary>[] = [
  { key: 'name', header: 'Assessment', render: (a) => <Link to={`/assessments/${a.id}`}>{a.name}</Link> },
  { key: 'target', header: 'Target', mono: true, render: (a) => a.target },
  { key: 'env', header: 'Environment', render: (a) => a.env },
  { key: 'status', header: 'Status', render: (a) => <Status a={a} /> },
  { key: 'open', header: 'Open findings', align: 'right', render: (a) => a.open_findings },
  { key: 'last', header: 'Last scan', render: (a) => (a.last_job ? relativeTime(a.last_job.submitted_at) : '—') },
];

export function AssessmentTable({ rows }: { rows: AssessmentSummary[] }) {
  return (
    <DataTable
      caption="Assessments" columns={columns} rows={rows} rowKey={(a) => a.id}
      empty={{ title: 'No assessments yet', text: 'Create an assessment with your target and scope. The target is validated before any scan can run.', action: <NewAssessmentLink /> }}
    />
  );
}

export function Assessments() {
  const { data, error, reload } = useLoad<AssessmentSummary[]>('/assessments');
  return (
    <div className="stack-lg">
      <div className="page-head">
        <h1>My Assessments</h1>
        <NewAssessmentLink />
      </div>
      {error && !data ? <LoadError error={error} thing="your assessments" onRetry={reload} /> : data ? <AssessmentTable rows={data} /> : <Loading />}
    </div>
  );
}

