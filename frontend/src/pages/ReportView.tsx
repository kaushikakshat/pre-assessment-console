import { Link, useParams } from 'react-router-dom';
import { Banner, LoadError, Loading, ReportPreview } from '../components';
import { useLoad } from '../lib/useLoad';
import type { Report, ReportModel } from '../lib/types';

export function ReportView() {
  const { reportId = '' } = useParams();
  const { data, error, reload } = useLoad<Report & { model: ReportModel | null }>(`/reports/${reportId}`, (r) => (r.state === 'generating' ? 3000 : 0));
  if (error && !data) return <LoadError error={error} thing={`report ${reportId}`} onRetry={reload} />;
  if (!data) return <Loading />;
  return (
    <div className="stack-lg">
      <div className="page-head">
        <h1>Report {data.id} · v{data.version}</h1>
        <div className="stack">
          <Link to={`/assessments/${data.assessment_id}`}>Back to assessment</Link>
          {data.state === 'ready' && <a className="btn btn-primary btn-md btn-link" download href={`/api/reports/${data.id}/pdf`}>Export PDF</a>}
        </div>
      </div>
      {data.state === 'generating' && <Banner tone="info" title="Generating">The report is being prepared. This page updates when it is ready.</Banner>}
      {data.state === 'failed' && <Banner tone="danger" title="Report generation failed — your assessment results are unchanged">Retry it from the Reports tab.</Banner>}
      {data.model && <ReportPreview model={data.model} />}
    </div>
  );
}
