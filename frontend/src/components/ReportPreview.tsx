import { Card, KeyValue, TbdMarker } from './Card';
import { DataTable, type Column } from './DataTable';
import { SeverityBadge, StatusBadge } from './Badges';
import type { ReportModel, Severity } from '../lib/types';

const str = (v: unknown) => (v === null || v === undefined || v === '' ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v));
const label = (k: string) => { const t = k.replace(/_/g, ' '); return t[0].toUpperCase() + t.slice(1); };
type Row = Record<string, unknown>;

/** DESIGN_SYSTEM §6.30. Renders the stored model as is; the same JSON drives the PDF. Absent sections are skipped. */
export function ReportPreview({ model: m }: { model: ReportModel }) {
  const t = m.title;
  const overview = m.findings_overview ?? [];
  const cols: Column<Row>[] = [
    { key: 'n', header: '#', render: (r) => str(r.n ?? r.id) },
    { key: 'sev', header: 'Severity', render: (r) => <SeverityBadge severity={r.severity as Severity} compact /> },
    { key: 'title', header: 'Finding', render: (r) => str(r.title) },
    { key: 'loc', header: 'Location', mono: true, render: (r) => str(r.location ?? r.asset) },
    { key: 'conf', header: 'Confidence', render: (r) => str(r.confidence) },
    { key: 'state', header: 'State', render: (r) => <StatusBadge kind="finding" status={String(r.state)} /> },
  ];
  return (
    <article className="stack-lg" aria-label="Report preview">
      {m.header && <div className="page-head"><b>{m.header.product}</b><TbdMarker label="TBD" od={8} title={`Classification: ${m.header.classification}`} /></div>}
      {t && (
        <div className="stack">
          <h2 style={{ fontSize: 26 }}>{t.assessment}</h2>
          <div className="sub"><span>{t.type}</span><span className="mono">{t.report_id}</span><span>v{t.version}</span><span>{t.generated_at}</span><span>{t.by}</span></div>
        </div>
      )}
      {m.watermark && <div role="note" style={{ border: '2px solid var(--warn)', color: 'var(--warn)', padding: 'var(--space-4)', fontWeight: 600 }}>{m.watermark}</div>}
      {m.scope && <Card title="Scope"><KeyValue items={Object.entries(m.scope).map(([k, v]) => ({ label: label(k), value: str(v) }))} /></Card>}
      {m.categories && (
        <DataTable caption="Result categories" rows={m.categories} rowKey={(c) => c.key} empty={{ title: 'No categories' }}
          columns={[{ key: 'l', header: 'Result category', render: (c) => c.label }, { key: 'c', header: 'Count', align: 'right', render: (c) => c.count }]} />
      )}
      {m.modules && (
        <DataTable caption="Modules" rows={m.modules} rowKey={(x) => x.key} empty={{ title: 'No modules' }}
          columns={[
            { key: 'n', header: 'Module', render: (x) => x.name },
            { key: 's', header: 'Outcome', render: (x) => <StatusBadge kind="module" status={x.state} /> },
            { key: 'd', header: 'Note', render: (x) => <>{str(x.detail)}{!!x.untested && <small className="muted"> · {x.untested} not tested</small>}</> },
          ]} />
      )}
      {m.summary !== undefined && (
        <Card title="Summary">
          {typeof m.summary === 'object' && m.summary ? <KeyValue items={Object.entries(m.summary).map(([k, v]) => ({ label: label(k), value: str(v) }))} /> : <p>{str(m.summary)}</p>}
        </Card>
      )}
      {m.findings_overview && <><h2>Findings and where they are</h2><DataTable caption="Findings overview" columns={cols} rows={overview} rowKey={(r) => str(r.n ?? r.id)} empty={{ title: 'No findings' }} /></>}
      {m.details?.map((d, i) => (
        <Card key={i} title={<>{d.severity ? <SeverityBadge severity={d.severity as Severity} compact /> : null} {str(d.title)}</>}>
          <KeyValue items={['location', 'description', 'impact', 'evidence', 'reproduce', 'remediation'].filter((k) => d[k] !== undefined).map((k) => ({ label: label(k), value: str(d[k]) }))} />
        </Card>
      ))}
      {m.limitations && <Card title="Limitations"><p>{m.limitations}</p></Card>}
    </article>
  );
}
