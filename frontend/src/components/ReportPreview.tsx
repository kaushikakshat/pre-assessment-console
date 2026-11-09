import { Card, EvidenceBlock, KeyValue, TbdMarker, Timeline } from './Card';
import { LocationList } from './Scan';
import { DataTable, type Column } from './DataTable';
import { ConfidenceTag, SeverityBadge, StatusBadge } from './Badges';
import { SEVERITIES, type ReportModel, type ReportOverviewRow } from '../lib/types';

const str = (v: unknown) => (v === null || v === undefined || v === '' ? '—' : typeof v === 'object' ? JSON.stringify(v) : String(v));
const label = (k: string) => { const t = k.replace(/_/g, ' '); return t[0].toUpperCase() + t.slice(1); };

/** DESIGN_SYSTEM §6.30. Renders the stored model as is; the same JSON drives the PDF. Absent sections are skipped. */
export function ReportPreview({ model: m }: { model: ReportModel }) {
  const t = m.title;
  const overview = m.findings_overview ?? [];
  const cols: Column<ReportOverviewRow>[] = [
    { key: 'n', header: '#', render: (r) => str(r.n) },
    { key: 'sev', header: 'Severity', render: (r) => <SeverityBadge severity={r.severity} compact /> },
    { key: 'title', header: 'Finding', render: (r) => str(r.title) },
    { key: 'loc', header: 'Location', mono: true, render: (r) => str(r.location) },
    { key: 'conf', header: 'Confidence', render: (r) => <ConfidenceTag confidence={r.confidence} /> },
    { key: 'state', header: 'State', render: (r) => <StatusBadge kind="finding" status={r.state} /> },
  ];
  return (
    <article className="stack-lg" aria-label="Report preview">
      {m.header && <div className="page-head"><b>{m.header.product}</b><TbdMarker label="TBD" od={8} title={`Classification: ${m.header.classification}`} /></div>}
      {t && (
        <div className="stack">
          <h2 className="report-title">{t.assessment}</h2>
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
      {m.summary && (
        <Card title="Findings by severity">
          <p className="chips">
            {SEVERITIES.map((v) => <span key={v} className="chip"><SeverityBadge severity={v} compact /> {m.summary!.by_severity?.[v] ?? 0}</span>)}
          </p>
          <p><b>{m.summary.total} total</b> · {m.summary.still_open} still open</p>
        </Card>
      )}
      {m.findings_overview && <><h2>Findings and where they are</h2><DataTable caption="Findings overview" columns={cols} rows={overview} rowKey={(r) => String(r.n)} empty={{ title: 'No findings' }} /></>}
      {m.details && <h2>Finding details</h2>}
      {m.details?.map((d) => (
        <Card key={d.id} title={<><span className="mono">{d.id}</span> <SeverityBadge severity={d.severity} compact /> <ConfidenceTag confidence={d.confidence} /> <StatusBadge kind="finding" status={d.state} /> {d.title}</>}>
          <div className="stack">
            <LocationList location={d.location} />
            <section><h3>Description</h3><p className="prewrap">{d.description}</p></section>
            <section><h3>Impact</h3><p className="prewrap">{d.impact}</p></section>
            <section><h3>Evidence</h3><EvidenceBlock text={d.evidence} /></section>
            <section><h3>How to reproduce</h3><p className="prewrap">{d.reproduce}</p></section>
            <section><h3>Remediation</h3><p className="prewrap">{d.remediation}</p>
              <span className="chips">{d.references?.filter((r) => /^https?:\/\//i.test(r)).map((r) => <a key={r} className="chip" href={r} target="_blank" rel="noreferrer noopener">{r}</a>)}</span>
            </section>
            <section><h3>History</h3><Timeline rows={(d.history ?? []).map((h) => ({ at: h.at, text: h.text }))} empty="No changes yet." /></section>
          </div>
        </Card>
      ))}
      {m.limitations && <Card title="Limitations"><p>{m.limitations}</p></Card>}
    </article>
  );
}
