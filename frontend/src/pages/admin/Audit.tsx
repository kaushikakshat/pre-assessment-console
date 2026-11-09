import { useEffect, useState } from 'react';
import { DataTable, Drawer, KeyValue, LoadError, Loading, Select, TbdMarker, TextField, type Column } from '../../components';
import { formatIST } from '../../lib/format';
import { useLoad } from '../../lib/useLoad';
import type { AuditEvent } from '../../lib/types';
import { AREAS, OutcomeBadge } from './common';

export function Audit() {
  const [f, setF] = useState({ q: '', area: '', actor: '', outcome: '' });
  const [applied, setApplied] = useState(f);
  const [open, setOpen] = useState<AuditEvent | null>(null);
  useEffect(() => { const t = setTimeout(() => setApplied(f), 300); return () => clearTimeout(t); }, [f]);
  const qs = new URLSearchParams(Object.entries(applied).filter(([, v]) => v.trim() !== '').map(([k, v]) => [k, v.trim()])).toString();
  const { data, error, reload } = useLoad<AuditEvent[]>(`/admin/audit?${qs}`);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  const cols: Column<AuditEvent>[] = [
    { key: 'at', header: 'When', render: (e) => formatIST(e.at) },
    { key: 'who', header: 'Actor', render: (e) => e.actor },
    { key: 'area', header: 'Area', render: (e) => AREAS[e.area] ?? e.area },
    { key: 'act', header: 'Action', render: (e) => <button type="button" className="link-btn" onClick={() => setOpen(e)}>{e.action}</button> },
    { key: 'obj', header: 'Object', mono: true, render: (e) => e.object },
    { key: 'out', header: 'Outcome', render: (e) => <OutcomeBadge outcome={e.outcome} /> },
  ];
  const csv = (
    <a className="btn btn-secondary btn-md" href={`/api/admin/audit.csv${qs ? `?${qs}` : ''}`}>Export CSV ({data?.length ?? 0})</a>
  );
  return (
    <div className="stack-lg">
      <div className="page-head"><h1>Audit Logs</h1>{csv}</div>
      <div className="f4">
        <TextField id="aq" label="Search" type="search" value={f.q} onChange={set('q')} />
        <Select id="aarea" label="Area" value={f.area} onChange={set('area')}>
          <option value="">All areas</option>
          {Object.entries(AREAS).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </Select>
        <TextField id="aactor" label="Actor" value={f.actor} onChange={set('actor')} />
        <Select id="aout" label="Outcome" value={f.outcome} onChange={set('outcome')}>
          <option value="">All outcomes</option><option value="success">Success</option><option value="blocked">Blocked</option><option value="failure">Failed</option>
        </Select>
      </div>
      {error && !data && <LoadError error={error} thing="the audit log" onRetry={reload} />}
      {!data && !error && <Loading />}
      {data && <DataTable caption="Audit events" columns={cols} rows={data} rowKey={(e) => e.id} empty={{ title: 'No events match', text: 'Try different filters.' }} />}
      <p className="muted">Events cannot be edited or deleted here. Secrets, passwords and tokens are never logged.</p>
      <Drawer open={!!open} title={open?.action ?? ''} badges={open && <OutcomeBadge outcome={open.outcome} />} onClose={() => setOpen(null)}
        footer={<span className="muted">Audit events are read-only.</span>}>
        {open && <KeyValue items={[
          { label: 'Timestamp', value: formatIST(open.at) },
          { label: 'Actor', value: open.actor },
          { label: 'Area', value: AREAS[open.area] ?? open.area },
          { label: 'Object', value: open.object, mono: true },
          { label: 'Policy version', value: open.policy_version ?? '—', mono: true },
          { label: 'Scanner version', value: <TbdMarker label="Scanner version" od={13} /> },
          { label: 'Detail', value: open.detail || '—' },
        ]} />}
      </Drawer>
    </div>
  );
}
