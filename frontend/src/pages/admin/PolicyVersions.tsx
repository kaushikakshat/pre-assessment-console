import { useState } from 'react';
import { api } from '../../lib/api';
import { formatIST } from '../../lib/format';
import { useLoad } from '../../lib/useLoad';
import { Button, Card, DataTable, LoadError, Loading, ReasonConfirm, Select, type Column } from '../../components';
import { useAct } from './common';
import { MATCH_LABEL, OUTCOME_LABEL, diffPolicies, type Rule, type VersionInfo } from './policyTypes';

const describe = (r: Rule) => `${r.id}: ${OUTCOME_LABEL[r.outcome]}, ${MATCH_LABEL[r.match]} ${r.value}${r.internal ? ', internal' : ''}${r.dev_only ? ', dev only' : ''}${r.note ? ` (${r.note})` : ''}`;
const label = (v: string) => OUTCOME_LABEL[v] ?? v;

export function PolicyVersions() {
  const { data, error, reload } = useLoad<VersionInfo[]>('/admin/policies/versions');
  const act = useAct();
  const [target, setTarget] = useState<VersionInfo | null>(null);
  const [pick, setPick] = useState<[string, string] | null>(null);
  if (error && !data) return <LoadError error={error} thing="policy versions" onRetry={reload} />;
  if (!data) return <Loading />;

  const current = data.find((v) => v.status === 'published') ?? data[0];
  const [from, to] = pick ?? [data.find((v) => v !== current)?.version ?? '', current?.version ?? ''];
  const cols: Column<VersionInfo>[] = [
    { key: 'v', header: 'Version', mono: true, render: (v) => v.version },
    { key: 's', header: 'Status', render: (v) => <span className={`badge tone-${v.status === 'published' ? 'ok' : 'neutral'}`}>{v.status === 'published' ? 'Published' : 'Superseded'}</span> },
    { key: 'p', header: 'Published', render: (v) => formatIST(v.published_at) },
    { key: 'b', header: 'Published by', render: (v) => v.published_by },
    { key: 'r', header: 'Rules', render: (v) => v.rules },
    { key: 'n', header: 'Note', render: (v) => v.note },
    { key: 'u', header: 'Used by', render: (v) => v.used_by },
    { key: 'x', header: <span className="sr-only">Actions</span>, render: (v) => v.status === 'superseded' && <Button size="sm" aria-label={`Roll back to ${v.version}`} onClick={() => { act.clear(); setTarget(v); }}>Roll back to this</Button> },
  ];
  return (
    <div className="stack-lg">
      <h1>Policy Versions</h1>
      <Card flush><DataTable caption="Policy versions" columns={cols} rows={data} rowKey={(v) => v.version} empty={{ title: 'No versions yet' }} /></Card>
      <Card title="Compare versions">
        <div className="stack">
          <div className="grid2">
            <Select id="cmp-from" label="From" value={from} onChange={(e) => setPick([e.target.value, to])}>{data.map((v) => <option key={v.version} value={v.version}>{v.version}</option>)}</Select>
            <Select id="cmp-to" label="To" value={to} onChange={(e) => setPick([from, e.target.value])}>{data.map((v) => <option key={v.version} value={v.version}>{v.version}</option>)}</Select>
          </div>
          {from && to && <Compare from={from} to={to} />}
        </div>
      </Card>
      {target && (
        <ReasonConfirm open title={`Roll back to ${target.version}?`} cancelLabel="Cancel" confirmLabel="Roll back" busy={act.busy}
          onCancel={() => setTarget(null)}
          extra={act.failure && <p className="field-error" role="alert">{act.failure}</p>}
          onConfirm={async (reason) => {
            const ok = await act.run(() => api<{ version: string; changed: number; reset: number; jobs_cancelled: number }>(`/admin/policies/versions/${target.version}/rollback`, { method: 'POST', body: { reason } }),
              (r) => `${r.version} published. ${r.changed} targets changed, ${r.reset} reset, ${r.jobs_cancelled} queued scans cancelled.`);
            if (ok) { setTarget(null); reload(); }
          }}>
          {`This publishes a new version with the rules of ${target.version}. Targets that become stricter must be validated again.`}
        </ReasonConfirm>
      )}
    </div>
  );
}

function Compare({ from, to }: { from: string; to: string }) {
  const a = useLoad<VersionInfo>(`/admin/policies/versions/${from}`);
  const b = useLoad<VersionInfo>(`/admin/policies/versions/${to}`);
  if (a.error || b.error) return <LoadError error={(a.error ?? b.error)!} thing="the versions" onRetry={() => { a.reload(); b.reload(); }} />;
  if (!a.data || !b.data) return <Loading />;
  const d = diffPolicies(a.data.document, b.data.document);
  const none = !d.added.length && !d.removed.length && !d.changed.length && !d.ports.added.length && !d.ports.removed.length && !d.noMatch;
  const list = (title: string, items: string[]) => items.length > 0 && <div><h3>{title}</h3><ul>{items.map((i) => <li key={i}>{i}</li>)}</ul></div>;
  return (
    <div className="stack">
      {none && <p>No differences.</p>}
      {list('Added rules', d.added.map(describe))}
      {list('Removed rules', d.removed.map(describe))}
      {list('Changed rules', d.changed.map((c) => `${describe(c.from)} → ${describe(c.to)}`))}
      {list('Ports', [...d.ports.added.map((p) => `Added ${p}`), ...d.ports.removed.map((p) => `Removed ${p}`)])}
      {d.noMatch && <div><h3>When no rule matches</h3><p>{`${label(d.noMatch.from)} → ${label(d.noMatch.to)}`}</p></div>}
    </div>
  );
}
