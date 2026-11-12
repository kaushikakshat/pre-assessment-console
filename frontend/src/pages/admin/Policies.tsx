import { useState } from 'react';
import { api } from '../../lib/api';
import { useLoad } from '../../lib/useLoad';
import { Banner, Button, Card, Checkbox, ConfirmDialog, DataTable, Icon, LoadError, Loading, Modal, Select, Stepper, Tabs, TbdMarker, TextField, Textarea, type Column } from '../../components';
import { useAct } from './common';
import { MATCH_LABEL, OUTCOME_LABEL, nextRuleId, stageIndex, type Check, type Draft, type DryRow, type Match, type Outcome, type PolicyDoc, type Rule, type VersionInfo } from './policyTypes';

interface Loaded { published: VersionInfo; draft: Draft | null; invariants: string[] }
const BASE = '/admin/policies/draft';
const STEPS = ['Draft', 'Validated', 'Dry run', 'Published'];
const HINT: Record<Match, string> = {
  suffix: 'A hostname ending, such as example.com. Matches the host and its subdomains.', domain: 'One exact hostname, such as app.example.com.',
  ip: 'One address, such as 203.0.113.7.', cidr: 'A range such as 203.0.113.0/24.', env: 'Development, Staging, UAT or Production.',
};
const PRIVATE_OK: Match[] = ['suffix', 'domain', 'ip', 'cidr'];
const OUTCOME_TONE = { allow: 'ok', approval: 'warn', deny: 'danger' } as const;
const Outcomes = ({ v }: { v: string }) => <span className={`badge tone-${OUTCOME_TONE[v as Outcome] ?? 'neutral'}`}>{OUTCOME_LABEL[v] ?? v}</span>;

export function Policies() {
  const { data, error, reload } = useLoad<Loaded>('/admin/policies');
  const act = useAct();
  const [confirm, setConfirm] = useState<'publish' | 'discard' | null>(null);
  if (error && !data) return <LoadError error={error} thing="target policies" onRetry={reload} />;
  if (!data) return <Loading />;
  const { published, draft, invariants } = data;

  const run = async (fn: () => Promise<unknown>, ok: string) => { if (await act.run(fn, ok)) reload(); };
  const failed = act.failure && (
    <Banner tone="danger" title="Not saved" action={act.error?.status === 409 && <Button size="sm" onClick={() => { act.clear(); reload(); }}>Reload</Button>}>
      {act.failure}
      {act.error?.errors && <ul>{act.error.errors.map((e) => <li key={e}>{e}</li>)}</ul>}
    </Banner>
  );

  if (!draft) {
    return (
      <div className="stack-lg">
        <h1>Target Policies</h1>
        {failed}
        <Banner tone="info" action={<Button variant="primary" busy={act.busy} onClick={() => run(() => api(BASE, { method: 'POST', body: {} }), 'Draft started.')}>Start new draft</Button>}>
          {`Published policy ${published.version} is in force. Start a draft to change it; nothing changes until you publish.`}
        </Banner>
        <Card title={`Published rules (${published.version})`} flush><RulesTable rules={published.document.rules} /></Card>
        <Invariants items={invariants} />
      </div>
    );
  }

  const save = (document: PolicyDoc, note: string) => run(() => api(BASE, { method: 'PUT', body: { document, note, rev: draft.rev } }), 'Draft saved.');
  const dry = draft.dry_run;
  return (
    <div className="stack-lg">
      <h1>Target Policies</h1>
      <Stepper steps={STEPS} current={stageIndex(draft, false)} />
      {failed}
      <div className="grid2">
        <Tabs tabs={[{ key: 'visual', label: 'Visual rules' }, { key: 'json', label: 'Structured config' }]}>
          {(tab) => tab === 'visual'
            ? <Visual key={draft.rev} draft={draft} busy={act.busy} save={save} />
            : <Structured key={draft.rev} draft={draft} onApplied={reload} />}
        </Tabs>
        <div className="stack-lg">
          <Card title="Next step">
            <div className="stack">
              {draft.checks && <ul className="checks">{draft.checks.map((c) => <CheckItem key={c.key} c={c} />)}</ul>}
              {draft.stage === 'draft' && <Button variant="primary" busy={act.busy} onClick={() => run(() => api(`${BASE}/validate`, { method: 'POST' }), 'Draft validated.')}>Validate draft</Button>}
              {draft.stage === 'validated' && <Button variant="primary" busy={act.busy} onClick={() => run(() => api(`${BASE}/dry-run`, { method: 'POST' }), 'Dry run complete.')}>Run dry run</Button>}
              {draft.stage === 'dry-run' && <Button variant="primary" busy={act.busy} onClick={() => { act.clear(); setConfirm('publish'); }}>{`Publish ${draft.version}`}</Button>}
              <Button variant="danger-outline" onClick={() => { act.clear(); setConfirm('discard'); }}>Discard draft</Button>
            </div>
          </Card>
          <Invariants items={invariants} />
        </div>
      </div>
      {dry && <Card title="Dry run" flush><DryTable rows={dry.rows} /></Card>}
      <ConfirmDialog open={confirm === 'publish'} title={`Publish ${draft.version}?`} cancelLabel="Keep draft" confirmLabel={`Publish ${draft.version}`} busy={act.busy}
        onCancel={() => setConfirm(null)}
        onConfirm={async () => {
          const ok = await act.run(() => api<{ version: string; changed: number; reset: number; jobs_cancelled: number }>(`${BASE}/publish`, { method: 'POST', body: { rev: draft.rev } }),
            (r) => `${r.version} published. ${r.changed} targets changed, ${r.reset} reset, ${r.jobs_cancelled} queued scans cancelled.`);
          setConfirm(null); if (ok) reload();
        }}>
        {`${dry?.changed ?? 0} targets change outcome. ${dry?.resets ?? 0} will need to be validated again and their queued scans cancelled. Running scans continue.`}
      </ConfirmDialog>
      <ConfirmDialog open={confirm === 'discard'} tone="danger" title={`Discard draft ${draft.version}?`} cancelLabel="Keep draft" confirmLabel="Discard draft" busy={act.busy}
        onCancel={() => setConfirm(null)}
        onConfirm={async () => { const ok = await act.run(() => api(BASE, { method: 'DELETE' }), 'Draft discarded.'); setConfirm(null); if (ok) reload(); }}>
        {`Discard draft ${draft.version}? Your changes are lost. The published policy is not affected.`}
      </ConfirmDialog>
    </div>
  );
}

const CheckItem = ({ c }: { c: Check }) => (
  <li><Icon name={c.result === 'pass' ? 'check' : c.result === 'warn' ? 'warn' : 'x'} size={16} /><span>{c.label}</span><span className="muted">{c.detail}</span></li>
);

function Invariants({ items }: { items: string[] }) {
  return <Card title="Safety invariants"><ul>{items.map((i) => <li key={i}>{i}</li>)}</ul></Card>;
}

function DryTable({ rows }: { rows: DryRow[] }) {
  const cols: Column<DryRow>[] = [
    { key: 'n', header: 'Assessment', render: (r) => <><b>{r.name}</b><div className="muted">{r.owner}</div></> },
    { key: 't', header: 'Target', mono: true, render: (r) => r.target },
    { key: 'e', header: 'Environment', render: (r) => r.env },
    { key: 'p', header: 'Published', render: (r) => <Outcomes v={r.published} /> },
    { key: 'd', header: 'Draft', render: (r) => <Outcomes v={r.draft} /> },
    { key: 's', header: 'Effect', render: (r) => (r.reset ? 'Needs validation again' : r.changed ? 'Changes' : 'No change') },
  ];
  return <DataTable caption="Dry run results" columns={cols} rows={rows} rowKey={(r) => r.assessment} rowClass={(r) => (r.changed ? 'row-changed' : '')} empty={{ title: 'No assessments to check' }} />;
}

interface RulesActions { onMove: (i: number, by: -1 | 1) => void; onEdit: (r: Rule) => void; onRemove: (r: Rule) => void }
function RulesTable({ rules, actions }: { rules: Rule[]; actions?: RulesActions }) {
  const cols: Column<Rule>[] = [
    { key: 'id', header: 'ID', mono: true, render: (r) => r.id },
    { key: 'o', header: 'Outcome', render: (r) => <Outcomes v={r.outcome} /> },
    { key: 'm', header: 'Match', render: (r) => MATCH_LABEL[r.match] },
    { key: 'v', header: 'Value', mono: true, render: (r) => r.value },
    { key: 'n', header: 'Note', render: (r) => r.note },
    { key: 't', header: 'Tags', render: (r) => <>{r.dev_only && <span className="tag">Dev only</span>}{r.internal && <span className="tag">Private allowed</span>}</> },
  ];
  if (actions) {
    cols.push({ key: 'x', header: <span className="sr-only">Actions</span>, render: (r) => {
      const i = rules.indexOf(r);
      return (
        <span className="badge-row">
          <Button size="sm" aria-label={`Move up ${r.id}`} disabled={i === 0} onClick={() => actions.onMove(i, -1)}>Move up</Button>
          <Button size="sm" aria-label={`Move down ${r.id}`} disabled={i === rules.length - 1} onClick={() => actions.onMove(i, 1)}>Move down</Button>
          <Button size="sm" aria-label={`Edit ${r.id}`} onClick={() => actions.onEdit(r)}>Edit</Button>
          <Button size="sm" variant="danger-outline" aria-label={`Remove ${r.id}`} onClick={() => actions.onRemove(r)}>Remove</Button>
        </span>
      );
    } });
  }
  return <DataTable caption="Rules, first match wins" columns={cols} rows={rules} rowKey={(r) => r.id} empty={{ title: 'No rules', text: 'Without rules, every target follows the "no rule matches" outcome.' }} />;
}

function Visual({ draft, busy, save }: { draft: Draft; busy: boolean; save: (d: PolicyDoc, note: string) => void }) {
  const [ports, setPorts] = useState(draft.document.permitted_ports.join(', '));
  const [noMatch, setNoMatch] = useState<Outcome>(draft.document.no_match);
  const [note, setNote] = useState(draft.note);
  const [editing, setEditing] = useState<Rule | 'new' | null>(null);
  const rules = draft.document.rules;
  const put = (next: Rule[]) => save({ rules: next, permitted_ports: ports.split(',').map((p) => p.trim()).filter(Boolean).map(Number), no_match: noMatch }, note);
  const actions: RulesActions = {
    onMove: (i, by) => { const n = [...rules]; [n[i], n[i + by]] = [n[i + by], n[i]]; put(n); },
    onEdit: setEditing,
    onRemove: (r) => put(rules.filter((x) => x.id !== r.id)),
  };
  return (
    <div className="stack">
      <Card title="Rules" action={<Button size="sm" variant="primary" onClick={() => setEditing('new')}>Add rule</Button>} flush>
        <RulesTable rules={rules} actions={actions} />
      </Card>
      <p className="muted">Rules are checked in order and the first match wins.</p>
      <TextField id="ports" label="Permitted ports" hint="Comma-separated, such as 80, 443." value={ports} onChange={(e) => setPorts(e.target.value)} />
      <Select id="nomatch" label="When no rule matches" value={noMatch} onChange={(e) => setNoMatch(e.target.value as Outcome)}>
        {Object.entries(OUTCOME_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
      </Select>
      <TbdMarker label="No-match default" od={18} />
      <Textarea id="note" label="Change note" maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} />
      <div><Button variant="primary" busy={busy} onClick={() => put(rules)}>Save draft</Button></div>
      {editing && (
        <RuleModal key={editing === 'new' ? 'new' : editing.id} rule={editing === 'new' ? { id: nextRuleId(rules), outcome: 'approval', match: 'suffix', value: '', note: '' } : editing} isNew={editing === 'new'}
          onClose={() => setEditing(null)}
          onSave={(r) => { setEditing(null); put(editing === 'new' ? [...rules, r] : rules.map((x) => (x.id === r.id ? r : x))); }} />
      )}
    </div>
  );
}

function RuleModal({ rule, isNew, onClose, onSave }: { rule: Rule; isNew: boolean; onClose: () => void; onSave: (r: Rule) => void }) {
  const [r, setR] = useState(rule);
  const set = (p: Partial<Rule>) => setR((x) => ({ ...x, ...p }));
  const privateOk = r.outcome === 'allow' && PRIVATE_OK.includes(r.match);
  const submit = () => {
    const { internal, ...rest } = r;
    const out: Rule = { ...rest, value: r.value.trim() };
    if (privateOk && internal) out.internal = true;
    if (!r.dev_only) delete out.dev_only;
    onSave(out);
  };
  return (
    <Modal open title={isNew ? 'Add rule' : `Edit ${r.id}`} onClose={onClose}
      footer={<><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!r.value.trim()} onClick={submit}>{isNew ? 'Add rule' : 'Save rule'}</Button></>}>
      <div className="stack">
        <Select id="r-outcome" label="Outcome" value={r.outcome} onChange={(e) => set({ outcome: e.target.value as Outcome })}>
          {Object.entries(OUTCOME_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </Select>
        <Select id="r-match" label="Match type" value={r.match} onChange={(e) => set({ match: e.target.value as Match })}>
          {(Object.keys(MATCH_LABEL) as Match[]).map((k) => <option key={k} value={k}>{MATCH_LABEL[k]}</option>)}
        </Select>
        <TextField id="r-value" label="Value" required mono hint={HINT[r.match]} value={r.value} onChange={(e) => set({ value: e.target.value })} />
        <TextField id="r-note" label="Note" value={r.note} onChange={(e) => set({ note: e.target.value })} />
        {privateOk && <Checkbox label="Allow private addresses" checked={!!r.internal} onChange={(e) => set({ internal: e.target.checked })} />}
        <Checkbox label="Dev only" checked={!!r.dev_only} onChange={(e) => set({ dev_only: e.target.checked })} />
      </div>
    </Modal>
  );
}

function Structured({ draft, onApplied }: { draft: Draft; onApplied: () => void }) {
  const [text, setText] = useState(JSON.stringify(draft.document, null, 2));
  const act = useAct();
  const errors = act.error?.errors ?? (act.failure ? [act.failure] : []);
  const apply = async () => { if (await act.run(() => api(`${BASE}/import`, { method: 'POST', body: { text, rev: draft.rev } }), 'Draft updated.')) onApplied(); };
  return (
    <div className="stack">
      <Textarea id="json" label="Policy document (JSON)" mono rows={18} value={text} onChange={(e) => setText(e.target.value)} />
      {errors.length > 0 && <ul className="field-error" role="alert">{errors.map((e) => <li key={e}>{e}</li>)}</ul>}
      <div><Button variant="primary" busy={act.busy} onClick={apply}>Validate &amp; apply to draft</Button></div>
    </div>
  );
}
