import { useEffect, useState } from 'react';
import { api } from '../../lib/api';
import { Banner, Button, Card, CapacityMeter, Checkbox, DataTable, LoadError, Loading, ReasonConfirm, Select, StatusBadge, TbdMarker, TextField, Timeline, type Column } from '../../components';
import { formatIST } from '../../lib/format';
import { useLoad } from '../../lib/useLoad';
import type { AuditEvent, Capacity as Cap, Worker } from '../../lib/types';
import { useAct } from './common';

interface Config { limit: number; aging_enabled: boolean; aging_minutes: number; queue_cap: number; per_user_quota: number; paused: boolean }
interface Data { config: Config; capacity: Cap; workers: Worker[]; history: AuditEvent[] }
type Form = { limit: string; aging_enabled: boolean; aging_minutes: string; queue_cap: string; per_user_quota: string };
const toForm = (c: Config): Form => ({ limit: String(c.limit), aging_enabled: c.aging_enabled, aging_minutes: String(c.aging_minutes), queue_cap: String(c.queue_cap), per_user_quota: String(c.per_user_quota) });
const whole = (s: string) => /^\d+$/.test(s.trim()) && Number(s) >= 1;

export function CapacityPage() {
  const loaded = useLoad<Data>('/admin/capacity', () => 10000);
  const { error, reload } = loaded;
  const [override, setOverride] = useState<Data | null>(null); // PUT response, until the next poll replaces it
  const data = override ?? loaded.data;
  useEffect(() => { if (loaded.data) setOverride(null); }, [loaded.data]);
  const [form, setForm] = useState<Form | null>(null);
  const [inline, setInline] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [worker, setWorker] = useState<{ w: Worker; action: 'enable' | 'drain' } | null>(null);
  const save = useAct();
  const wact = useAct();
  // Take the server config once; later polls must not overwrite what the admin is typing.
  useEffect(() => { if (data && !form) setForm(toForm(data.config)); }, [data, form]);

  if (error && !data) return <LoadError error={error} thing="capacity settings" onRetry={reload} />;
  if (!data || !form) return <Loading />;
  const { config, capacity: cap, workers } = data;
  const set = (patch: Partial<Form>) => { setForm({ ...form, ...patch }); setInline(null); save.clear(); };
  const limit = Number(form.limit);
  const changed = JSON.stringify(form) !== JSON.stringify(toForm(config));
  const invalid = !whole(form.queue_cap) || !whole(form.per_user_quota) || (form.aging_enabled && !whole(form.aging_minutes));
  const lowering = cap.active > limit;

  const onSave = () => {
    if (limit > config.limit && limit > cap.healthy_workers) {
      const n = cap.healthy_workers;
      setInline(`Only ${n} healthy ${n === 1 ? 'worker is' : 'workers are'} available. Enable or provision more workers before raising the limit to ${limit}.`);
      return;
    }
    save.clear(); setConfirming(true);
  };
  const confirm = async (reason: string) => {
    let fresh: Data | undefined;
    const ok = await save.run(async () => { fresh = await api<Data>('/admin/capacity', { method: 'PUT', body: {
      limit, aging_enabled: form.aging_enabled, aging_minutes: Number(form.aging_minutes), queue_cap: Number(form.queue_cap), per_user_quota: Number(form.per_user_quota), reason,
    } }); }, 'Capacity configuration saved.');
    setConfirming(false);
    if (ok && fresh) { setOverride(fresh); setForm(toForm(fresh.config)); } else setInline(null); // the server refusal shows inline below the form
  };
  const doWorker = async (reason: string) => {
    const { w, action } = worker!;
    if (await wact.run(() => api(`/admin/workers/${w.id}`, { method: 'POST', body: { action, reason } }), `${w.name}: ${action === 'enable' ? 'enabled' : 'draining'}.`)) { setWorker(null); reload(); }
  };

  const enabledCount = workers.filter((w) => w.enabled).length;
  const cols: Column<Worker>[] = [
    { key: 'n', header: 'Worker', render: (w) => w.name },
    { key: 's', header: 'Status', render: (w) => <StatusBadge kind="worker" status={w.status} /> },
    { key: 'l', header: 'Last seen', render: (w) => formatIST(w.last_seen_at) },
    { key: 'j', header: 'Current job', mono: true, render: (w) => w.current_job ?? '—' },
    { key: 'x', header: <span className="sr-only">Action</span>, render: (w) => w.status === 'standby'
      ? <Button size="sm" aria-label={`Enable ${w.name}`} onClick={() => { wact.clear(); setWorker({ w, action: 'enable' }); }}>Enable</Button>
      : w.status === 'healthy' && enabledCount > 1 ? <Button size="sm" aria-label={`Drain ${w.name}`} onClick={() => { wact.clear(); setWorker({ w, action: 'drain' }); }}>Drain</Button> : null },
  ];

  return (
    <div className="stack-lg">
      <h1>Scan Capacity &amp; Scheduling</h1>
      <div className="grid2">
        <Card title="Settings">
          <div className="stack">
            <Select id="limit" label="Global concurrency limit" value={form.limit} onChange={(e) => set({ limit: e.target.value })}
              hint={`Healthy workers: ${cap.healthy_workers} · Active scans: ${cap.active} · Queued: ${cap.queued}`}>
              {Array.from({ length: Math.min(cap.ceiling, 3) }, (_, i) => <option key={i + 1} value={i + 1}>{i + 1}</option>)}
            </Select>
            <p className="muted">Ceiling 3 <TbdMarker label="Ceiling beyond 3" od={9} /></p>
            <p className="muted">Queue policy: jobs run by priority (High, Normal, Low), then in submission order.</p>
            <Checkbox label="Priority aging: waiting jobs gain priority over time" checked={form.aging_enabled} onChange={(e) => set({ aging_enabled: e.target.checked })} />
            <TextField id="aging" label="Aging interval (minutes)" type="number" min={1} disabled={!form.aging_enabled} value={form.aging_minutes} onChange={(e) => set({ aging_minutes: e.target.value })} />
            <TextField id="cap" label="Queue cap" type="number" min={1} value={form.queue_cap} onChange={(e) => set({ queue_cap: e.target.value })} hint="Most jobs allowed to wait at once." />
            <p><TbdMarker label="Queue cap value" od={10} /></p>
            <TextField id="quota" label="Per-user quota" type="number" min={1} value={form.per_user_quota} onChange={(e) => set({ per_user_quota: e.target.value })} hint="Most queued and running jobs one user can have." />
            <p className="muted">Per-profile limits <TbdMarker label="Per-profile limits" od={6} /></p>
            <Banner tone="info" title="Safe FIFO fallback">If priority aging cannot be applied, jobs run in submission order.</Banner>
            {inline && <Banner tone="danger" title="Not saved">{inline}</Banner>}
            {save.failure && !confirming && <Banner tone="danger" title="Not saved">{save.failure}</Banner>}
            <div><Button variant="primary" disabled={!changed || invalid} onClick={onSave}>Save configuration</Button></div>
          </div>
        </Card>
        <div className="stack-lg">
          <Card title="Now"><CapacityMeter capacity={cap} /></Card>
          <Card title="Worker pool" flush>
            <DataTable caption="Worker pool" columns={cols} rows={workers} rowKey={(w) => w.id} empty={{ title: 'No workers registered' }} />
          </Card>
        </div>
      </div>
      <Card title="Recent changes"><Timeline rows={data.history.map((e) => ({ at: e.at, text: `${e.actor} · ${e.action}${e.detail ? ` · ${e.detail}` : ''}` }))} empty="No changes recorded yet." /></Card>
      {confirming && (
        <ReasonConfirm open tone="primary" title={lowering ? `Lower the global limit to ${limit}?` : 'Save capacity configuration?'} cancelLabel="Keep current settings" confirmLabel="Save configuration"
          busy={save.busy} onCancel={() => setConfirming(false)} onConfirm={confirm}>
          {lowering ? `${cap.active} scans are active. They will finish normally; no new scan starts until fewer than ${limit} are active.` : 'The new settings apply to scans scheduled from now on.'}
        </ReasonConfirm>
      )}
      {worker && (
        <ReasonConfirm open title={`${worker.action === 'enable' ? 'Enable' : 'Drain'} ${worker.w.name}?`} cancelLabel="Keep as is" confirmLabel={worker.action === 'enable' ? 'Enable worker' : 'Drain worker'}
          busy={wact.busy} onCancel={() => setWorker(null)} onConfirm={doWorker} extra={wact.failure && <Banner tone="danger" title="Not saved">{wact.failure}</Banner>}>
          {worker.action === 'enable' ? 'The worker can take new scans.' : 'The worker finishes its current scan and takes no new ones.'}
        </ReasonConfirm>
      )}
    </div>
  );
}
