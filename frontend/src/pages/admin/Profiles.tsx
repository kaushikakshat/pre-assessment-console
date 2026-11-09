import { useState } from 'react';
import { api } from '../../lib/api';
import { Banner, Button, Card, DataTable, LoadError, Loading, ReasonConfirm, StatusBadge, TbdMarker, type Column } from '../../components';
import { useLoad } from '../../lib/useLoad';
import type { ModuleInfo, ProfileInfo } from '../../lib/types';
import { useAct } from './common';
import type { Limits } from './Capacity';

interface Catalog { profiles: ProfileInfo[]; modules: ModuleInfo[]; limits?: Limits }
interface Wordlist { key: string; category: string; label: string; lines: number; enabled: boolean }

export function Profiles() {
  const cat = useLoad<Catalog>('/catalog');
  const caps = useLoad<{ config: { profile_limits?: Limits } }>('/admin/capacity');
  const words = useLoad<Wordlist[]>('/admin/wordlists');
  const [target, setTarget] = useState<Wordlist | null>(null);
  const act = useAct();
  if (cat.error && !cat.data) return <LoadError error={cat.error} thing="profiles and modules" onRetry={cat.reload} />;
  if (words.error && !words.data) return <LoadError error={words.error} thing="wordlists" onRetry={words.reload} />;
  if (!cat.data || !words.data) return <Loading />;
  const limits = caps.data?.config.profile_limits ?? cat.data.limits;
  const { profiles, modules } = cat.data;
  const names = Object.fromEntries(modules.map((m) => [m.key, m.name]));

  const confirm = async (reason: string) => {
    const w = target!;
    if (await act.run(() => api('/admin/wordlists', { method: 'PUT', body: { key: w.key, enabled: !w.enabled, reason } }), `${w.label}: ${w.enabled ? 'disabled' : 'enabled'}.`)) { setTarget(null); words.reload(); }
  };
  const mcols: Column<ModuleInfo>[] = [
    { key: 'n', header: 'Module', render: (m) => <><b>{m.name}</b><div className="muted">{m.description}</div></> },
    { key: 'u', header: 'Used by', render: (m) => m.profiles.map((p) => profiles.find((x) => x.key === p)?.name ?? p).join(', ') },
    { key: 'v', header: 'Engine version', render: () => <TbdMarker label="Engine version" od={13} /> },
    { key: 's', header: 'Status', render: (m) => <StatusBadge kind="module" status={m.available ? 'available' : 'unavailable'} /> },
  ];
  const wcols: Column<Wordlist>[] = [
    { key: 'l', header: 'Wordlist', render: (w) => w.label },
    { key: 'c', header: 'Category', render: (w) => (w.category === 'discovery' ? 'Discovery' : 'Fuzzing') },
    { key: 'n', header: 'Lines', mono: true, render: (w) => w.lines.toLocaleString('en-IN') },
    { key: 's', header: 'Status', render: (w) => (w.enabled ? 'Enabled' : 'Disabled') },
    { key: 'x', header: <span className="sr-only">Action</span>, render: (w) => (
      <Button size="sm" aria-label={`${w.enabled ? 'Disable' : 'Enable'} ${w.label}`} onClick={() => { act.clear(); setTarget(w); }}>{w.enabled ? 'Disable' : 'Enable'}</Button>) },
  ];

  return (
    <div className="stack-lg">
      <h1>Profiles &amp; Modules</h1>
      <div className="profile-grid">
        {profiles.map((p) => {
          const l = p.key === 'pre' || p.key === 'deep' ? limits?.[p.key] : undefined;
          return (
            <Card key={p.key} title={p.name}>
              <div className="stack">
                <p>{p.description}</p>
                <div className="badge-row">{p.modules.map((m) => <span key={m} className="tag">{names[m] ?? m}</span>)}</div>
                <p className="muted">Duration: {p.duration}</p>
                {l && <p className="muted">{`Limits: ${l.budget_min} minutes · ${l.request_cap.toLocaleString('en-IN')} requests · ${l.rate_per_s} requests per second`}</p>}
              </div>
            </Card>
          );
        })}
      </div>
      <Card title="Modules" flush><DataTable caption="Modules" columns={mcols} rows={modules} rowKey={(m) => m.key} empty={{ title: 'No modules' }} /></Card>
      <Card title="Wordlists" flush><DataTable caption="Wordlists" columns={wcols} rows={words.data} rowKey={(w) => w.key} empty={{ title: 'No wordlists' }} /></Card>
      {target && (
        <ReasonConfirm open title={`${target.enabled ? 'Disable' : 'Enable'} ${target.label}?`} cancelLabel="Keep as is" confirmLabel={target.enabled ? 'Disable wordlist' : 'Enable wordlist'}
          busy={act.busy} onCancel={() => setTarget(null)} onConfirm={confirm} extra={act.failure && <Banner tone="danger" title="Not saved">{act.failure}</Banner>}>
          {target.enabled ? 'Owners can no longer select this wordlist.' : 'Owners can select this wordlist for Pre-Assessment and Deep scans.'}
        </ReasonConfirm>
      )}
    </div>
  );
}
