// Scan-flow display components: ProfileCard, Stepper, ValidationResult, ModuleProgress, CapacityMeter, SeverityBar, LocationList.
import type { ReactNode } from 'react';
import { Icon } from './Icon';
import { StatusBadge } from './Badges';
import { SeverityGlyph } from './Icon';
import { KeyValue } from './Card';
import { formatIST } from '../lib/format';
import { VOCAB, VALIDATION_HEADING, SKIPPED_CHECK_DETAIL, SEVERITY, PROFILE_NAMES } from '../lib/status';
import { CHECK_KEYS, SEVERITIES, type Capacity, type Job, type Location, type ModuleKey, type ProfileInfo, type Severity, type Validation } from '../lib/types';

export function ProfileGrid({ label, children }: { label: string; children: ReactNode }) {
  return <div role="radiogroup" aria-label={label} className="profile-grid">{children}</div>;
}

export function ProfileCard({ profile, name, selected, onSelect, disabledModules = [] }: {
  profile: ProfileInfo; name: string; selected: boolean; onSelect: () => void; disabledModules?: ModuleKey[];
}) {
  const off = !profile.available;
  return (
    <label className={`profile${selected ? ' selected' : ''}${off ? ' disabled' : ''}`}>
      <input type="radio" name={name} checked={selected} disabled={off} onChange={onSelect} />
      <span className="profile-name">{profile.name}</span>
      <span>{off ? 'Not available in this release.' : profile.description}</span>
      <span className="profile-meta">Duration <b>{profile.duration}</b> · Impact <b>{profile.impact}</b></span>
      <span className="chips">
        {profile.modules.map((m) => (
          <span key={m} className={`mono chip${disabledModules.includes(m) ? ' struck' : ''}`}>{m}</span>
        ))}
      </span>
    </label>
  );
}

export function Stepper({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="stepper">
      {steps.map((s, i) => {
        const state = i < current ? 'done' : i === current ? 'current' : 'todo';
        return (
          <li key={s} className={`step ${state}`} aria-current={state === 'current' ? 'step' : undefined}>
            <span className="step-dot">{state === 'done' ? <Icon name="check" size={12} /> : i + 1}</span>
            {s}
          </li>
        );
      })}
    </ol>
  );
}

export function ValidationResult({ validation }: { validation: Validation }) {
  const head = VOCAB.validation[validation.outcome];
  const sorted = [...validation.checks].sort((a, b) => CHECK_KEYS.indexOf(a.key) - CHECK_KEYS.indexOf(b.key));
  let failed = false;
  const checks = sorted.map((c) => {
    const result = failed ? 'skip' : c.result;
    if (c.result === 'fail') failed = true;
    return { ...c, result, detail: result === 'skip' && c.result !== 'skip' ? SKIPPED_CHECK_DETAIL : c.detail };
  });
  return (
    <section className="card validation" aria-live="polite">
      <header className={`validation-head tone-${head.tone}`}>
        <Icon name={head.icon} />
        <h2>{VALIDATION_HEADING[validation.outcome]}</h2>
      </header>
      <ul className="checks">
        {checks.map((c) => {
          const def = VOCAB.check[c.result];
          return (
            <li key={c.key}>
              <span className={`tone-text-${def.tone}`}><Icon name={def.icon} /></span>
              <span>{c.label}<span className="sr-only">: {def.label}</span></span>
              <span className="muted">{c.detail}</span>
            </li>
          );
        })}
      </ul>
      <footer className="validation-foot">
        <span className="mono">{validation.normalized_target}</span>
        <span className="muted">Decision recorded · policy {validation.policy_version} · {formatIST(validation.decided_at)}</span>
      </footer>
    </section>
  );
}

const FINISHED = (s: string) => s !== 'queued' && s !== 'running';
const SEG: Record<string, string> = { completed: 'ok', running: 'run', interrupted: 'warn', inconclusive: 'warn', cancelled: 'warn' };

export function ModuleProgress({ job, compact }: { job: Job; compact?: boolean }) {
  const done = job.modules.filter((m) => FINISHED(m.state)).length;
  const summary = `${done} of ${job.modules.length} modules finished`;
  if (compact) {
    return (
      <div className="segments" role="img" aria-label={`${job.id}: ${summary}`}>
        {job.modules.map((m) => <span key={m.key} className={`seg seg-${SEG[m.state] ?? 'none'}`} title={`${m.name}: ${VOCAB.module[m.state].label}`} />)}
      </div>
    );
  }
  return (
    <section className="card">
      <header className="card-head">
        <h2 className="mono">{job.id} · {job.profile ? PROFILE_NAMES[job.profile] : 'Individual modules'}</h2>
        <span role="status" className="muted">{summary}</span>
      </header>
      <ol className="modules">
        {job.modules.map((m) => (
          <li key={m.key} className={m.state === 'running' ? 'running' : undefined}>
            <span>
              {m.name}
              {m.detail && <small className="muted">{m.detail}</small>}
            </span>
            <StatusBadge kind="module" status={m.state} />
          </li>
        ))}
      </ol>
    </section>
  );
}

export function CapacityMeter({ capacity: c }: { capacity: Capacity }) {
  const pips = Array.from({ length: c.ceiling }, (_, i) => (i < c.active ? 'on' : i < c.limit ? 'free' : 'off'));
  return (
    <div className="capacity">
      <div className="capacity-line">
        <span className="caption">Global capacity</span>
        <span className="pips" aria-hidden="true">{pips.map((p, i) => <span key={i} className={`pip pip-${p}`} />)}</span>
        <span><b>{c.active} / {c.limit} active</b></span>
        <span className="muted">{c.queued} queued · {c.healthy_workers} healthy {c.healthy_workers === 1 ? 'worker' : 'workers'}</span>
      </div>
      {c.healthy_workers < c.limit && (
        <p className="tone-text-danger"><b>Effective capacity reduced to {c.healthy_workers}: not enough healthy workers. Administrators have been alerted.</b></p>
      )}
    </div>
  );
}

export function SeverityBar({ counts }: { counts: Record<Severity, number> }) {
  const label = SEVERITIES.map((s) => `${counts[s]} ${SEVERITY[s].label}`).join(', ');
  return (
    <div>
      <div className="sevbar" role="img" aria-label={`Findings by severity: ${label}`}>
        {SEVERITIES.filter((s) => counts[s] > 0).map((s) => <span key={s} className={`sevseg sev-${s}`} style={{ flex: counts[s] }} />)}
      </div>
      <ul className="sevlegend">
        {SEVERITIES.map((s) => (
          <li key={s} className={`sev-text-${s}`}>
            <SeverityGlyph bars={SEVERITY[s].bars} /> <b>{counts[s]}</b> <span className="muted">{SEVERITY[s].label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function LocationList({ location: l, module, foundBy, firstSeen, lastSeen, latestRetest }: {
  location: Location; module?: string; foundBy?: string; firstSeen?: string; lastSeen?: string; latestRetest?: string;
}) {
  const rows: { label: string; value: ReactNode; mono?: boolean }[] = [
    { label: 'Location', value: l.component ?? l.url, mono: true },
    { label: 'Type', value: l.kind },
    { label: 'Host · port', value: `${l.host} · ${l.port}`, mono: true },
    ...(l.path ? [{ label: 'Path', value: l.path, mono: true }] : []),
    ...(l.param ? [{ label: 'Parameter', value: l.param, mono: true }] : []),
    ...(l.method ? [{ label: 'HTTP method', value: l.method }] : []),
    ...(module ? [{ label: 'Module', value: module }] : []),
    ...(foundBy ? [{ label: 'Found by', value: foundBy, mono: true }] : []),
    ...(firstSeen ? [{ label: 'First seen', value: formatIST(firstSeen) }] : []),
    ...(lastSeen ? [{ label: 'Last seen', value: formatIST(lastSeen) }] : []),
    ...(latestRetest ? [{ label: 'Latest retest', value: latestRetest }] : []),
  ];
  return <KeyValue items={rows} />;
}
