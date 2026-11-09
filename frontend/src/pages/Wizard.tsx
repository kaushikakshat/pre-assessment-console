import { useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { api, ApiError } from '../lib/api';
import {
  Advanced, Banner, Button, Card, CapacityMeter, Checkbox, Disclaimer, KeyValue, LoadError, Loading, OptionCard, ProfileCard, ProfileGrid,
  Select, Stepper, StatusBadge, TbdMarker, TextField, Textarea, ValidationResult,
} from '../components';
import { BLOCKED_COPY, PROFILE_NAMES } from '../lib/status';
import { useLoad } from '../lib/useLoad';
import { ENVIRONMENTS, type Assessment, type Capacity, type Environment, type Job, type ModuleInfo, type ModuleKey, type ProfileInfo, type ProfileKey, type SigninState, type Validation, type Wordlist } from '../lib/types';

interface Limits { budget_min: number; request_cap: number; rate_per_s: number }
interface Catalog { profiles: ProfileInfo[]; modules: ModuleInfo[]; limits?: { pre: Limits; deep: Limits }; advisory_as_of?: string; wordlists?: Wordlist[] }
interface Extras { lists: string[]; accounts: string[] }
const ENGINE_DOWN = 'The scanning engine is not running.';
const budgetText = (m: number) => (m >= 120 && m % 60 === 0 ? `${m / 60} hours` : `${m} minutes`);

/** Lists and accounts only apply to Pre/Deep; fuzzing lists and accounts only to Deep. Applied wherever they are read. */
export function effective(run: Run, x: Extras, wordlists: Wordlist[] = []): Extras {
  const profile = run.mode === 'profile' ? run.profile : null;
  if (profile !== 'pre' && profile !== 'deep') return { lists: [], accounts: [] };
  const lists = x.lists.filter((k) => { const w = wordlists.find((l) => l.key === k); return !!w && (profile === 'deep' || w.category === 'discovery'); });
  return { lists, accounts: profile === 'deep' ? x.accounts : [] };
}
export const estimate = (lists: string[], wordlists: Wordlist[] = []) => lists.reduce((n, k) => n + (wordlists.find((w) => w.key === k)?.lines ?? 0), 0);
interface Form { name: string; target: string; env: Environment; hosts: string; paths: string; ports: string; exclusions: string; notes: string }
type Run = { mode: 'profile'; profile: ProfileKey } | { mode: 'modules'; modules: ModuleKey[] };

const PROD_ONLY = 'Production targets can only be scanned with Quick Scan.';
const EMPTY: Form = { name: '', target: '', env: 'Development', hosts: '', paths: '/*', ports: '443', exclusions: '', notes: '' };
const STEPS = ['Target & scope', 'Scan configuration', 'Review & submit'];

export function targetError(raw: string): string | null {
  const v = raw.trim();
  if (!v) return 'Enter the target URL.';
  let u: URL;
  try { u = new URL(v); } catch { return 'Enter a full URL, for example https://app.example.com.'; }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return 'Use http or https.';
  if (u.username || u.password) return 'Remove credentials from the URL. Authenticated testing is set up in scan configuration.';
  const host = v.replace(/^[a-z]+:\/\//i, '').split(/[/?#]/)[0].split('@').pop()!.split(':')[0];
  const numeric = /^(0x[0-9a-f]+|\d+)(\.(0x[0-9a-f]+|\d+))*$/i.test(host);
  if (numeric && !/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return 'Write the host as a name or a standard IP address, for example 192.0.2.10.';
  return null;
}

const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : ([1e7, 1e3, 4e3, 8e3, 1e11].join('-').replace(/[018]/g, (c) => (Number(c) ^ (crypto.getRandomValues(new Uint8Array(1))[0] & (15 >> (Number(c) / 4)))).toString(16))));

/** Production allows Quick Scan only; applied wherever the run is read so a later env change cannot bypass it. */
const forEnv = (run: Run, env: Environment, catalog: Catalog | null): Run => {
  if (env !== 'Production') return run;
  if (run.mode === 'profile') return run.profile === 'quick' ? run : { mode: 'profile', profile: 'quick' };
  const quick = catalog?.profiles.find((p) => p.key === 'quick')?.modules ?? ['reach'];
  return { mode: 'modules', modules: run.modules.filter((m) => quick.includes(m)) };
};

const hostOf = (t: string) => { try { return new URL(t.trim()).hostname; } catch { return ''; } };
const fromAssessment = (a: Assessment): Form => ({ name: a.name, target: a.target, env: a.env, hosts: a.hosts, paths: a.paths, ports: a.ports, exclusions: a.exclusions, notes: a.notes ?? '' });

/** /assessments/new[?from=A-…] starts at step 1; /assessments/:id/scan starts at step 2 for an allowed assessment. */
export function Wizard() {
  const { id: routeId } = useParams();
  const [params] = useSearchParams();
  const from = routeId ?? params.get('from');
  const existing = useLoad<Assessment>(from ? `/assessments/${from}` : null);
  if (from && existing.error) return <LoadError error={existing.error} thing={`assessment ${from}`} onRetry={existing.reload} />;
  if (from && !existing.data) return <Loading />;
  const a = existing.data;
  if (routeId && a && a.status !== 'active') {
    return (
      <div className="stack-lg">
        <h1>New scan</h1>
        <Banner tone="warn" title="This assessment cannot be scanned yet" action={<Link className="btn btn-secondary btn-sm btn-link" to={`/assessments/${a.id}`}>Open assessment</Link>}>
          A scan needs the target to be validated as Allowed or approved by an administrator.
        </Banner>
      </div>
    );
  }
  return <WizardBody assessment={a} scanRoute={!!routeId} />;
}

function WizardBody({ assessment: initial, scanRoute }: { assessment: Assessment | null; scanRoute: boolean }) {
  const nav = useNavigate();
  const { user } = useAuth();
  const [step, setStep] = useState(scanRoute ? 1 : 0);
  const [form, setForm] = useState<Form>(initial ? fromAssessment(initial) : EMPTY);
  const [assessment, setAssessment] = useState<Assessment | null>(initial);
  const [validation, setValidation] = useState<Validation | null>(scanRoute ? initial?.validation ?? null : null);
  const [errors, setErrors] = useState<Partial<Record<keyof Form, string>>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [validating, setValidating] = useState(false);
  const [rawRun, setRun] = useState<Run>({ mode: 'profile', profile: 'quick' });
  const catalog = useLoad<Catalog>(step >= 1 ? '/catalog' : null);
  const run = forEnv(rawRun, form.env, catalog.data);
  const [extras, setExtras] = useState<Extras>({ lists: [], accounts: [] });
  const x = effective(run, extras, catalog.data?.wordlists);
  const signin = useLoad<SigninState>(assessment && step >= 1 && run.mode === 'profile' && run.profile === 'deep' ? `/assessments/${assessment.id}/signin` : null);

  const set = (k: keyof Form) => (e: { target: { value: string } }) => {
    setForm((f) => ({ ...f, [k]: e.target.value as never }));
    setValidation(null); // any edit invalidates the shown result; validating again saves and re-checks
    setFailure(null);
  };
  const required = form.name.trim() !== '' && form.target.trim() !== '' && form.hosts.trim() !== '' && !targetError(form.target);

  const validate = async () => {
    const errs: typeof errors = {};
    const te = targetError(form.target);
    if (te) errs.target = te;
    if (!form.name.trim()) errs.name = 'Enter an assessment name.';
    const hosts = form.hosts.trim() || hostOf(form.target);
    if (!hosts) errs.hosts = 'Enter at least one in-scope hostname or IP.';
    setErrors(errs);
    setFailure(null);
    if (Object.keys(errs).length) return;
    setValidating(true);
    try {
      const body = { ...form, hosts, notes: form.notes.trim() || null };
      const saved = assessment
        ? await api<Assessment>(`/assessments/${assessment.id}`, { method: 'PATCH', body })
        : await api<Assessment>('/assessments', { method: 'POST', body });
      setAssessment(saved);
      setForm((f) => ({ ...f, hosts }));
      setValidation(await api<Validation>(`/assessments/${saved.id}/validate`, { method: 'POST' }));
    } catch (e) {
      if (e instanceof ApiError && e.fields) setErrors(e.fields as typeof errors);
      else setFailure(e instanceof ApiError ? e.detail : 'Validation failed. Try again.');
    }
    setValidating(false);
  };

  const outcome = validation?.outcome;

  return (
    <div className="stack-lg">
      <h1>{scanRoute ? 'New scan' : initial ? 'Edit and revalidate' : 'New assessment'}</h1>
      <Stepper steps={STEPS} current={step} />

      {step === 0 && (
        <div className="grid2">
          <Card title="Target & scope">
            <TextField id="name" label="Assessment name" required value={form.name} onChange={set('name')} error={errors.name} />
            <TextField id="target" label="Target URL / API base URL" required mono value={form.target} onChange={set('target')} error={errors.target}
              placeholder="https://app.example.com" autoComplete="off"
              onBlur={() => { if (!form.hosts.trim()) setForm((f) => ({ ...f, hosts: hostOf(f.target) })); }} />
            <Select id="env" label="Environment" required value={form.env} onChange={set('env')} error={errors.env}>
              {ENVIRONMENTS.map((e) => <option key={e}>{e}</option>)}
            </Select>
            <TextField id="hosts" label="In-scope hostnames / IPs" required mono value={form.hosts} onChange={set('hosts')} error={errors.hosts} hint="Filled from the target if left empty." />
            <div className="f2">
              <TextField id="paths" label="In-scope paths" mono value={form.paths} onChange={set('paths')} error={errors.paths} />
              <TextField id="ports" label="Permitted ports" mono value={form.ports} onChange={set('ports')} error={errors.ports} />
            </div>
            <Textarea id="exclusions" label="Exclusions" mono value={form.exclusions} onChange={set('exclusions')} error={errors.exclusions} />
            <Textarea id="notes" label="Notes" value={form.notes} onChange={set('notes')} error={errors.notes} />
          </Card>
          <div className="stack sticky">
            <Card title="Target validation">
              <p className="muted">No scan traffic is sent until the target is validated.</p>
              <Button icon="shield" busy={validating} busyLabel="Validating…" onClick={validate}>Validate target</Button>
              {failure && <Banner tone="danger" title="Validation could not run">{failure} Check your connection, then validate again.</Banner>}
            </Card>
            {validation && <ValidationResult validation={validation} />}
            {outcome === 'allowed' && <Button variant="primary" disabled={!required} onClick={() => setStep(1)}>Continue to scan configuration</Button>}
            {outcome === 'approval' && (
              <>
                {user?.role === 'admin' && <p className="muted">As an administrator you can approve your own target from its assessment page, with a reason that is flagged in the audit log.</p>}
                <Button variant="primary" onClick={() => nav(`/assessments/${assessment!.id}`)}>Save and request approval</Button>
              </>
            )}
            {outcome === 'blocked' && (
              <>
                <Banner tone="danger">Target validation failed — no scan traffic was sent.</Banner>
                <Button onClick={() => nav(`/assessments/${assessment!.id}`)}>Save as draft</Button>
              </>
            )}
          </div>
        </div>
      )}

      {step === 1 && (
        <Configure form={form} catalog={catalog} run={run} setRun={setRun} extras={x} setExtras={setExtras} signin={signin.data} assessmentId={assessment?.id} onBack={scanRoute ? undefined : () => setStep(0)} onNext={() => setStep(2)} />
      )}

      {step === 2 && assessment && (
        <Review
          assessment={assessment} form={form} run={run} extras={x} signin={signin.data} catalog={catalog.data} policy={validation?.policy_version ?? assessment.validation?.policy_version ?? '—'}
          onBack={() => setStep(1)}
        />
      )}
    </div>
  );
}

function ScopeSummary({ form }: { form: Form }) {
  return (
    <Card title="Scope summary">
      <KeyValue items={[
        { label: 'Target', value: form.target, mono: true },
        { label: 'Environment', value: form.env },
        { label: 'Hosts', value: form.hosts, mono: true },
        { label: 'Paths', value: form.paths || '—', mono: true },
        { label: 'Ports', value: form.ports || '—', mono: true },
      ]} />
    </Card>
  );
}

function Configure({ form, catalog, run, setRun, extras, setExtras, signin, assessmentId, onBack, onNext }: {
  form: Form; catalog: { data: Catalog | null; error: ApiError | null; reload: () => void }; run: Run; setRun: (r: Run) => void;
  extras: Extras; setExtras: (x: Extras) => void; signin: SigninState | null; assessmentId?: string; onBack?: () => void; onNext: () => void;
}) {
  const c = catalog.data;
  if (catalog.error && !c) return <LoadError error={catalog.error} thing="the scan catalog" onRetry={catalog.reload} />;
  if (!c) return <Loading />;
  const prod = form.env === 'Production';
  const quickModules = c.profiles.find((p) => p.key === 'quick')?.modules ?? [];
  const selected = run.mode === 'modules' ? run.modules : [];
  const chosen = run.mode === 'profile' ? c.profiles.find((p) => p.key === run.profile) : null;
  const pd = chosen && (chosen.key === 'pre' || chosen.key === 'deep') ? chosen.key : null;
  const limit = pd ? c.limits?.[pd] : undefined;
  const need = estimate(extras.lists, c.wordlists);
  const over = !!limit && need > limit.request_cap;
  const canContinue = run.mode === 'profile' ? !!chosen?.available && !over : selected.some((m) => m !== 'reach');
  const toggleList = (k: string) => setExtras({ ...extras, lists: extras.lists.includes(k) ? extras.lists.filter((l) => l !== k) : [...extras.lists, k] });
  const toggleAccount = (id: string) => setExtras({ ...extras, accounts: extras.accounts.includes(id) ? extras.accounts.filter((a) => a !== id) : [...extras.accounts, id] });
  const toggle = (m: ModuleKey) => setRun({ mode: 'modules', modules: selected.includes(m) ? selected.filter((x) => x !== m) : [...selected, m] });
  return (
    <div className="grid2">
      <Card title="Scan configuration">
        <div className="seg-ctl" role="group" aria-label="Run type">
          <button type="button" aria-pressed={run.mode === 'profile'} onClick={() => setRun({ mode: 'profile', profile: 'quick' })}>Scan profile</button>
          <button type="button" aria-pressed={run.mode === 'modules'} onClick={() => setRun({ mode: 'modules', modules: ['reach'] })}>Individual modules</button>
        </div>
        {prod && <Banner tone="info">{PROD_ONLY}</Banner>}
        {run.mode === 'profile' ? (
          <ProfileGrid label="Scan profile">
            {c.profiles.map((p) => (
              <ProfileCard key={p.key} name="profile" profile={prod && p.key !== 'quick' ? { ...p, available: false } : p} unavailableText={prod && p.key !== 'quick' ? PROD_ONLY : p.key !== 'quick' ? ENGINE_DOWN : undefined}
                selected={run.mode === 'profile' && run.profile === p.key} onSelect={() => setRun({ mode: 'profile', profile: p.key })} />
            ))}
          </ProfileGrid>
        ) : (
          <div className="opt-grid">
            {c.modules.map((m) => {
              const locked = m.key === 'reach';
              const prodOff = prod && !quickModules.includes(m.key);
              const off = !m.available || prodOff;
              return (
                <OptionCard key={m.key} title={m.name} checked={locked || selected.includes(m.key)} disabled={locked || off}
                  description={locked ? 'Always runs first.' : prodOff ? PROD_ONLY : off ? 'Not available in this release' : m.description} onChange={() => toggle(m.key)} />
              );
            })}
          </div>
        )}
        {pd === 'deep' && (
          <fieldset className="stack">
            <legend className="group-title">Accounts to test as</legend>
            {signin?.accounts.map((a) => <Checkbox key={a.id} checked={extras.accounts.includes(a.id)} onChange={() => toggleAccount(a.id)} label={`${a.role_label} · ${a.username_hint}`} />)}
            {signin && !signin.accounts.length && <small className="muted">No test accounts yet.</small>}
            {assessmentId && <Link to={`/assessments/${assessmentId}?tab=signin`}>Set up sign-in and accounts</Link>}
          </fieldset>
        )}
        {pd && !!c.wordlists?.length && (
          <>
            <Advanced wordlists={c.wordlists} selected={extras.lists} deep={pd === 'deep'} onToggle={toggleList} />
            <p className={over ? 'tone-text-danger' : 'muted'} role={over ? 'alert' : undefined}>
              {over ? `This selection needs about ${need.toLocaleString('en-IN')} requests; the limit for this profile is ${limit!.request_cap.toLocaleString('en-IN')}.` : `About ${need.toLocaleString('en-IN')} extra requests`}
            </p>
          </>
        )}
        <div className="filters">
          {onBack && <Button onClick={onBack}>Back</Button>}
          <Button variant="primary" disabled={!canContinue} onClick={onNext}>Continue to review</Button>
        </div>
      </Card>
      <div className="stack sticky">
        <ScopeSummary form={form} />
        <Card title="Limits & impact">
          <KeyValue items={[
            { label: 'Expected impact', value: chosen?.impact ?? 'Depends on the modules chosen' },
            { label: 'Estimated duration', value: chosen?.duration ?? 'Depends on the modules chosen' },
            ...(limit ? [
              { label: 'Time budget', value: `Stops after ${budgetText(limit.budget_min)} and reports what it found` },
              { label: 'Request cap and rate', value: `${limit.request_cap.toLocaleString('en-IN')} requests · ${limit.rate_per_s} per second` },
              ...(c.advisory_as_of ? [{ label: 'Advisory data as of', value: c.advisory_as_of }] : []),
            ] : [{ label: 'Request cap and rate', value: <TbdMarker label="TBD" od={6} /> }]),
            { label: 'Crawl depth and timeouts', value: <TbdMarker label="TBD" od={6} /> },
            { label: 'Priority', value: 'Normal · set by an administrator' },
          ]} />
        </Card>
      </div>
    </div>
  );
}

function Review({ assessment, form, run, extras, signin, catalog, policy, onBack }: {
  assessment: Assessment; form: Form; run: Run; extras: Extras; signin: SigninState | null; catalog: Catalog | null; policy: string; onBack: () => void;
}) {
  const [key] = useState(uuid); // one key per review screen: a retry returns the same job
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ unavailable: boolean; text: string } | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const cap = useLoad<{ capacity: Capacity }>('/queue');
  const capacity = cap.data?.capacity;
  const blocked = capacity?.blocked_reason ?? null;
  const modules = run.mode === 'profile' ? catalog?.profiles.find((p) => p.key === run.profile)?.modules ?? [] : run.modules;
  const moduleName = (k: ModuleKey) => catalog?.modules.find((m) => m.key === k)?.name ?? k;

  const submit = async () => {
    setBusy(true); setError(null);
    try {
      const body = { assessment_id: assessment.id, profile: run.mode === 'profile' ? run.profile : null, modules: run.mode === 'modules' ? run.modules : null, authorized: true, idempotency_key: key, ...(extras.lists.length ? { wordlists: extras.lists } : {}), ...(extras.accounts.length ? { credential_ids: extras.accounts } : {}) };
      const j = await api<Job>('/jobs', { method: 'POST', body });
      if (j?.id) setJob(j); else setError({ unavailable: true, text: '' });
    } catch (e) {
      const client = e instanceof ApiError && e.status > 0 && e.status < 500;
      setError({ unavailable: !client, text: client ? (e.fields?.wordlists ?? e.fields?.profile ?? e.fields?.credential_ids ?? e.detail) : '' });
    }
    setBusy(false);
  };

  if (job) {
    return (
      <Card title="Scan submitted">
        <p>Job <b className="mono">{job.id}</b> <StatusBadge kind="job" status={job.state} live /></p>
        {job.queue_position !== null && (
          <p>#{job.queue_position} in queue{job.wait_estimate ? ` · approx. ${job.wait_estimate.lo_min}–${job.wait_estimate.hi_min} min` : ''}</p>
        )}
        <p>{job.queue_position !== null ? 'Scan queued — another scan is using the available capacity. It starts automatically; you can leave this page.' : 'Your scan was accepted and starts automatically. You can leave this page.'}</p>
        <div className="filters">
          <Link className="btn btn-primary btn-md btn-link" to={`/assessments/${assessment.id}`}>Follow progress</Link>
          <Link className="btn btn-secondary btn-md btn-link" to="/queue">View scan queue</Link>
        </div>
      </Card>
    );
  }

  const chips: ReactNode = <span className="chips">{modules.map((m) => <span key={m} className="chip mono">{moduleName(m)}</span>)}</span>;
  return (
    <div className="grid2">
      <Card title="Review & submit">
        {assessment.active_job_id && (
          <Banner tone="warn" title="This assessment already has a scan in progress">
            <span className="mono">{assessment.active_job_id}</span> is queued or running. Submitting adds another scan of the same target.
          </Banner>
        )}
        <KeyValue items={[
          { label: 'Assessment', value: `${assessment.name} · ${assessment.id}` },
          { label: 'Target', value: form.target, mono: true },
          { label: 'Scope', value: `${form.hosts} · ${form.paths} · ports ${form.ports}`, mono: true },
          { label: 'Run', value: run.mode === 'profile' ? PROFILE_NAMES[run.profile] : 'Individual modules' },
          { label: 'Modules', value: chips },
          ...(extras.accounts.length ? [{ label: 'Accounts', value: extras.accounts.map((id) => signin?.accounts.find((a) => a.id === id)?.role_label ?? id).join(', ') }] : []),
          ...(extras.lists.length ? [{ label: 'Wordlists', value: extras.lists.map((k) => catalog?.wordlists?.find((w) => w.key === k)?.label ?? k).join(', ') }] : []),
          { label: 'Policy', value: policy, mono: true },
        ]} />
        <p className="muted">Queue limits: <TbdMarker label="TBD" od={10} /></p>
        {cap.error && !capacity && <Banner tone="danger" title="Capacity unknown">Current capacity could not be loaded, so Submit is disabled. <button type="button" className="btn btn-secondary btn-sm" onClick={cap.reload}>Try again</button></Banner>}
        {blocked && <Banner tone="danger" title="New scans are blocked">{BLOCKED_COPY[blocked]}</Banner>}
        {error?.unavailable && (
          <Banner tone="danger">Service unavailable — your scan was not submitted. No job ID was returned, so nothing is queued. Check Scan Queue before trying again.</Banner>
        )}
        {error && !error.unavailable && <Banner tone="danger" title="Your scan was not submitted">{error.text}</Banner>}
        <Checkbox checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} label="I confirm I am authorized to test this target within the scope above." />
        <div className="filters">
          <Button onClick={onBack}>Back</Button>
          <Button variant="primary" disabled={!authorized || !!blocked || !capacity} busy={busy} busyLabel="Submitting…" onClick={submit}>Submit scan</Button>
        </div>
      </Card>
      <div className="stack sticky">
        <Disclaimer />
        {capacity && <CapacityMeter capacity={capacity} />}
      </div>
    </div>
  );
}
