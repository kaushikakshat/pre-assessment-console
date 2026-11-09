import { useState } from 'react';
import { api, ApiError } from '../lib/api';
import { Banner, Button, Card, Checkbox, ConfirmDialog, DataTable, LoadError, Loading, Modal, StatusBadge, TextField, useToast } from '../components';
import { formatIST } from '../lib/format';
import { useLoad } from '../lib/useLoad';
import type { LoginStyle, SigninSetup as Setup, SigninState, TestAccount } from '../lib/types';

export const AUTH_COPY = 'I confirm I am authorized to test this target within the scope above.';
const BLANK = { style: 'single' as LoginStyle, login_url: '', username_field: '', password_field: '', code_field: '', otp_url: '', otp_field: '', logged_in_indicator: '', logged_out_indicator: '' };
type SetupForm = typeof BLANK;
/** Field errors that no rendered input shows, so they still reach the user. */
const unmapped = (fields: Record<string, string>, shown: string[]) => Object.entries(fields).filter(([k]) => !shown.includes(k)).map(([, v]) => v).join(' ');

/** Owner-only tab. Secrets are write-only: no input is ever prefilled from the server. */
export function SigninSetup({ assessmentId }: { assessmentId: string }) {
  const state = useLoad<SigninState>(`/assessments/${assessmentId}/signin`);
  const [adding, setAdding] = useState<TestAccount | 'new' | null>(null);
  const [removing, setRemoving] = useState<TestAccount | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toast = useToast();
  if (state.error && !state.data) return <LoadError error={state.error} thing="sign-in setup" onRetry={state.reload} />;
  if (!state.data) return <Loading />;
  const { setup, accounts } = state.data;

  const remove = async () => {
    setBusy(true);
    try { await api(`/assessments/${assessmentId}/accounts/${removing!.id}`, { method: 'DELETE' }); toast('Account removed.'); setRemoving(null); state.reload(); }
    catch (e) { setError(e instanceof ApiError ? e.detail : 'Could not remove the account. Try again.'); setRemoving(null); }
    setBusy(false);
  };

  return (
    <div className="stack-lg">
      <SetupCard assessmentId={assessmentId} setup={setup} onSaved={state.reload} />
      <Card title="Test accounts" action={<Button icon="plus" disabled={!setup} onClick={() => setAdding('new')}>Add account</Button>}>
        {!setup && <p className="muted">Save the sign-in setup before adding accounts.</p>}
        {error && <Banner tone="danger">{error}</Banner>}
        <DataTable caption="Test accounts" rows={accounts} rowKey={(r) => r.id}
          empty={{ title: 'No test accounts', text: 'Add one account per role you want tested.' }}
          columns={[
            { key: 'role', header: 'Role', render: (r) => r.role_label },
            { key: 'user', header: 'Username', mono: true, render: (r) => r.username_hint },
            { key: 'test', header: 'Last test', render: (r) => (r.last_test
              ? <StatusBadge kind="check" status={r.last_test === 'ok' ? 'pass' : 'fail'} label={`${r.last_test === 'ok' ? 'Signed in' : 'Sign-in failed'}${r.last_tested_at ? ` · ${formatIST(r.last_tested_at)}` : ''}`} />
              : <span className="muted">Not tested</span>) },
            { key: 'actions', header: 'Actions', render: (r) => (
              <span className="filters">
                <Button size="sm" onClick={() => setAdding(r)}>Replace<span className="sr-only"> {r.role_label}</span></Button>
                <Button size="sm" variant="danger-outline" onClick={() => setRemoving(r)}>Remove<span className="sr-only"> {r.role_label}</span></Button>
              </span>) },
          ]} />
      </Card>
      {adding && setup && <AccountModal assessmentId={assessmentId} setup={setup} account={adding === 'new' ? null : adding} onClose={() => { setAdding(null); state.reload(); }} />}
      <ConfirmDialog open={!!removing} title={`Remove ${removing?.role_label ?? ''}?`} tone="danger" cancelLabel="Keep account" confirmLabel="Remove account" busy={busy}
        onCancel={() => setRemoving(null)} onConfirm={remove}>
        Its saved credentials are deleted. Scans can no longer test as this role.
      </ConfirmDialog>
    </div>
  );
}

function SetupCard({ assessmentId, setup, onSaved }: { assessmentId: string; setup: Setup | null; onSaved: () => void }) {
  const [f, setF] = useState<SetupForm>(setup ? { ...BLANK, ...Object.fromEntries(Object.entries(setup).filter(([k, v]) => k in BLANK && v !== null)) } as SetupForm : BLANK);
  const [bypass, setBypass] = useState('');
  const [replacing, setReplacing] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [failure, setFailure] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [removing, setRemoving] = useState(false);
  const toast = useToast();
  const two = f.style === 'two-step';
  const set = (k: keyof SetupForm) => (e: { target: { value: string } }) => setF((x) => ({ ...x, [k]: e.target.value }));
  const field = (k: keyof SetupForm, label: string, extra: { mono?: boolean; required?: boolean; hint?: string } = { mono: true }) => (
    <TextField id={`su-${k}`} label={label} autoComplete="off" value={f[k]} onChange={set(k)} error={errors[k]} {...extra} />
  );

  const save = async (clearBypass = false) => {
    setBusy(true); setErrors({}); setFailure(null);
    const body: Record<string, unknown> = { ...f, code_field: !two && f.code_field ? f.code_field : null, otp_url: two ? f.otp_url : null, otp_field: two ? f.otp_field : null, logged_out_indicator: f.logged_out_indicator || null };
    if (clearBypass) body.bypass_code = ''; else if (bypass) body.bypass_code = bypass; // omitted keeps the stored value
    try {
      await api(`/assessments/${assessmentId}/signin`, { method: 'PUT', body });
      setBypass(''); setReplacing(false); setRemoving(false); toast('Sign-in setup saved.'); onSaved();
    } catch (e) {
      setRemoving(false);
      if (e instanceof ApiError && e.fields) {
        setErrors(e.fields);
        const extra = unmapped(e.fields, [...Object.keys(BLANK), ...(setup?.bypass_code_set && !replacing ? [] : ['bypass_code'])]);
        if (extra) setFailure(extra);
      } else setFailure(e instanceof ApiError ? e.detail : 'Could not save. Try again.');
    }
    setBusy(false);
  };

  return (
    <Card title="Sign-in setup">
      <p className="muted">Describe how the app signs a user in. Scans use this to test as each account.</p>
      <div className="seg-ctl" role="group" aria-label="Sign-in style">
        <button type="button" aria-pressed={!two} onClick={() => setF((x) => ({ ...x, style: 'single' }))}>One form</button>
        <button type="button" aria-pressed={two} onClick={() => setF((x) => ({ ...x, style: 'two-step' }))}>Password then OTP page</button>
      </div>
      {failure && <Banner tone="danger">{failure}</Banner>}
      {field('login_url', 'Login page URL', { mono: true, required: true })}
      <div className="f2">{field('username_field', 'Username field name', { mono: true, required: true })}{field('password_field', 'Password field name', { mono: true, required: true })}</div>
      {!two && field('code_field', 'Code field name', { mono: true, hint: 'Optional. Only if the form also asks for a code.' })}
      {two && <div className="f2">{field('otp_url', 'OTP page URL', { mono: true, required: true })}{field('otp_field', 'OTP field name', { mono: true, required: true })}</div>}
      <div className="field">
        {setup?.bypass_code_set && !replacing
          ? <p>Bypass code: Set <button type="button" className="link-btn" aria-label="Replace bypass code" onClick={() => setReplacing(true)}>Replace</button>{' '}
              <button type="button" className="link-btn" onClick={() => setRemoving(true)}>Remove code</button></p>
          : <TextField id="su-bypass" label="Bypass code" type="password" autoComplete="new-password" value={bypass} onChange={(e) => setBypass(e.target.value)} error={errors.bypass_code} hint="Stored encrypted. It is never shown again." />}
      </div>
      <div className="f2">
        {field('logged_in_indicator', 'Signed-in marker', { required: true, hint: 'Text that appears only when signed in, for example Log out.' })}
        {field('logged_out_indicator', 'Signed-out marker', { hint: 'Optional. Text that appears when signed out.' })}
      </div>
      <div className="filters"><Button variant="primary" busy={busy} busyLabel="Saving…" onClick={() => save()}>Save sign-in setup</Button></div>
      {setup && <small className="muted">Last saved {formatIST(setup.updated_at)}</small>}
      <ConfirmDialog open={removing} title="Remove bypass code?" tone="danger" cancelLabel="Keep code" confirmLabel="Remove code" busy={busy} onCancel={() => setRemoving(false)} onConfirm={() => save(true)}>
        The saved code is deleted. Scans that need it will fail until you add one again.
      </ConfirmDialog>
    </Card>
  );
}

function AccountModal({ assessmentId, setup, account, onClose }: { assessmentId: string; setup: Setup; account: TestAccount | null; onClose: () => void }) {
  const [role, setRole] = useState(account?.role_label ?? '');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [bypass, setBypass] = useState('');
  const [test, setTest] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [result, setResult] = useState<{ tone: 'ok' | 'danger' | 'info'; text: string } | null>(null);
  const [done, setDone] = useState(false);
  const [savedOnce, setSavedOnce] = useState(false);
  const [savedId, setSavedId] = useState<string | null>(account?.id ?? null); // after a first save, retries replace it instead of adding a duplicate
  const needsBypass = test && (!!setup.code_field || setup.style === 'two-step');
  const ready = role.trim() && username && password && (!test || authorized);

  const submit = async () => {
    setBusy(true); setErrors({}); setResult(null);
    const body: Record<string, unknown> = { role_label: role.trim(), username, password, test, authorized: test && authorized };
    if (needsBypass && bypass) body.bypass_code = bypass; // used for this test only, never stored
    try {
      const r = await api<TestAccount & { test_result: string | null }>(`/assessments/${assessmentId}/accounts${savedId ? `/${savedId}` : ''}`, { method: savedId ? 'PUT' : 'POST', body });
      setSavedId(r.id ?? savedId); setSavedOnce(true); setPassword(''); setBypass('');
      const ok = r.last_test === 'ok';
      setDone(!test || ok); // a failed test keeps the form so the user can retry
      setResult(test ? { tone: ok ? 'ok' : 'danger', text: r.test_result ?? (ok ? 'Signed in.' : 'Sign-in failed.') } : { tone: 'info', text: 'Account saved. It has not been tested.' });
    } catch (e) {
      setPassword(''); setBypass('');
      if (e instanceof ApiError && e.fields) {
        setErrors(e.fields);
        const extra = unmapped(e.fields, ['role_label', 'username', 'password', ...(needsBypass ? ['bypass_code'] : [])]);
        if (extra) setResult({ tone: 'danger', text: extra });
      } else setResult({ tone: 'danger', text: e instanceof ApiError ? e.detail : 'Could not save the account. Try again.' });
    }
    setBusy(false);
  };

  const banner = result && <Banner tone={result.tone} title={result.tone === 'ok' ? 'Sign-in worked' : result.tone === 'danger' && savedOnce ? 'Saved, but sign-in failed' : undefined}>{result.text}</Banner>;
  return (
    <Modal open title={account ? `Replace ${account.role_label}` : 'Add account'} onClose={onClose}
      footer={done ? <Button variant="primary" onClick={onClose}>Done</Button> : <><Button onClick={onClose}>Cancel</Button><Button variant="primary" disabled={!ready} busy={busy} busyLabel="Saving…" onClick={submit}>{test ? 'Save and test' : 'Save account'}</Button></>}>
      {banner}
      {!done && (
        <div className="stack">
          <TextField id="ac-role" label="Role label" required autoComplete="off" value={role} onChange={(e) => setRole(e.target.value)} error={errors.role_label} hint="For example Admin or Customer." />
          <TextField id="ac-user" label="Username" required autoComplete="off" value={username} onChange={(e) => setUsername(e.target.value)} error={errors.username} />
          <TextField id="ac-pass" label="Password" type="password" required autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} error={errors.password} />
          <Checkbox checked={test} onChange={(e) => setTest(e.target.checked)} label="Test sign-in now" />
          {test && <Checkbox checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} label={AUTH_COPY} />}
          {needsBypass && <TextField id="ac-bypass" label="Bypass code (used for this test only, never stored)" type="password" autoComplete="new-password" value={bypass} onChange={(e) => setBypass(e.target.value)} error={errors.bypass_code} />}
        </div>
      )}
    </Modal>
  );
}
