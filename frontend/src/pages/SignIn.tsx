import { useRef, useState, type ClipboardEvent, type FormEvent, type KeyboardEvent } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { api, ApiError } from '../lib/api';
import type { LoginResult, Me } from '../lib/types';
import { landingFor, useAuth } from '../auth/AuthContext';
import { Banner, Button, TbdMarker, TextField } from '../components';

const LEN = 6;

function CodeInput({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const refs = useRef<(HTMLInputElement | null)[]>([]);
  const focus = (i: number) => refs.current[Math.min(Math.max(i, 0), LEN - 1)]?.focus();
  const set = (i: number, digits: string) => {
    const chars = value.padEnd(LEN, ' ').split('');
    digits.split('').forEach((d, k) => { if (i + k < LEN) chars[i + k] = d; });
    onChange(chars.join('').trimEnd());
    focus(i + digits.length);
  };
  const onKeyDown = (i: number, e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !value[i]) focus(i - 1);
    if (e.key === 'ArrowLeft') focus(i - 1);
    if (e.key === 'ArrowRight') focus(i + 1);
  };
  const onPaste = (e: ClipboardEvent) => {
    e.preventDefault();
    const digits = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, LEN);
    if (digits) { onChange(digits); focus(digits.length); }
  };
  return (
    <fieldset className="code">
      <legend>6-digit code</legend>
      <div className="code-row">
        {Array.from({ length: LEN }, (_, i) => (
          <input
            key={i} ref={(el) => { refs.current[i] = el; }} className="control mono code-digit" inputMode="numeric"
            autoComplete={i === 0 ? 'one-time-code' : 'off'} maxLength={1} aria-label={`Digit ${i + 1} of ${LEN}`}
            value={value[i]?.trim() ?? ''}
            onChange={(e) => { const d = e.target.value.replace(/\D/g, ''); if (d) set(i, d); else onChange(value.slice(0, i)); }}
            onKeyDown={(e) => onKeyDown(i, e)} onPaste={onPaste}
          />
        ))}
      </div>
    </fieldset>
  );
}

const group4 = (s: string) => s.replace(/\s+/g, '').replace(/(.{4})/g, '$1 ').trim();

export function SignIn() {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();
  const [step, setStep] = useState<'password' | 'mfa' | 'enrol'>('password');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [enrol, setEnrol] = useState<{ secret: string; uri: string } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  if (user) return <Navigate to={landingFor(user)} replace />;

  const run = async (fn: () => Promise<void>) => {
    setBusy(true); setError('');
    try { await fn(); } catch (e) { setError(e instanceof ApiError ? e.detail : 'Service unavailable. Try again.'); } finally { setBusy(false); }
  };

  const submitPassword = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const r = await api<LoginResult>('/auth/login', { method: 'POST', body: { email, password } });
      setPassword('');
      if (r.next === 'enrol') setEnrol({ secret: r.secret, uri: r.otpauth_uri });
      setStep(r.next);
    });
  };

  const submitCode = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      const me = await api<Me>('/auth/mfa', { method: 'POST', body: { code } });
      setUser(me);
      navigate(landingFor(me), { replace: true });
    });
  };

  return (
    <main className="signin">
      <div className="card signin-card">
        <div className="brand"><strong>Pre-Assessment Console</strong><span>Web & API security pre-assessment</span></div>
        <h1>Sign in</h1>
        {error && <Banner tone="danger">{error}</Banner>}
        {step === 'password' ? (
          <form onSubmit={submitPassword} className="stack" noValidate>
            <TextField id="email" label="Work email" type="email" required autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} />
            <TextField id="password" label="Password" type="password" required autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
            <Button type="submit" variant="primary" busy={busy} busyLabel="Signing in…" disabled={!email || !password}>Sign in</Button>
            <p className="muted">
              Forgot password? Resets go through your platform administrator. <TbdMarker label="Procedure" od={11} title="Password reset procedure" />
            </p>
          </form>
        ) : (
          <form onSubmit={submitCode} className="stack">
            {step === 'enrol' && enrol ? (
              <>
                <p>Set up two-step verification. Add this key to your authenticator app, then enter the first code it shows.</p>
                <p className="mono secret" aria-label="Setup key">{group4(enrol.secret)}</p>
                <details>
                  <summary>Show the otpauth link</summary>
                  <p className="mono wrap">{enrol.uri}</p>
                </details>
              </>
            ) : (
              <p>Enter the 6-digit code from your authenticator app.</p>
            )}
            <CodeInput value={code} onChange={setCode} />
            <Button type="submit" variant="primary" busy={busy} busyLabel="Verifying…" disabled={code.length < LEN}>Verify</Button>
          </form>
        )}
      </div>
    </main>
  );
}
