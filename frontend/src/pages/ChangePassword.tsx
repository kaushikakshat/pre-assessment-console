import { useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api, ApiError } from '../lib/api';
import type { Me } from '../lib/types';
import { landingFor, useAuth } from '../auth/AuthContext';
import { Banner, Button, Card, TextField, useToast } from '../components';

export function ChangePassword() {
  const { user, setUser } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [fields, setFields] = useState<Record<string, string>>({});
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError('');
    const missing: Record<string, string> = {};
    if (!current) missing.current_password = 'Enter your current password.';
    if (!next) missing.new_password = 'Enter a new password.';
    if (!confirm) missing.confirm = 'Confirm your new password.';
    if (Object.keys(missing).length) { setFields(missing); return; }
    if (next !== confirm) { setFields({ confirm: 'The passwords do not match.' }); document.getElementById('confirm')?.focus(); return; }
    setFields({}); setBusy(true);
    try {
      const me = await api<Me>('/auth/password', { method: 'POST', body: { current_password: current, new_password: next } });
      setUser(me);
      toast('Password changed. Other sessions were signed out.');
      navigate(landingFor(me), { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.fields) setFields(err.fields);
      else setError(err instanceof ApiError ? err.detail : 'Service unavailable. Try again.');
    } finally { setBusy(false); }
  };

  return (
    <div className="stack-lg">
      <h1>Change password</h1>
      {user?.must_change_password && (
        <Banner tone="warn" title="Choose a new password to continue">The temporary password from your administrator only works once.</Banner>
      )}
      <Card title="New password">
        <form onSubmit={(e) => void submit(e)} className="stack" noValidate>
          {error && <Banner tone="danger">{error}</Banner>}
          <TextField id="current" label="Current password" type="password" required autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} error={fields.current_password} />
          <TextField id="new" label="New password" type="password" required autoComplete="new-password" hint="At least 12 characters." value={next} onChange={(e) => setNext(e.target.value)} error={fields.new_password} />
          <TextField id="confirm" label="Confirm new password" type="password" required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} error={fields.confirm} />
          <div><Button type="submit" variant="primary" busy={busy} busyLabel="Changing…">Change password</Button></div>
        </form>
      </Card>
    </div>
  );
}
