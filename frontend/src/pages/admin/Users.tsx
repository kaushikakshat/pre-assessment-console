import { useState } from 'react';
import { api, ApiError } from '../../lib/api';
import { useAuth } from '../../auth/AuthContext';
import { Banner, Button, DataTable, KeyValue, LoadError, Loading, Modal, ReasonConfirm, Select, Tabs, TbdMarker, TextField, type Column } from '../../components';
import { formatIST } from '../../lib/format';
import { useLoad } from '../../lib/useLoad';
import type { Role, User } from '../../lib/types';
import { useAct } from './common';

const ROLE_LABEL: Record<Role, string> = { owner: 'Assessment Owner', admin: 'Platform Administrator' };
type Action = 'change-role' | 'deactivate' | 'reactivate' | 'reset-mfa' | 'revoke-sessions';
const ACTIONS: Record<Action, { label: string; title: (n: string) => string; text: string; keep: string; confirm: string; danger?: boolean }> = {
  'change-role': { label: 'Change role', title: (n) => `Change role for ${n}?`, text: 'Their access changes the next time they load a page.', keep: 'Keep role', confirm: 'Change role' },
  deactivate: { label: 'Deactivate', title: (n) => `Deactivate ${n}?`, text: 'They are signed out and cannot sign in until reactivated.', keep: 'Keep access', confirm: 'Deactivate', danger: true },
  reactivate: { label: 'Reactivate', title: (n) => `Reactivate ${n}?`, text: 'They can sign in again.', keep: 'Keep deactivated', confirm: 'Reactivate' },
  'reset-mfa': { label: 'Reset two-step verification', title: (n) => `Reset two-step verification for ${n}?`, text: 'They must enrol a new authenticator at their next sign-in.', keep: 'Keep verification', confirm: 'Reset verification', danger: true },
  'revoke-sessions': { label: 'Revoke all sessions', title: (n) => `Revoke all sessions for ${n}?`, text: 'Every device they are signed in on is signed out.', keep: 'Keep sessions', confirm: 'Revoke sessions', danger: true },
};
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export function Users() {
  const { user: me } = useAuth();
  const users = useLoad<User[]>('/admin/users');
  const [pending, setPending] = useState<{ user: User; action: Action } | null>(null);
  const [role, setRole] = useState<Role>('owner');
  const [creating, setCreating] = useState(false);
  const act = useAct();

  const choose = (u: User, a: Action) => {
    act.clear(); setRole(u.role === 'admin' ? 'owner' : 'admin'); setPending({ user: u, action: a });
  };
  const confirm = async (reason: string) => {
    const { user, action } = pending!;
    const ok = await act.run(() => api(`/admin/users/${user.id}/actions`, { method: 'POST', body: { action, reason, ...(action === 'change-role' ? { role } : {}) } }), `${ACTIONS[action].label}: done for ${user.name}.`);
    if (ok) { setPending(null); users.reload(); }
  };

  const cols: Column<User>[] = [
    { key: 'p', header: 'Person', render: (u) => <><b>{u.name}</b><br /><span className="muted">{u.email}{u.team ? ` · ${u.team}` : ''}</span></> },
    { key: 'r', header: 'Role', render: (u) => ROLE_LABEL[u.role] },
    { key: 's', header: 'Status', render: (u) => (u.status === 'active' ? 'Active' : 'Deactivated') },
    { key: 'm', header: 'Two-step verification', render: (u) => (u.mfa === 'enrolled' ? 'Enrolled' : 'Pending enrolment') },
    { key: 'l', header: 'Last sign-in', render: (u) => formatIST(u.last_login_at) },
    { key: 'n', header: 'Sessions', align: 'right', render: (u) => u.sessions },
    { key: 'a', header: 'Actions', render: (u) => {
      if (u.id === me!.id) return <b>You</b>;
      const list: Action[] = ['change-role', u.status === 'active' ? 'deactivate' : 'reactivate', 'reset-mfa', 'revoke-sessions'];
      return (
        <select className="control" aria-label={`Actions for ${u.name}`} value="" onChange={(e) => choose(u, e.target.value as Action)}>
          <option value="">Actions…</option>
          {list.map((a) => <option key={a} value={a}>{ACTIONS[a].label}</option>)}
        </select>
      );
    } },
  ];

  return (
    <div className="stack-lg">
      <div className="page-head"><h1>Users &amp; Roles</h1><Button variant="primary" icon="plus" onClick={() => setCreating(true)}>Create account</Button></div>
      <Tabs tabs={[{ key: 'accounts', label: 'Accounts' }, { key: 'roles', label: 'Roles & permissions' }, { key: 'signin', label: 'Sign-in & sessions' }]}>
        {(tab) => tab === 'accounts' ? (
          <div className="stack">
            {users.error && !users.data && <LoadError error={users.error} thing="accounts" onRetry={users.reload} />}
            {!users.data && !users.error && <Loading />}
            {users.data && <DataTable caption="Accounts" columns={cols} rows={users.data} rowKey={(u) => u.id} empty={{ title: 'No accounts' }} />}
          </div>
        ) : tab === 'roles' ? <RoleMatrix /> : (
          <section className="card"><div className="card-body"><KeyValue items={[
            { label: 'Two-step verification', value: 'Required for every account' },
            { label: 'Session lifetime', value: <>12 hours <TbdMarker label="Confirm value" od={19} /></> },
            { label: 'Single sign-on', value: <TbdMarker label="Single sign-on" od={5} /> },
          ]} /></div></section>
        )}
      </Tabs>
      {pending && (
        <ReasonConfirm
          open title={ACTIONS[pending.action].title(pending.user.name)} cancelLabel={ACTIONS[pending.action].keep} confirmLabel={ACTIONS[pending.action].confirm}
          tone={ACTIONS[pending.action].danger ? 'danger' : 'primary'} busy={act.busy} onCancel={() => setPending(null)} onConfirm={confirm}
          extra={<>
            {pending.action === 'change-role' && (
              <Select id="new-role" label="New role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
                {(['owner', 'admin'] as Role[]).map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
              </Select>
            )}
            {act.failure && <Banner tone="danger" title="Not saved">{act.failure}</Banner>}
          </>}
        >{ACTIONS[pending.action].text}</ReasonConfirm>
      )}
      {creating && <CreateAccount onClose={() => { setCreating(false); users.reload(); }} />}
    </div>
  );
}

function CreateAccount({ onClose }: { onClose: () => void }) {
  const [f, setF] = useState({ name: '', email: '', role: 'owner' as Role, team: '' });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [password, setPassword] = useState<string | null>(null);
  const submit = async () => {
    const e: Record<string, string> = {};
    if (!f.name.trim()) e.name = 'Enter the full name.';
    if (!EMAIL.test(f.email.trim())) e.email = 'Enter a valid work email, like name@company.com.';
    setErrors(e); setFailure(null);
    if (Object.keys(e).length) return;
    setBusy(true);
    try {
      const r = await api<{ temporary_password: string }>('/admin/users', { method: 'POST', body: { name: f.name.trim(), email: f.email.trim(), role: f.role, team: f.team.trim() || null } });
      setPassword(r.temporary_password);
    } catch (x) {
      if (x instanceof ApiError && x.fields) setErrors(x.fields);
      else if (x instanceof ApiError && x.status === 409) setErrors({ email: x.detail });
      else setFailure(x instanceof ApiError ? x.detail : 'The account was not created. Try again.');
    }
    setBusy(false);
  };
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  return (
    <Modal open title="Create account" onClose={onClose}
      footer={password ? <Button variant="primary" onClick={onClose}>Done</Button> : <><Button onClick={onClose}>Cancel</Button><Button variant="primary" busy={busy} onClick={submit}>Create account</Button></>}>
      {password ? (
        <>
          <p>Account created. Give this temporary password to the new user. They set up two-step verification at first sign-in.</p>
          <p className="secret mono" aria-label="Temporary password">{password}</p>
          <Banner tone="warn">Share this through an approved channel. It is shown only once.</Banner>
        </>
      ) : (
        <>
          <TextField id="cu-name" label="Full name" required value={f.name} error={errors.name} onChange={set('name')} />
          <TextField id="cu-email" label="Work email" required type="email" value={f.email} error={errors.email} onChange={set('email')} />
          <Select id="cu-role" label="Role" value={f.role} onChange={set('role')}>
            {(['owner', 'admin'] as Role[]).map((r) => <option key={r} value={r}>{ROLE_LABEL[r]}</option>)}
          </Select>
          <TextField id="cu-team" label="Team" value={f.team} error={errors.team} onChange={set('team')} />
          {failure && <Banner tone="danger" title="Not created">{failure}</Banner>}
        </>
      )}
    </Modal>
  );
}

const MATRIX: [string, string, string][] = [
  ['Manage users and roles', 'No', 'Yes'],
  ['Create assessments and test websites', 'Yes', 'Yes'],
  ['Submit scans and retests on own assessments', 'Yes', 'Yes'],
  ['View any assessment', 'No (only shared, read-only)', 'Yes, read-only'],
  ['Share an assessment (view only)', 'Own, with any active user', 'Own, with any active user'],
  ['Retest findings', 'Only on scans they initiated', 'Only on scans they initiated'],
  ['Change finding state', 'Own assessments, directly', 'Own assessments, directly'],
  ['Generate reports', 'Own assessments', 'Any assessment'],
  ['Approve targets that need approval', 'No', 'Yes (own: self-approval with reason)'],
  ['Change policy, profiles, modules', 'No', 'Yes'],
  ['Change concurrency and scheduling', 'No', 'Yes'],
  ['Emergency controls', 'No', 'Yes'],
  ['View audit logs', 'Activity on own assessments', 'All'],
];
function RoleMatrix() {
  const cols: Column<(typeof MATRIX)[number]>[] = [
    { key: 'f', header: 'Function', render: (r) => r[0] },
    { key: 'o', header: 'Assessment Owner', render: (r) => r[1] },
    { key: 'a', header: 'Platform Administrator', render: (r) => r[2] },
  ];
  return <DataTable caption="Role permissions" columns={cols} rows={MATRIX} rowKey={(r) => r[0]} empty={{ title: 'No roles' }} />;
}
