import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

let me: Record<string, unknown> = { id: 'U-001', name: 'Ada Admin', email: 'ada@example.test', role: 'admin', team: null };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });
const capacity = { active: 0, limit: 1, effective_limit: 1, queued: 0, healthy_workers: 1, ceiling: 3, blocked_reason: null };
const config = { limit: 1, aging_enabled: false, aging_minutes: 30, queue_cap: 50, per_user_quota: 3, paused: false };
const assessment = (own: boolean) => ({
  id: 'A-0002', name: 'Billing', owner: { id: own ? 'U-001' : 'U-002', name: 'Someone' }, target: 'https://billing.example.com', env: 'Staging', hosts: '', paths: '', ports: '', exclusions: '', notes: null,
  status: 'awaiting-approval', validation: { outcome: 'approval', checks: [], normalized_target: 'https://billing.example.com/', policy_version: 'v1', decided_at: '2026-11-09T08:50:00Z' },
  approval: { state: 'pending', note: null, by: null, at: null, self: own }, active_job_id: null, created_at: '2026-11-09T08:00:00Z', updated_at: '2026-11-09T08:00:00Z', access: 'admin',
});

type Handler = (method: string, body: any) => Response | undefined;
function mockApi(routes: Record<string, Handler | Response | object>) {
  document.cookie = 'pa_csrf=tok';
  const calls: { method: string; path: string; body: any }[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    const path = String(url).replace('/api', '');
    const method = init?.method ?? 'GET';
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, body });
    if (path === '/auth/me') return json(200, me);
    const r = routes[`${method} ${path}`] ?? routes[path];
    if (typeof r === 'function') return r(method, body) ?? json(404, { detail: 'No.' });
    if (r instanceof Response) return r.clone();
    return r ? json(200, r) : json(404, { detail: 'No.' });
  });
  return calls;
}
const mount = (path: string) => render(
  <MemoryRouter initialEntries={[path]}><AuthProvider><ToastProvider><App /></ToastProvider></AuthProvider></MemoryRouter>,
);
afterEach(() => { me = { ...me, role: 'admin' }; vi.restoreAllMocks(); document.cookie = 'pa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

it('non-admin on an admin route sees DeniedState', async () => {
  me = { ...me, role: 'owner' };
  mockApi({});
  mount('/admin/capacity');
  expect(await screen.findByText(/limited to Platform Administrators/)).toBeTruthy();
});

it('capacity: raising the limit above healthy workers shows the copy inline and opens no confirm', async () => {
  const calls = mockApi({ '/admin/capacity': { config, capacity, workers: [], history: [] } });
  const user = userEvent.setup();
  mount('/admin/capacity');
  const save = await screen.findByRole('button', { name: 'Save configuration' });
  expect((save as HTMLButtonElement).disabled).toBe(true);
  await user.selectOptions(screen.getByLabelText(/Global concurrency limit/), '2');
  await user.click(save);
  expect(await screen.findByText('Only 1 healthy worker is available. Enable or provision more workers before raising the limit to 2.')).toBeTruthy();
  expect(screen.queryByRole('alertdialog')).toBeNull();
  expect(calls.some((c) => c.method === 'PUT')).toBe(false);
});

it('capacity: confirm needs a reason, then PUT; a server 422 is shown inline', async () => {
  const calls = mockApi({
    '/admin/capacity': { config, capacity: { ...capacity, healthy_workers: 3 }, workers: [], history: [] },
    'PUT /admin/capacity': json(422, { detail: 'Limit must be between 1 and 3.' }),
  });
  const user = userEvent.setup();
  mount('/admin/capacity');
  await user.selectOptions(await screen.findByLabelText(/Global concurrency limit/), '2');
  await user.click(screen.getByRole('button', { name: 'Save configuration' }));
  const dlg = await screen.findByRole('alertdialog');
  const ok = within(dlg).getByRole('button', { name: 'Save configuration' }) as HTMLButtonElement;
  expect(ok.disabled).toBe(true);
  await user.type(within(dlg).getByLabelText(/Reason/), 'Need more throughput');
  expect(ok.disabled).toBe(false);
  await user.click(ok);
  expect(await screen.findByText('Limit must be between 1 and 3.')).toBeTruthy();
  expect(calls.find((c) => c.method === 'PUT')?.body).toMatchObject({ limit: 2, reason: 'Need more throughput' });
});

it('approvals: own request shows the self-approval banner; others do not', async () => {
  mockApi({
    '/admin/approvals': [{ assessment: assessment(true), requested_at: '2026-11-09T08:50:00Z', own: true }, { assessment: { ...assessment(false), id: 'A-0003', name: 'Other' }, requested_at: '2026-11-09T08:50:00Z', own: false }],
    '/admin/jobs?filter=interrupted': [],
  });
  const user = userEvent.setup();
  mount('/admin/jobs');
  expect(await screen.findByText('Your own request')).toBeTruthy();
  await user.click(screen.getByRole('button', { name: 'Decide on Billing' }));
  expect(await screen.findByText(/This is your own target/)).toBeTruthy();
  await user.click(screen.getByRole('button', { name: 'Cancel' }));
  await user.click(screen.getByRole('button', { name: 'Decide on Other' }));
  await screen.findByRole('dialog');
  expect(screen.queryByText(/This is your own target/)).toBeNull();
});

it('users: own row shows You without actions; create shows the temporary password once', async () => {
  const u = (id: string, name: string) => ({ id, name, email: `${id}@example.test`, role: 'owner', team: null, status: 'active', mfa: 'enrolled', last_login_at: null, sessions: 1 });
  mockApi({ '/admin/users': [u('U-001', 'Ada Admin'), u('U-002', 'Bob')], 'POST /admin/users': json(201, { user: u('U-003', 'Cy'), temporary_password: 'Tmp-Pass-123' }) });
  const user = userEvent.setup();
  mount('/admin/users');
  await screen.findByText('Bob');
  expect(screen.getByText('You')).toBeTruthy();
  expect(screen.queryByLabelText('Actions for Ada Admin')).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Create account' }));
  await user.type(screen.getByLabelText(/Full name/), 'Cy');
  await user.type(screen.getByLabelText(/Work email/), 'not-an-email');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Create account' }));
  expect(await screen.findByText(/valid work email/)).toBeTruthy();
  await user.clear(screen.getByLabelText(/Work email/));
  await user.type(screen.getByLabelText(/Work email/), 'cy@example.test');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Create account' }));
  expect(await screen.findByText('Tmp-Pass-123')).toBeTruthy();
  expect(screen.getByText('Share this through an approved channel. It is shown only once.')).toBeTruthy();
});

it('audit: export link carries the filters and the footer copy is exact', async () => {
  const ev = { id: 'E-1', at: '2026-11-09T08:50:00Z', actor: 'Ada', area: 'job', action: 'job.cancel', object: 'JOB-1', outcome: 'success', detail: 'why', policy_version: null };
  mockApi({ '/admin/audit?': [ev], '/admin/audit?area=job': [ev] });
  const user = userEvent.setup();
  mount('/admin/audit');
  await screen.findByText('job.cancel');
  expect(screen.getByText('Events cannot be edited or deleted here. Secrets, passwords and tokens are never logged.')).toBeTruthy();
  await user.selectOptions(screen.getByLabelText('Area'), 'job');
  await waitFor(() => expect(screen.getByRole('link', { name: 'Export CSV (1)' }).getAttribute('href')).toBe('/api/admin/audit.csv?area=job'));
});
