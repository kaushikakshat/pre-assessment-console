import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

const me = { id: 'U-001', name: 'Ada Admin', email: 'ada@example.test', role: 'admin', team: null, must_change_password: false };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });
const capacity = { active: 0, limit: 1, effective_limit: 1, queued: 0, healthy_workers: 1, ceiling: 3, blocked_reason: null };
const profile_limits = { pre: { budget_min: 30, request_cap: 5000, rate_per_s: 5 }, deep: { budget_min: 180, request_cap: 50000, rate_per_s: 10 } };
const config = { limit: 1, aging_enabled: false, aging_minutes: 30, queue_cap: 50, per_user_quota: 3, paused: false, engine_slots: 1, profile_limits };
const catalog = {
  profiles: [{ key: 'pre', name: 'Pre-Assessment', description: 'Crawl and test.', modules: ['crawl'], available: true, duration: '30 min', impact: 'Moderate' }],
  modules: [{ key: 'crawl', name: 'Crawler', description: 'Maps pages.', available: true, profiles: ['pre'] }], limits: profile_limits,
};
const wl = [{ key: 'raft', category: 'discovery', label: 'Raft small', lines: 1000, enabled: true }];

function mockApi(routes: Record<string, any>) {
  document.cookie = 'pa_csrf=tok';
  const calls: { method: string; path: string; body: any }[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    const path = String(url).replace('/api', ''); const method = init?.method ?? 'GET';
    calls.push({ method, path, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    if (path === '/auth/me') return json(200, me);
    const r = routes[`${method} ${path}`] ?? routes[path];
    return r instanceof Response ? r.clone() : r ? json(200, r) : json(404, { detail: 'No.' });
  });
  return calls;
}
const mount = (path: string) => render(<MemoryRouter initialEntries={[path]}><AuthProvider><ToastProvider><App /></ToastProvider></AuthProvider></MemoryRouter>);
afterEach(() => { vi.restoreAllMocks(); document.cookie = 'pa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

it('test_engine_slots_saved_with_reason', async () => {
  const calls = mockApi({ '/admin/capacity': { config, capacity, workers: [], history: [] }, 'PUT /admin/capacity': json(422, { detail: 'Only one scanning engine is provisioned.' }) });
  const user = userEvent.setup();
  mount('/admin/capacity');
  await user.selectOptions(await screen.findByLabelText(/Engine slots/), '2');
  await user.click(screen.getByRole('button', { name: 'Save configuration' }));
  const dlg = await screen.findByRole('alertdialog');
  const ok = within(dlg).getByRole('button', { name: 'Save configuration' }) as HTMLButtonElement;
  expect(ok.disabled).toBe(true);
  await user.type(within(dlg).getByLabelText(/Reason/), 'More engines');
  await user.click(ok);
  const put = calls.find((c) => c.method === 'PUT')!;
  expect(put.body.engine_slots).toBe(2);
  expect(put.body.reason).toBe('More engines');
  expect(put.body.profile_limits.pre.request_cap).toBe(5000);
  expect(await screen.findByText('Only one scanning engine is provisioned.')).toBeTruthy();
});

it('test_profile_limits_validation_inline', async () => {
  const calls = mockApi({ '/admin/capacity': { config, capacity, workers: [], history: [] } });
  const user = userEvent.setup();
  mount('/admin/capacity');
  const f = await screen.findByLabelText('Pre-Assessment: Requests per second');
  await user.clear(f); await user.type(f, '99');
  expect(screen.getByText('Enter a whole number from 1 to 50.')).toBeTruthy();
  expect((screen.getByRole('button', { name: 'Save configuration' }) as HTMLButtonElement).disabled).toBe(true);
  expect(calls.some((c) => c.method === 'PUT')).toBe(false);
});

it('test_wordlist_toggle_requires_reason', async () => {
  const calls = mockApi({ '/catalog': catalog, '/admin/capacity': { config, capacity, workers: [], history: [] }, '/admin/wordlists': wl, 'PUT /admin/wordlists': { ...wl[0], enabled: false } });
  const user = userEvent.setup();
  mount('/admin/profiles');
  await user.click(await screen.findByRole('button', { name: 'Disable Raft small' }));
  const dlg = await screen.findByRole('alertdialog');
  const ok = within(dlg).getByRole('button', { name: 'Disable wordlist' }) as HTMLButtonElement;
  expect(ok.disabled).toBe(true);
  await user.type(within(dlg).getByLabelText(/Reason/), 'Too noisy');
  await user.click(ok);
  expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({ key: 'raft', enabled: false, reason: 'Too noisy' });
  expect(screen.getAllByText('Crawler').length).toBeTruthy();
});
