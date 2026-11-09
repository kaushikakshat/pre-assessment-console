import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

const me = { id: 'U-001', name: 'Asha Rao', email: 'asha@example.test', role: 'owner', team: null, must_change_password: false };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });
const capacity = { active: 0, limit: 1, effective_limit: 1, queued: 0, healthy_workers: 1, ceiling: 3, blocked_reason: null };
const profiles = (up: boolean) => [
  { key: 'quick', name: 'Quick Scan', description: 'Fast checks.', modules: ['reach'], available: true, duration: '5–10 min', impact: 'Low' },
  { key: 'pre', name: 'Pre-Assessment', description: 'More checks.', modules: ['reach', 'crawl'], available: up, duration: '30 min', impact: 'Moderate' },
  { key: 'deep', name: 'Deep Scan', description: 'Signed-in testing.', modules: ['reach', 'dast'], available: up, duration: '3 h', impact: 'Higher' },
];
const catalog = (up = true) => ({
  profiles: profiles(up), modules: [{ key: 'reach', name: 'Reachability', description: 'd', available: true, profiles: ['quick'] }],
  limits: { pre: { budget_min: 30, request_cap: 5000, rate_per_s: 5 }, deep: { budget_min: 180, request_cap: 5000, rate_per_s: 10 } }, advisory_as_of: '2026-11-01',
  wordlists: [{ key: 'common', category: 'discovery', label: 'Common paths', lines: 4000 }, { key: 'big', category: 'discovery', label: 'Big paths', lines: 9000 }, { key: 'xss', category: 'fuzzing', label: 'XSS payloads', lines: 100 }],
});
const assessment = {
  id: 'A-0001', name: 'Shop', owner: { id: 'U-001', name: 'Asha Rao' }, target: 'https://shop.example.com', env: 'Staging', hosts: 'shop.example.com', paths: '/*', ports: '443',
  exclusions: '', notes: null, status: 'active', validation: { outcome: 'allowed', checks: [], normalized_target: 'https://shop.example.com/', policy_version: 'v1', decided_at: '2026-11-09T08:50:00Z' },
  approval: null, active_job_id: null, created_at: '2026-11-09T08:00:00Z', updated_at: '2026-11-09T08:00:00Z', access: 'owner',
};
const setup = (o = {}) => ({ style: 'single', login_url: 'https://shop.example.com/login', username_field: 'u', password_field: 'p', code_field: null, otp_url: null, otp_field: null, logged_in_indicator: 'Log out', logged_out_indicator: null, bypass_code_set: true, updated_at: '2026-11-09T08:00:00Z', ...o });

type Handler = (method: string, body: any) => Response | undefined;
function mockApi(routes: Record<string, Handler | object>) {
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
    return r ? json(200, r) : json(404, { detail: 'No.' });
  });
  return calls;
}
const mount = (path: string) => render(<MemoryRouter initialEntries={[path]}><AuthProvider><ToastProvider><App /></ToastProvider></AuthProvider></MemoryRouter>);
const base = { '/queue': { capacity, mine: [], platform: [], recent: [] }, '/assessments/A-0001': assessment, '/assessments/A-0001/jobs': [], '/assessments/A-0001/findings': [] };
afterEach(() => { vi.restoreAllMocks(); document.cookie = 'pa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

describe('sign-in tab', () => {
  it('test_two_step_shows_otp_fields', async () => {
    mockApi({ ...base, '/catalog': catalog(), '/assessments/A-0001/signin': { setup: null, accounts: [] } });
    mount('/assessments/A-0001?tab=signin');
    const user = userEvent.setup();
    await screen.findByText('Sign-in setup');
    expect(screen.queryByLabelText(/OTP page URL/)).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Password then OTP page' }));
    expect(screen.getByLabelText(/OTP page URL/)).toBeTruthy();
    expect(screen.getByLabelText(/OTP field name/)).toBeTruthy();
  });

  it('test_password_never_rendered_after_save', async () => {
    const calls = mockApi({ ...base, '/catalog': catalog(), '/assessments/A-0001/signin': { setup: setup(), accounts: [{ id: 'C-1', role_label: 'Admin', username_hint: 'ad•••', last_test: 'ok', last_tested_at: '2026-11-09T08:00:00Z' }] },
      'PUT /assessments/A-0001/signin': () => json(200, setup()),
      'POST /assessments/A-0001/accounts': () => json(201, { id: 'C-2', role_label: 'User', username_hint: 'us•••', last_test: null, last_tested_at: null, test_result: null }) });
    mount('/assessments/A-0001?tab=signin');
    const user = userEvent.setup();
    expect(await screen.findByRole('button', { name: 'Replace bypass code' })).toBeTruthy(); // bypass code stored: no input
    expect(screen.queryByLabelText(/Bypass code/)).toBeNull();
    await user.click(screen.getByRole('button', { name: 'Add account' }));
    await user.type(screen.getByLabelText(/Role label/), 'User');
    await user.type(screen.getByLabelText(/^Username \*/), 'user1');
    const pw = screen.getByLabelText(/^Password \*/);
    expect(pw.getAttribute('type')).toBe('password');
    expect(pw.getAttribute('autocomplete')).toBe('new-password');
    await user.type(pw, 'S3cret-pw!');
    await user.click(screen.getByRole('button', { name: 'Save account' }));
    await screen.findByText('Account saved. It has not been tested.');
    expect('bypass_code' in calls.find((c) => c.method === 'POST')!.body).toBe(false);
    expect(document.body.innerHTML).not.toContain('S3cret-pw!');
    expect((document.body as HTMLElement).querySelectorAll('input[value="S3cret-pw!"]').length).toBe(0);
  });

  it('setup PUT omits bypass_code unless typed; unmapped 422 fields reach a banner', async () => {
    let n = 0;
    const calls = mockApi({ ...base, '/catalog': catalog(), '/assessments/A-0001/signin': { setup: setup({ style: 'two-step' }), accounts: [] },
      'PUT /assessments/A-0001/signin': () => (n++ ? json(200, setup()) : json(422, { detail: { fields: { otp_url: 'The login page must be on an in-scope host.', port: 'Port not permitted.' } } })) });
    mount('/assessments/A-0001?tab=signin');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Save sign-in setup' }));
    expect(await screen.findByText('Port not permitted.')).toBeTruthy();
    await user.click(screen.getByRole('button', { name: 'Save sign-in setup' }));
    await waitFor(() => expect(calls.filter((c) => c.method === 'PUT').length).toBe(2));
    const put = calls.find((c) => c.method === 'PUT')!.body;
    expect('bypass_code' in put).toBe(false);
    expect(put.code_field).toBeNull();
  });

  it('test_test_signin_requires_authorization_checkbox', async () => {
    const calls = mockApi({ ...base, '/catalog': catalog(), '/assessments/A-0001/signin': { setup: setup({ style: 'two-step' }), accounts: [] },
      'POST /assessments/A-0001/accounts': () => json(429, { detail: 'Wait before testing sign-in again.' }) });
    mount('/assessments/A-0001?tab=signin');
    const user = userEvent.setup();
    await user.click(await screen.findByRole('button', { name: 'Add account' }));
    await user.type(screen.getByLabelText(/Role label/), 'Admin');
    await user.type(screen.getByLabelText(/^Username \*/), 'root');
    await user.type(screen.getByLabelText(/^Password \*/), 'pw');
    await user.click(screen.getByLabelText('Test sign-in now'));
    expect(screen.getByLabelText(/Bypass code \(used for this test only, never stored\)/).getAttribute('type')).toBe('password');
    const save = screen.getByRole('button', { name: 'Save and test' });
    expect((save as HTMLInputElement).disabled).toBe(true);
    await user.click(screen.getByLabelText(/I confirm I am authorized/));
    expect((save as HTMLInputElement).disabled).toBe(false);
    await user.type(screen.getByLabelText(/Bypass code \(used/), '123456');
    await user.click(save);
    expect(await screen.findByText('Wait before testing sign-in again.')).toBeTruthy();
    expect(calls.find((c) => c.method === 'POST')!.body).toMatchObject({ test: true, authorized: true, bypass_code: '123456' });
    expect((screen.getByLabelText(/^Password \*/) as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText(/^Username \*/) as HTMLInputElement).value).toBe('root');
  });
});

async function toConfigure(up = true) {
  const calls = mockApi({ ...base, '/catalog': catalog(up), '/assessments/A-0001/signin': { setup: setup(), accounts: [{ id: 'C-1', role_label: 'Admin', username_hint: 'ad•••', last_test: 'ok', last_tested_at: null }] },
    'POST /jobs': () => json(422, { detail: { fields: { wordlists: 'This selection needs about 9,000 requests; the limit for this profile is 5,000.' } } }) });
  mount('/assessments/A-0001/scan');
  return { calls, user: userEvent.setup() };
}

describe('wizard', () => {
  it('test_deep_disabled_when_engine_down', async () => {
    await toConfigure(false);
    expect((await screen.findByRole('radio', { name: /Deep Scan/ }) as HTMLInputElement).disabled).toBe(true);
    expect(screen.getAllByText('The scanning engine is not running.')).toHaveLength(2);
  });

  it('test_fuzzing_disabled_unless_deep', async () => {
    const { user } = await toConfigure();
    await user.click(await screen.findByRole('radio', { name: /Pre-Assessment/ }));
    const adv = screen.getByRole('button', { name: 'Advanced' });
    expect(adv.getAttribute('aria-expanded')).toBe('false');
    await user.click(adv);
    expect(adv.getAttribute('aria-expanded')).toBe('true');
    expect((screen.getByLabelText(/XSS payloads/) as HTMLInputElement).disabled).toBe(true);
    expect(screen.getByText('Fuzzing runs only in Deep Scan.')).toBeTruthy();
    await user.click(screen.getByRole('radio', { name: /Deep Scan/ }));
    expect((screen.getByLabelText(/XSS payloads/) as HTMLInputElement).disabled).toBe(false);
    expect(screen.getByLabelText(/Admin · ad•••/)).toBeTruthy();
    await user.click(screen.getByLabelText(/XSS payloads/));
    expect(screen.getByText('About 1,000 extra requests')).toBeTruthy();
  });

  it('test_over_cap_disables_continue', async () => {
    const { user, calls } = await toConfigure();
    await user.click(await screen.findByRole('radio', { name: /Pre-Assessment/ }));
    await user.click(screen.getByRole('button', { name: 'Advanced' }));
    await user.click(screen.getByLabelText(/Common paths/));
    expect(screen.getByText('About 4,000 extra requests')).toBeTruthy();
    expect(screen.getByText(/Stops after 30 minutes and reports what it found/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Continue to review' }) as HTMLInputElement).disabled).toBe(false);
    await user.click(screen.getByLabelText(/Big paths/));
    expect(screen.getByText(/needs about 13,000 requests; the limit for this profile is 5,000/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Continue to review' }) as HTMLInputElement).disabled).toBe(true);
    await user.click(screen.getByLabelText(/Big paths/));
    await user.click(screen.getByRole('button', { name: 'Continue to review' }));
    await user.click(await screen.findByLabelText(/I confirm I am authorized/));
    await user.click(screen.getByRole('button', { name: 'Submit scan' }));
    await waitFor(() => expect(calls.find((c) => c.path === '/jobs')!.body).toMatchObject({ profile: 'pre', wordlists: ['common'] }));
    expect(await screen.findByText(/This selection needs about 9,000 requests/)).toBeTruthy();
  });
});
