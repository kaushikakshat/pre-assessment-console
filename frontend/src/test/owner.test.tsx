import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

const me = { id: 'U-001', name: 'Asha Rao', email: 'asha@example.test', role: 'owner', team: null };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });
const capacity = { active: 0, limit: 1, effective_limit: 1, queued: 0, healthy_workers: 1, ceiling: 3, blocked_reason: null };
const catalog = {
  profiles: [{ key: 'quick', name: 'Quick Scan', description: 'Fast checks.', modules: ['reach', 'ports'], available: true, duration: '5–10 min', impact: 'Low' },
    { key: 'pre', name: 'Pre-Assessment', description: 'More.', modules: ['reach'], available: false, duration: '—', impact: 'Moderate' }],
  modules: [{ key: 'reach', name: 'Reachability', description: 'd', available: true, profiles: ['quick'] }, { key: 'ports', name: 'Ports', description: 'd', available: true, profiles: ['quick'] }],
};
const assessment = {
  id: 'A-0001', name: 'Shop', owner: { id: 'U-001', name: 'Asha Rao' }, target: 'https://shop.example.com', env: 'Staging', hosts: 'shop.example.com', paths: '/*', ports: '443',
  exclusions: '', notes: null, status: 'active', validation: { outcome: 'allowed', checks: [], normalized_target: 'https://shop.example.com/', policy_version: 'v1', decided_at: '2026-11-09T08:50:00Z' },
  approval: null, active_job_id: null, created_at: '2026-11-09T08:00:00Z', updated_at: '2026-11-09T08:00:00Z', access: 'owner',
};
const finding = {
  id: 'F-1', assessment_id: 'A-0001', job_id: 'JOB-1', severity: 'high', confidence: 'confirmed', state: 'open', module: 'headers', title: 'Missing header', asset: '/', first_seen_at: '2026-11-09T08:00:00Z', last_seen_at: '2026-11-09T08:00:00Z',
  location: { url: 'https://shop.example.com/', host: 'shop.example.com', port: '443', path: '/', param: null, method: 'GET', component: null, kind: 'Web page' },
  description: 'desc', impact: 'imp', evidence: 'x [REDACTED]', reproduce: 'rep', remediation: 'fix', references: [], policy_version: 'v1', history: [], comments: [],
};

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
afterEach(() => { vi.restoreAllMocks(); document.cookie = 'pa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

async function toReview(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'Continue to review' }));
  await screen.findByRole('button', { name: 'Submit scan' });
}

it('wizard keeps Submit disabled until authorization is checked', async () => {
  mockApi({ '/assessments/A-0001': assessment, '/catalog': catalog, '/queue': { capacity } });
  const user = userEvent.setup();
  mount('/assessments/A-0001/scan');
  await toReview(user);
  const submit = screen.getByRole('button', { name: 'Submit scan' }) as HTMLButtonElement;
  expect(submit.disabled).toBe(true);
  await user.click(screen.getByLabelText(/I confirm I am authorized to test this target within the scope above\./));
  expect(submit.disabled).toBe(false);
});

it('submit answered with 503 shows the unavailable banner and no success', async () => {
  const calls = mockApi({
    '/assessments/A-0001': assessment, '/catalog': catalog, '/queue': { capacity },
    'POST /jobs': json(503, { detail: 'Down.' }),
  });
  const user = userEvent.setup();
  mount('/assessments/A-0001/scan');
  await toReview(user);
  await user.click(screen.getByLabelText(/I confirm I am authorized/));
  await user.click(screen.getByRole('button', { name: 'Submit scan' }));
  expect((await screen.findByRole('alert')).textContent).toContain('Service unavailable — your scan was not submitted. No job ID was returned, so nothing is queued. Check Scan Queue before trying again.');
  expect(screen.queryByText('Scan submitted')).toBeNull();
  const post = calls.find((c) => c.path === '/jobs')!;
  expect(post.body).toMatchObject({ assessment_id: 'A-0001', profile: 'quick', authorized: true });
  expect(typeof post.body.idempotency_key).toBe('string');
});

it('blocked validation shows exact copy and offers no continue button', async () => {
  mockApi({
    'POST /assessments': json(201, { ...assessment, status: 'draft', validation: null }),
    'POST /assessments/A-0001/validate': json(200, { outcome: 'blocked', checks: [{ key: 'url', label: 'URL normalised', result: 'fail', detail: 'Blocked.' }], normalized_target: 'http://10.0.0.1/', policy_version: 'v1', decided_at: '2026-11-09T08:50:00Z' }),
  });
  const user = userEvent.setup();
  mount('/assessments/new');
  await user.type(await screen.findByLabelText(/Assessment name/), 'Internal');
  await user.type(screen.getByLabelText(/Target URL/), 'http://10.0.0.1');
  await user.click(screen.getByRole('button', { name: 'Validate target' }));
  expect(await screen.findByText('Target validation failed — no scan traffic was sent.')).toBeTruthy();
  expect(screen.queryByRole('button', { name: /Continue to scan configuration/ })).toBeNull();
  expect(screen.getByRole('button', { name: 'Save as draft' })).toBeTruthy();
});

it('finding state change that needs a reason keeps confirm disabled until one is typed', async () => {
  const calls = mockApi({
    '/assessments/A-0001': assessment, '/assessments/A-0001/jobs': [], '/assessments/A-0001/findings': [finding], '/queue': { capacity },
    '/findings/F-1': finding,
    'POST /findings/F-1/state': { ...finding, state: 'false-positive' },
  });
  const user = userEvent.setup();
  mount('/assessments/A-0001?tab=findings&finding=F-1');
  await user.click(await screen.findByRole('button', { name: 'Mark false positive' }));
  const dialogConfirm = within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Mark false positive' }) as HTMLButtonElement;
  expect(dialogConfirm.disabled).toBe(true);
  await user.type(screen.getByLabelText(/Reason/), 'Test page only');
  expect(dialogConfirm.disabled).toBe(false);
  await user.click(dialogConfirm);
  await waitFor(() => expect(calls.find((c) => c.path === '/findings/F-1/state')?.body).toEqual({ action: 'false-positive', reason: 'Test page only' }));
});

it('shows DeniedState when the assessment returns 404', async () => {
  mockApi({ '/assessments/A-9': json(404, { detail: 'Not found.' }), '/assessments/A-9/jobs': json(404, { detail: 'x' }), '/assessments/A-9/findings': json(404, { detail: 'x' }), '/queue': { capacity } });
  mount('/assessments/A-9');
  expect(await screen.findByText("You don't have access to assessment A-9")).toBeTruthy();
});

it('a 401 from a data endpoint signs the user out', async () => {
  mockApi({ '/assessments': json(401, { detail: 'Not signed in.' }) });
  mount('/assessments');
  expect(await screen.findByLabelText(/Work email/)).toBeTruthy();
});
