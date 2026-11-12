import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { nextRuleId, stageIndex } from '../pages/admin/policyTypes';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

let me: Record<string, unknown> = { id: 'U-001', name: 'Ada Admin', email: 'ada@example.test', role: 'admin', team: null, must_change_password: false };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });

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

const doc = { rules: [
  { id: 'R-01', outcome: 'allow', match: 'suffix', value: 'example.com', note: 'Main' },
  { id: 'R-02', outcome: 'deny', match: 'domain', value: 'bad.example.com', note: '' },
], permitted_ports: [80, 443], no_match: 'approval' };
const published = { version: 'v1', status: 'published', document: doc, note: '', published_at: '2026-11-01T00:00:00Z', published_by: 'Ada', rules: 2, used_by: 1 };
const draft = (over = {}) => ({ version: 'v2', status: 'draft', document: doc, note: 'n', rev: 3, created_by: 'Ada', created_at: '2026-11-10T00:00:00Z', stage: 'draft', checks: null, dry_run: null, ...over });
const inv = ['Loopback is never allowed.'];

it('stageIndex and nextRuleId', () => {
  expect(stageIndex(null, false)).toBe(0);
  expect(stageIndex(draft({ stage: 'validated' }) as any, false)).toBe(1);
  expect(stageIndex(draft({ stage: 'dry-run' }) as any, false)).toBe(2);
  expect(stageIndex(null, true)).toBe(3);
  expect(nextRuleId([{ id: 'R-01' }, { id: 'R-09' }] as any)).toBe('R-10');
  expect(nextRuleId([])).toBe('R-01');
});

it('no draft: banner and Start new draft posts', async () => {
  const calls = mockApi({ '/admin/policies': { published, draft: null, invariants: inv }, 'POST /admin/policies/draft': json(201, draft()) });
  const user = userEvent.setup();
  mount('/admin/policies');
  expect(await screen.findByText('Published policy v1 is in force. Start a draft to change it; nothing changes until you publish.')).toBeTruthy();
  await user.click(screen.getByRole('button', { name: 'Start new draft' }));
  await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/admin/policies/draft')).toBe(true));
});

it('draft: add rule and move down send PUT with rev', async () => {
  const calls = mockApi({ '/admin/policies': { published, draft: draft(), invariants: inv }, 'PUT /admin/policies/draft': json(200, draft({ rev: 4 })) });
  const user = userEvent.setup();
  mount('/admin/policies');
  await user.click(await screen.findByRole('button', { name: 'Add rule' }));
  await user.type(screen.getByLabelText(/^Value/), 'new.example.org');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Add rule' }));
  await waitFor(() => expect(calls.filter((c) => c.method === 'PUT')).toHaveLength(1));
  const put = calls.find((c) => c.method === 'PUT')!.body;
  expect(put.rev).toBe(3);
  expect(put.document.rules[2]).toMatchObject({ id: 'R-03', value: 'new.example.org', outcome: 'approval', match: 'suffix' });
  await user.click(await screen.findByRole('button', { name: 'Move down R-01' }));
  await waitFor(() => expect(calls.filter((c) => c.method === 'PUT')).toHaveLength(2));
  expect(calls.filter((c) => c.method === 'PUT')[1].body.document.rules.map((r: any) => r.id)).toEqual(['R-02', 'R-01']);
});

it('structured config: 422 errors are shown and only the import is sent', async () => {
  const calls = mockApi({ '/admin/policies': { published, draft: draft(), invariants: inv }, 'POST /admin/policies/draft/import': json(422, { detail: 'Bad.', errors: ['R-01: unknown match type.'] }) });
  const user = userEvent.setup();
  mount('/admin/policies?tab=json');
  await user.click(await screen.findByRole('button', { name: 'Validate & apply to draft' }));
  expect(await screen.findByText('R-01: unknown match type.')).toBeTruthy();
  expect(calls.filter((c) => c.method !== 'GET').map((c) => c.path)).toEqual(['/admin/policies/draft/import']);
});

it('FastAPI list-style 422 does not crash', async () => {
  mockApi({ '/admin/policies': { published, draft: draft(), invariants: inv }, 'PUT /admin/policies/draft': json(422, { detail: [{ msg: 'String should have at most 500 characters' }] }) });
  const user = userEvent.setup();
  mount('/admin/policies');
  await user.click(await screen.findByRole('button', { name: 'Save draft' }));
  expect(await screen.findByText('String should have at most 500 characters')).toBeTruthy();
});

it('dry run: changed rows highlighted; publish shows counts and posts rev', async () => {
  const row = (a: string, changed: boolean) => ({ assessment: a, name: a, target: 'https://x', env: 'Staging', owner: 'O', stored: 'allow', published: 'allow', draft: 'deny', changed, reset: changed });
  const d = draft({ stage: 'dry-run', checks: [], dry_run: { at: 'now', rows: [row('A-1', true), row('A-2', false)], changed: 1, resets: 1 } });
  const calls = mockApi({ '/admin/policies': { published, draft: d, invariants: inv }, 'POST /admin/policies/draft/publish': json(200, { version: 'v2', changed: 1, reset: 1, jobs_cancelled: 2 }) });
  const user = userEvent.setup();
  mount('/admin/policies');
  const r1 = (await screen.findByText('A-1')).closest('tr')!;
  expect(r1.className).toContain('row-changed');
  expect(screen.getByText('A-2').closest('tr')!.className).not.toContain('row-changed');
  await user.click(screen.getByRole('button', { name: 'Publish v2' }));
  const dlg = await screen.findByRole('alertdialog');
  expect(within(dlg).getByText('1 targets change outcome. 1 will need to be validated again and their queued scans cancelled. Running scans continue.')).toBeTruthy();
  await user.click(within(dlg).getByRole('button', { name: 'Publish v2' }));
  await waitFor(() => expect(calls.find((c) => c.path === '/admin/policies/draft/publish')?.body).toEqual({ rev: 3 }));
  expect(await screen.findByText('v2 published. 1 targets changed, 1 reset, 2 queued scans cancelled.')).toBeTruthy();
});

it('owner on /admin/policies sees the denied state', async () => {
  me = { ...me, role: 'owner' };
  mockApi({});
  mount('/admin/policies');
  expect(await screen.findByText(/limited to Platform Administrators/)).toBeTruthy();
});
