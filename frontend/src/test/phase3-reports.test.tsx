import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

const me = { id: 'U-001', name: 'Asha Rao', email: 'asha@example.test', role: 'owner', team: null, must_change_password: false };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });
const capacity = { active: 0, limit: 1, effective_limit: 1, queued: 0, healthy_workers: 1, ceiling: 3, blocked_reason: null };
const assessment = {
  id: 'A-0001', name: 'Shop', owner: { id: 'U-001', name: 'Asha Rao' }, target: 'https://shop.example.com', env: 'Staging', hosts: 'shop.example.com', paths: '/*', ports: '443',
  exclusions: '', notes: null, status: 'active', validation: null, approval: null, active_job_id: null, created_at: '2026-11-09T08:00:00Z', updated_at: '2026-11-09T08:00:00Z', access: 'owner',
};
const job = (id: string, state: string) => ({ id, seq: 1, assessment_id: 'A-0001', assessment_name: 'Shop', type: 'scan', profile: 'quick', priority: 'Normal', state, submitted_at: '2026-11-09T08:00:00Z', started_at: null, ended_at: '2026-11-09T08:30:00Z', policy_version: 'v1', requested_by: 'Asha Rao', note: null, resume_of: null, review: null, modules: [], queue_position: null, wait_estimate: null });
const finding = (id: string, state: string) => ({ id, assessment_id: 'A-0001', job_id: 'JOB-1', severity: 'high', confidence: 'confirmed', state, module: 'headers', title: `Title ${id}`, asset: '/', first_seen_at: '2026-11-09T08:00:00Z', last_seen_at: '2026-11-09T08:00:00Z' });
const report = (id: string, state: string) => ({ id, assessment_id: 'A-0001', job_id: 'JOB-1', type: 'management', version: 1, state, created_at: '2026-11-09T09:00:00Z', requested_by: 'Asha Rao' });

function mockApi(routes: Record<string, unknown>) {
  document.cookie = 'pa_csrf=tok';
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    const path = String(url).replace('/api', '');
    if (path === '/auth/me') return json(200, me);
    const r = routes[`${init?.method ?? 'GET'} ${path}`] ?? routes[path];
    return r ? json(200, r) : json(404, { detail: 'No.' });
  });
}
const base = {
  '/queue': { capacity, mine: [], platform: [], recent: [] }, '/catalog': { modules: [], profiles: [] }, '/assessments/A-0001': assessment,
  '/assessments/A-0001/jobs': [job('JOB-2', 'running'), job('JOB-1', 'completed'), job('JOB-0', 'failed')],
  '/assessments/A-0001/findings': [finding('F-1', 'open'), finding('F-2', 'false-positive')],
  '/jobs/JOB-2': job('JOB-2', 'running'),
};
const mount = (path: string) => render(<MemoryRouter initialEntries={[path]}><AuthProvider><ToastProvider><App /></ToastProvider></AuthProvider></MemoryRouter>);

afterEach(() => vi.restoreAllMocks());

const WATERMARK = 'PRE-ASSESSMENT RESULTS — not a penetration test, statutory certificate or security clearance. Results are not exhaustive and may include false positives.';

test('test_retest_confirm_disabled_until_checked', async () => {
  mockApi(base);
  mount('/assessments/A-0001?tab=findings');
  const u = userEvent.setup();
  await u.click(await screen.findByRole('tab', { name: /Findings/ }));
  await u.click(await screen.findByRole('checkbox', { name: 'Select F-1' }));
  await u.click(screen.getByRole('button', { name: 'Request retest (1)' }));
  const dlg = await screen.findByRole('dialog');
  expect(within(dlg).getByText(/will be marked/)).toBeTruthy();
  const queue = within(dlg).getByRole('button', { name: 'Queue retest' });
  expect((queue as HTMLButtonElement).disabled).toBe(true);
  await u.click(within(dlg).getByRole('checkbox', { name: /still authorized/ }));
  expect((queue as HTMLButtonElement).disabled).toBe(false);
});

test('test_false_positive_row_not_selectable', async () => {
  mockApi(base);
  mount('/assessments/A-0001');
  const u = userEvent.setup();
  await u.click(await screen.findByRole('tab', { name: /Findings/ }));
  expect(((await screen.findByRole('checkbox', { name: 'Select F-2' })) as HTMLInputElement).disabled).toBe(true);
  expect((screen.getByRole('checkbox', { name: 'Select F-1' }) as HTMLInputElement).disabled).toBe(false);
});

test('test_generate_lists_only_finished_jobs', async () => {
  mockApi({ ...base, '/assessments/A-0001/reports': [] });
  mount('/assessments/A-0001');
  const u = userEvent.setup();
  await u.click(await screen.findByRole('button', { name: 'Generate report' }));
  const sel = await screen.findByRole('combobox', { name: 'Based on scan' });
  expect(within(sel).getAllByRole('option').map((o) => o.textContent)).toEqual([expect.stringContaining('JOB-1')]);
  expect(screen.getByText(/TBD · OD-8/)).toBeTruthy();
});

test('test_report_failed_shows_banner_and_retry', async () => {
  mockApi({ ...base, '/assessments/A-0001/reports': [report('R-0001', 'failed'), report('R-0002', 'ready')], 'POST /reports/R-0001/retry': report('R-0001', 'generating') });
  mount('/assessments/A-0001');
  const u = userEvent.setup();
  await u.click(await screen.findByRole('tab', { name: /Reports/ }));
  expect(await screen.findByText(/Report generation failed — your assessment results are unchanged/)).toBeTruthy();
  const pdf = screen.getByRole('link', { name: /^Export PDF/ });
  expect(pdf.getAttribute('href')).toBe('/api/reports/R-0002/pdf');
  expect(pdf.hasAttribute('download')).toBe(true);
  await u.click(screen.getByRole('button', { name: /^Retry/ }));
  await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/reports/R-0001/retry', expect.objectContaining({ method: 'POST' })));
});

test('test_preview_shows_all_seven_categories_and_watermark', async () => {
  const labels = ['Confirmed', 'Suspected', 'False positive', 'Unresolved', 'Blocked', 'Skipped', 'Not tested'];
  mockApi({ '/reports/R-0002': { ...report('R-0002', 'ready'), model: {
    header: { product: 'Pre-Assessment Platform', classification: 'TBD · OD-8' },
    title: { assessment: 'Shop', type: 'Management summary', report_id: 'R-0002', version: 1, generated_at: 'x', by: 'Asha Rao' },
    watermark: WATERMARK,
    categories: labels.map((l, i) => ({ key: l, label: l, count: i })), modules: [], findings_overview: [], limitations: 'None.',
  } } });
  mount('/reports/R-0002');
  const table = await screen.findByRole('table', { name: 'Result categories' });
  for (const l of labels) expect(within(table).getByText(l)).toBeTruthy();
  expect(screen.getByRole('note').textContent).toBe(WATERMARK);
  expect(screen.getByRole('link', { name: /^Export PDF/ })).toBeTruthy();
});

test('test_technical_preview_renders_summary_and_details_without_raw_json', async () => {
  const loc = { url: 'https://shop.example.com/admin', host: 'shop.example.com', port: '443', path: '/admin', param: null, method: 'GET', component: null, kind: 'Web page' };
  mockApi({ '/reports/R-0003': { ...report('R-0003', 'ready'), type: 'technical', model: {
    watermark: WATERMARK,
    summary: { by_severity: { critical: 0, high: 3, medium: 2, low: 1, info: 0 }, total: 6, still_open: 4 },
    findings_overview: [{ n: 1, id: 'F-1', severity: 'high', title: 'Admin exposed', location: '/admin', confidence: 'confirmed', state: 'open' }],
    details: [{ id: 'F-1', severity: 'high', confidence: 'confirmed', state: 'open', title: 'Admin exposed', location: loc, description: 'Desc text', impact: 'Impact text',
      evidence: 'Authorization: [redacted]', reproduce: 'Open it', remediation: 'Restrict it', references: ['https://owasp.org/x'], history: [{ at: '2026-11-09T08:00:00Z', by: 'system', text: 'Found in JOB-1' }] }],
  } } });
  const { container } = mount('/reports/R-0003');
  const sum = (await screen.findByText('6 total')).closest('section')!;
  expect(sum.textContent).toMatch(/High\s*3/);
  expect(sum.textContent).toContain('4 still open');
  expect(screen.getAllByText('/admin').length).toBeGreaterThan(0);
  expect(screen.getByText('Authorization: [redacted]')).toBeTruthy();
  expect(screen.getByText('Found in JOB-1')).toBeTruthy();
  expect(screen.getByRole('link', { name: 'https://owasp.org/x' })).toBeTruthy();
  expect(container.textContent).not.toContain('{');
});
