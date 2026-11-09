import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

const me = { id: 'U-001', name: 'Asha Rao', email: 'asha@example.test', role: 'owner', team: null, must_change_password: false };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });

function mount(path = '/dashboard') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider><ToastProvider><App /></ToastProvider></AuthProvider>
    </MemoryRouter>,
  );
}

afterEach(() => { vi.restoreAllMocks(); document.cookie = 'pa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

it('signs in through password then MFA and lands on the dashboard', async () => {
  document.cookie = 'pa_csrf=tok';
  let signedIn = false;
  const calls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url, init) => {
    const path = String(url);
    calls.push(`${init?.method ?? 'GET'} ${path}`);
    if (path === '/api/auth/me') return signedIn ? json(200, me) : json(401, { detail: 'Not signed in.' });
    if (path === '/api/auth/login') return json(200, { next: 'mfa' });
    if (path === '/api/auth/mfa') { signedIn = true; return json(200, me); }
    if (path === '/api/dashboard') return json(200, { counts: { assessments: 2, open_findings: 0, active_jobs: 1 }, active_job: null, recent: [], capacity: { active: 0, limit: 1, effective_limit: 1, queued: 0, healthy_workers: 1, ceiling: 3, blocked_reason: null } });
    return json(404, { detail: 'No.' });
  });
  const user = userEvent.setup();
  mount();

  await user.type(await screen.findByLabelText(/Work email/), 'asha@example.test');
  await user.type(screen.getByLabelText(/Password/), 'correct horse');
  await user.click(screen.getByRole('button', { name: 'Sign in' }));

  const first = await screen.findByLabelText('Digit 1 of 6');
  await user.click(first);
  await user.keyboard('123456'); // auto-advance across the six inputs
  await user.click(screen.getByRole('button', { name: 'Verify' }));

  expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeTruthy();
  expect(await screen.findByText('Asha Rao')).toBeTruthy();
  expect(screen.queryByText('Admin mode')).toBeNull();
  const mfa = (vi.mocked(fetch).mock.calls.find((c) => c[0] === '/api/auth/mfa')![1] as RequestInit);
  expect(mfa.body).toBe('{"code":"123456"}');
  expect((mfa.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok');
});

it('shows the neutral server message on a wrong password', async () => {
  document.cookie = 'pa_csrf=tok';
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    String(url) === '/api/auth/login' ? json(401, { detail: 'The email or password is incorrect.' }) : json(401, { detail: 'Not signed in.' }));
  const user = userEvent.setup();
  mount();
  await user.type(await screen.findByLabelText(/Work email/), 'a@b.test');
  await user.type(screen.getByLabelText(/Password/), 'nope');
  await user.click(screen.getByRole('button', { name: 'Sign in' }));
  expect((await screen.findByRole('alert')).textContent).toContain('The email or password is incorrect.');
});

it('shows the denied state on admin routes for owners', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => (String(url) === '/api/auth/me' ? json(200, me) : json(500, { detail: 'x' })));
  mount('/admin/users');
  expect(await screen.findByText("You don't have access to the admin console")).toBeTruthy();
});
