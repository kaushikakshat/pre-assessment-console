import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { App } from '../App';
import { AuthProvider } from '../auth/AuthContext';
import { ToastProvider } from '../components';

const me = { id: 'U-001', name: 'Asha Rao', email: 'asha@example.test', role: 'owner', team: null, must_change_password: false };
const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });
const dash = { counts: { assessments: 2, open_findings: 0, active_jobs: 1 }, active_job: null, recent: [], capacity: { active: 0, limit: 1, effective_limit: 1, queued: 0, healthy_workers: 1, ceiling: 3, blocked_reason: null } };

function mount(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider><ToastProvider><App /></ToastProvider></AuthProvider>
    </MemoryRouter>,
  );
}
const fill = async (user: ReturnType<typeof userEvent.setup>, next: string, confirm: string) => {
  await user.type(await screen.findByLabelText(/Current password/), 'temp-pass');
  await user.type(screen.getByLabelText(/^New password/), next);
  await user.type(screen.getByLabelText(/Confirm new password/), confirm);
};

beforeEach(() => { document.cookie = 'pa_csrf=tok'; });
afterEach(() => { vi.restoreAllMocks(); document.cookie = 'pa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

it('sends every route to the change-password page while the flag is set, without navigation', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    String(url) === '/api/auth/me' ? json(200, { ...me, must_change_password: true }) : json(403, { detail: 'Change your temporary password to continue.' }));
  mount('/assessments');
  expect(await screen.findByRole('heading', { name: 'Change password' })).toBeTruthy();
  expect(screen.getByText('Choose a new password to continue')).toBeTruthy();
  expect(screen.queryByRole('navigation', { name: 'Main' })).toBeNull();
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeTruthy();
});

it('blocks submit when the confirmation does not match', async () => {
  const f = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => (String(url) === '/api/auth/me' ? json(200, me) : json(404, { detail: 'No.' })));
  const user = userEvent.setup();
  mount('/account/password');
  await fill(user, 'a brand new pass', 'something else!!');
  await user.click(screen.getByRole('button', { name: 'Change password' }));
  expect(await screen.findByText('The passwords do not match.')).toBeTruthy();
  expect(f.mock.calls.some((c) => c[0] === '/api/auth/password')).toBe(false);
});

it('updates the user and lands on the dashboard after a successful change', async () => {
  let changed = false;
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
    const p = String(url);
    if (p === '/api/auth/me') return json(200, { ...me, must_change_password: true });
    if (p === '/api/auth/password') { changed = true; return json(200, me); }
    if (p === '/api/dashboard') return json(200, dash);
    return json(404, { detail: 'No.' });
  });
  const user = userEvent.setup();
  mount('/dashboard');
  await fill(user, 'a brand new pass', 'a brand new pass');
  await user.click(screen.getByRole('button', { name: 'Change password' }));
  expect(await screen.findByRole('heading', { name: 'Dashboard' })).toBeTruthy();
  expect(changed).toBe(true);
  expect(await screen.findByText('Password changed. Other sessions were signed out.')).toBeTruthy();
  expect(screen.getByRole('navigation', { name: 'Main' })).toBeTruthy();
});

it('shows a server field error inline', async () => {
  vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) =>
    String(url) === '/api/auth/password' ? json(422, { detail: { fields: { new_password: 'Use at least 12 characters.' } } }) : String(url) === '/api/auth/me' ? json(200, me) : json(404, { detail: 'No.' }));
  const user = userEvent.setup();
  mount('/account/password');
  await fill(user, 'short', 'short');
  await user.click(screen.getByRole('button', { name: 'Change password' }));
  expect(await screen.findByText('Use at least 12 characters.')).toBeTruthy();
});
