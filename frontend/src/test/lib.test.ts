import { can, type Action, type AccessLevel } from '../lib/perm';
import { VOCAB } from '../lib/status';
import { formatIST, relativeTime } from '../lib/format';
import { api, ApiError } from '../lib/api';
import { ICON_NAMES } from '../components/Icon';
import {
  ASSESSMENT_STATUSES, CHECK_RESULTS, FINDING_STATES, JOB_STATES, MODULE_STATES, VALIDATION_OUTCOMES, WORKER_STATUSES,
} from '../lib/types';

describe('can() matrix (§11.2)', () => {
  const rows: [Action, boolean, boolean, boolean][] = [
    // action, owner, view, admin
    ['view', true, true, true],
    ['export-report', true, true, true],
    ['generate-report', true, false, true],
    ['change-finding-state', true, false, false],
    ['comment', true, false, false],
    ['retest', true, false, false],
    ['new-scan', true, false, false],
    ['share', true, false, false],
    ['sharing-tab', true, false, false],
    ['activity-tab', true, false, true],
  ];
  it.each(rows)('%s', (action, owner, view, admin) => {
    expect(can('owner', action)).toBe(owner);
    expect(can('view', action)).toBe(view);
    expect(can('admin', action)).toBe(admin);
  });
  it('denies everything without access', () => {
    for (const [action] of rows) expect(can(null as AccessLevel | null, action)).toBe(false);
  });
});

describe('status vocabularies (§5)', () => {
  const keys = (o: object) => Object.keys(o).sort();
  it('cover every API enum value', () => {
    expect(keys(VOCAB.job)).toEqual([...JOB_STATES].sort());
    expect(keys(VOCAB.module)).toEqual([...MODULE_STATES].sort());
    expect(keys(VOCAB.finding)).toEqual([...FINDING_STATES].sort());
    expect(keys(VOCAB.validation)).toEqual([...VALIDATION_OUTCOMES].sort());
    expect(keys(VOCAB.check)).toEqual([...CHECK_RESULTS].sort());
    expect(keys(VOCAB.assessment)).toEqual(ASSESSMENT_STATUSES.filter((s) => s !== 'active').sort());
    for (const w of WORKER_STATUSES) expect(VOCAB.worker[w]).toBeDefined();
  });
  it('only uses defined icons and never shows an interrupted state as ok', () => {
    for (const kind of Object.values(VOCAB)) for (const d of Object.values(kind)) expect(ICON_NAMES).toContain(d.icon);
    expect(VOCAB.job.interrupted.tone).not.toBe('ok');
    expect(VOCAB.module.inconclusive.tone).not.toBe('ok');
    expect(VOCAB.job.interrupted.label).toBe('Interrupted · needs review');
  });
});

describe('format', () => {
  it('shows IST dates', () => {
    expect(formatIST('2026-11-02T08:50:00Z')).toBe('02 Nov 2026, 14:20 IST');
    expect(formatIST('2026-12-31T20:00:00Z')).toBe('01 Jan 2027, 01:30 IST');
  });
  it('shows relative time', () => {
    const now = Date.parse('2026-11-02T12:00:00Z');
    expect(relativeTime('2026-11-02T11:55:00Z', now)).toBe('5 min ago');
    expect(relativeTime('2026-11-02T11:59:50Z', now)).toBe('just now');
    expect(relativeTime('2026-11-02T07:00:00Z', now)).toBe('5 h ago');
    expect(relativeTime('2026-10-30T12:00:00Z', now)).toBe('3 d ago');
  });
});

describe('api()', () => {
  const json = (status: number, body?: unknown) => new Response(body === undefined ? null : JSON.stringify(body), { status });
  afterEach(() => { vi.restoreAllMocks(); document.cookie = 'pa_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT'; });

  it('sends cookies, and the CSRF header only on non-GET', async () => {
    document.cookie = 'pa_csrf=tok123';
    const f = vi.spyOn(globalThis, 'fetch').mockImplementation(async () => json(200, { ok: 1 }));
    await api('/assessments');
    await api('/assessments', { method: 'POST', body: { name: 'x' } });
    const [get, post] = f.mock.calls.map((c) => c[1] as RequestInit);
    expect(get.credentials).toBe('include');
    expect((get.headers as Record<string, string>)['X-CSRF-Token']).toBeUndefined();
    expect((post.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok123');
    expect(post.body).toBe('{"name":"x"}');
  });

  it('fetches a CSRF cookie first when none exists', async () => {
    const f = vi.spyOn(globalThis, 'fetch').mockImplementation(async (url) => {
      if (url === '/api/auth/csrf') document.cookie = 'pa_csrf=fresh';
      return json(204);
    });
    await api('/auth/logout', { method: 'POST' });
    expect(f.mock.calls[0][0]).toBe('/api/auth/csrf');
    expect(((f.mock.calls[1][1] as RequestInit).headers as Record<string, string>)['X-CSRF-Token']).toBe('fresh');
  });

  it('parses {detail} and field errors into ApiError', async () => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(json(401, { detail: 'The email or password is incorrect.' }))
      .mockResolvedValueOnce(json(422, { detail: { fields: { target: 'Use http or https.' } } }));
    await expect(api('/auth/me')).rejects.toMatchObject({ status: 401, detail: 'The email or password is incorrect.' });
    const e = await api('/auth/me').catch((x) => x);
    expect(e).toBeInstanceOf(ApiError);
    expect(e.fields).toEqual({ target: 'Use http or https.' });
  });
});
