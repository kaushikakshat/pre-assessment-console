export class ApiError extends Error {
  constructor(public status: number, public detail: string, public fields?: Record<string, string>, public errors?: string[]) {
    super(detail);
  }
}

let onUnauthorized: (() => void) | null = null;
/** AuthContext registers this so any 401 from a non-auth endpoint signs the user out. */
export const setUnauthorizedHandler = (fn: (() => void) | null) => { onUnauthorized = fn; };

let onPasswordRequired: (() => void) | null = null;
/** AuthContext registers this so a 403 "change your temporary password" sends the user to the change-password page. */
export const setPasswordRequiredHandler = (fn: (() => void) | null) => { onPasswordRequired = fn; };
export const PASSWORD_REQUIRED = 'Change your temporary password to continue.';

const csrfCookie = () => document.cookie.split('; ').find((c) => c.startsWith('pa_csrf='))?.slice(8);

async function send(path: string, method: string, body: unknown, headers: Record<string, string>) {
  return fetch(`/api${path}`, {
    method,
    credentials: 'include',
    headers: body === undefined ? headers : { ...headers, 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

export async function api<T = void>(path: string, opts: { method?: string; body?: unknown; onResponse?: (r: Response) => void } = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = {};
  if (method !== 'GET') {
    // Before sign-in no CSRF cookie exists yet; ask the server to set it.
    if (!csrfCookie()) await send('/auth/csrf', 'GET', undefined, {});
    const token = csrfCookie();
    if (token) headers['X-CSRF-Token'] = decodeURIComponent(token);
  }
  let res: Response;
  try {
    res = await send(path, method, opts.body, headers);
  } catch {
    throw new ApiError(0, 'The service is not reachable. Check your connection and try again.');
  }
  if (res.ok) opts.onResponse?.(res);
  if (res.ok) return (res.status === 204 ? undefined : await res.json()) as T;
  let detail = 'Something went wrong. Try again.';
  let fields: Record<string, string> | undefined;
  let errors: string[] | undefined;
  try {
    const j = await res.json();
    if (Array.isArray(j.errors)) errors = j.errors;
    if (typeof j.detail === 'string') detail = j.detail;
    else if (Array.isArray(j.detail)) detail = j.detail.map((d: { msg?: string }) => d.msg).filter(Boolean).join(' ') || detail; // FastAPI field validation
    else if (j.detail?.fields) { fields = j.detail.fields; detail = 'Check the highlighted fields.'; }
  } catch { /* non-JSON error body: keep the generic sentence */ }
  if (res.status === 401 && !path.startsWith('/auth/')) onUnauthorized?.();
  if (res.status === 403 && detail === PASSWORD_REQUIRED) onPasswordRequired?.();
  throw new ApiError(res.status, detail, fields, errors);
}
