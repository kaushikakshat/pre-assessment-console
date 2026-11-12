import { useState } from 'react';
import { ApiError } from '../../lib/api';
import { Icon, useToast } from '../../components';
import type { AuditArea, AuditEvent, Job } from '../../lib/types';

export type AdminJob = Job & { owner: string; target: string };

export const AREAS: Record<AuditArea, string> = {
  auth: 'Sign-in', users: 'Users', assessment: 'Assessment', validation: 'Validation', job: 'Job',
  finding: 'Finding', capacity: 'Capacity', worker: 'Worker', approval: 'Approval',
  scheduler: 'Scheduler', system: 'System', cli: 'Command line',
};
const OUTCOME = {
  success: { label: 'Success', tone: 'ok', icon: 'check' }, blocked: { label: 'Blocked', tone: 'warn', icon: 'stop' }, failure: { label: 'Failed', tone: 'danger', icon: 'x' },
} as const;
export function OutcomeBadge({ outcome }: { outcome: AuditEvent['outcome'] }) {
  const o = OUTCOME[outcome] ?? { label: outcome, tone: 'neutral', icon: 'help' as const };
  return <span className={`badge tone-${o.tone}`}><Icon name={o.icon} size={12} />{o.label}</span>;
}

/** Runs one admin API call: busy flag, inline failure text, success toast. Resolves true on success. */
export function useAct() {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const run = async <R,>(fn: () => Promise<R>, ok: string | ((r: R) => string)) => {
    setBusy(true); setFailure(null); setError(null);
    try { const r = await fn(); toast(typeof ok === 'function' ? ok(r) : ok); return true; }
    catch (e) { setError(e instanceof ApiError ? e : null); setFailure(e instanceof ApiError ? e.detail : 'That did not work. Try again.'); return false; }
    finally { setBusy(false); }
  };
  return { busy, failure, error, run, clear: () => { setFailure(null); setError(null); } };
}
