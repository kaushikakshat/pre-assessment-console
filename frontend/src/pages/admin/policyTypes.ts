export type Outcome = 'allow' | 'approval' | 'deny';
export type Match = 'suffix' | 'domain' | 'ip' | 'cidr' | 'env';
export interface Rule { id: string; outcome: Outcome; match: Match; value: string; note: string; internal?: boolean; dev_only?: boolean }
export interface PolicyDoc { rules: Rule[]; permitted_ports: number[]; no_match: Outcome }
export interface Check { key: string; label: string; result: 'pass' | 'warn' | 'fail'; detail: string }
export interface DryRow { assessment: string; name: string; target: string; env: string; owner: string; stored: string; published: string; draft: string; changed: boolean; reset: boolean }
export interface Draft {
  version: string; status: string; document: PolicyDoc; note: string; rev: number; created_by: string; created_at: string;
  stage: 'draft' | 'validated' | 'dry-run'; checks: Check[] | null;
  dry_run: { at: string; rows: DryRow[]; changed: number; resets: number } | null;
}
export interface VersionInfo { version: string; status: string; document: PolicyDoc; note: string; published_at: string; published_by: string; rules: number; used_by: number }

export const OUTCOME_LABEL: Record<string, string> = { allow: 'Allow', approval: 'Needs approval', deny: 'Deny' };
export const MATCH_LABEL: Record<Match, string> = { suffix: 'Hostname suffix', domain: 'Exact domain', ip: 'IP address', cidr: 'CIDR range', env: 'Environment' };

/** Stepper position: Draft, Validated, Dry run, Published. */
export const stageIndex = (d: Draft | null, published: boolean): 0 | 1 | 2 | 3 =>
  published ? 3 : d?.stage === 'dry-run' ? 2 : d?.stage === 'validated' ? 1 : 0;

export const nextRuleId = (rules: Rule[]) =>
  `R-${String(Math.max(0, ...rules.map((r) => Number(r.id.slice(2)) || 0)) + 1).padStart(2, '0')}`;

/** Rules are matched by id; a rule is changed when any field or its position differs. */
export function diffPolicies(a: PolicyDoc, b: PolicyDoc) {
  const ids = (d: PolicyDoc) => d.rules.map((r) => r.id);
  const added = b.rules.filter((r) => !ids(a).includes(r.id));
  const removed = a.rules.filter((r) => !ids(b).includes(r.id));
  const changed = a.rules.flatMap((from, i) => {
    const j = ids(b).indexOf(from.id);
    return j >= 0 && (j !== i || JSON.stringify(Object.entries(from).sort()) !== JSON.stringify(Object.entries(b.rules[j]).sort())) ? [{ id: from.id, from, to: b.rules[j] }] : [];
  });
  const pa = a.permitted_ports, pb = b.permitted_ports;
  return {
    added, removed, changed,
    ports: { added: pb.filter((p) => !pa.includes(p)), removed: pa.filter((p) => !pb.includes(p)) },
    noMatch: a.no_match === b.no_match ? null : { from: a.no_match, to: b.no_match },
  };
}
