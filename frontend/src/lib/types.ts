// Shapes and enums from docs/API.md. Enums are const arrays so tests can check vocabularies against them.
export const ROLES = ['owner', 'admin'] as const;
export const ENVIRONMENTS = ['Development', 'Staging', 'UAT', 'Production'] as const;
export const PROFILE_KEYS = ['quick', 'pre', 'deep'] as const;
export const MODULE_KEYS = ['reach', 'ports', 'tls', 'headers', 'exposed', 'finger', 'crawl', 'cms', 'config', 'dast', 'api', 'auth', 'access', 'cval'] as const;
export const JOB_STATES = ['queued', 'validating', 'scheduled', 'running', 'cancelling', 'completed', 'completed-warnings', 'failed', 'cancelled', 'blocked', 'interrupted'] as const;
export const MODULE_STATES = ['queued', 'running', 'completed', 'completed-warnings', 'skipped', 'blocked', 'failed', 'cancelled', 'unavailable', 'inconclusive', 'interrupted'] as const;
export const FINDING_STATES = ['new', 'open', 'under-review', 'false-positive', 'resolved', 'reopened', 'not-retested', 'accepted-risk'] as const;
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const CONFIDENCES = ['confirmed', 'suspected'] as const;
export const VALIDATION_OUTCOMES = ['allowed', 'approval', 'blocked'] as const;
export const CHECK_RESULTS = ['pass', 'warn', 'fail', 'skip'] as const;
export const CHECK_KEYS = ['url', 'dns', 'addresses', 'redirects', 'ports', 'rules', 'environment'] as const;
export const PRIORITIES = ['High', 'Normal', 'Low'] as const;
export const ASSESSMENT_STATUSES = ['draft', 'active', 'awaiting-approval', 'blocked'] as const;
export const WORKER_STATUSES = ['healthy', 'heartbeat-lost', 'standby'] as const;

export type Role = (typeof ROLES)[number];
export type Environment = (typeof ENVIRONMENTS)[number];
export type ProfileKey = (typeof PROFILE_KEYS)[number];
export type ModuleKey = (typeof MODULE_KEYS)[number];
export type JobState = (typeof JOB_STATES)[number];
export type ModuleState = (typeof MODULE_STATES)[number];
export type FindingState = (typeof FINDING_STATES)[number];
export type Severity = (typeof SEVERITIES)[number];
export type Confidence = (typeof CONFIDENCES)[number];
export type ValidationOutcome = (typeof VALIDATION_OUTCOMES)[number];
export type CheckResult = (typeof CHECK_RESULTS)[number];
export type CheckKey = (typeof CHECK_KEYS)[number];
export type Priority = (typeof PRIORITIES)[number];
export type AssessmentStatus = (typeof ASSESSMENT_STATUSES)[number];
export type WorkerStatus = (typeof WORKER_STATUSES)[number];
export type LocationKind = 'Web page' | 'API endpoint' | 'File' | 'Network service' | 'Cookie' | 'Response header' | 'TLS certificate';
export type AuditArea = 'auth' | 'users' | 'assessment' | 'validation' | 'job' | 'finding' | 'capacity' | 'worker' | 'approval' | 'scheduler' | 'system' | 'cli';

export interface User {
  id: string; name: string; email: string; role: Role; team: string | null;
  status: 'active' | 'deactivated'; mfa: 'enrolled' | 'pending'; last_login_at: string | null; sessions: number;
}
export interface Me { id: string; name: string; email: string; role: Role; team: string | null; must_change_password: boolean }
export interface Check { key: CheckKey; label: string; result: CheckResult; detail: string }
export interface Validation { outcome: ValidationOutcome; checks: Check[]; normalized_target: string; policy_version: string; decided_at: string }
export interface Approval { state: 'pending' | 'approved' | 'refused'; note: string | null; by: string | null; at: string | null; self: boolean }
export interface Assessment {
  id: string; name: string; owner: { id: string; name: string }; target: string; env: Environment;
  hosts: string; paths: string; ports: string; exclusions: string; notes: string | null;
  status: AssessmentStatus; validation: Validation | null; approval: Approval | null;
  active_job_id: string | null; created_at: string; updated_at: string; access: 'owner' | 'admin';
}
export interface AssessmentSummary {
  id: string; name: string; target: string; env: Environment; status: AssessmentStatus;
  validation_outcome: ValidationOutcome | null; last_job: { id: string; state: JobState; submitted_at: string } | null;
  open_findings: number; created_at: string;
}
export interface ModuleRun { key: ModuleKey; name: string; state: ModuleState; detail: string | null; started_at: string | null; ended_at: string | null }
export interface Job {
  id: string; seq: number; assessment_id: string; assessment_name: string; type: 'scan'; profile: ProfileKey | null;
  priority: Priority; state: JobState; submitted_at: string; started_at: string | null; ended_at: string | null;
  policy_version: string; requested_by: string; note: string | null; resume_of: string | null;
  review: 'resumed' | 'rerun-advised' | 'closed' | null; modules: ModuleRun[];
  queue_position: number | null; wait_estimate: { lo_min: number; hi_min: number } | null;
}
export interface Capacity {
  active: number; limit: number; effective_limit: number; queued: number; healthy_workers: number; ceiling: number;
  blocked_reason: 'emergency' | 'paused' | 'queue-down' | null;
}
export interface Location {
  url: string; host: string; port: string; path: string | null; param: string | null; method: string | null;
  component: string | null; kind: LocationKind;
}
export interface Finding {
  id: string; assessment_id: string; job_id: string; severity: Severity; confidence: Confidence; state: FindingState;
  module: ModuleKey; title: string; asset: string; first_seen_at: string; last_seen_at: string;
}
export interface HistoryLine { at: string; by: string; text: string }
export interface FindingDetail extends Finding {
  location: Location; description: string; impact: string; evidence: string; reproduce: string; remediation: string;
  references: string[]; policy_version: string; history: HistoryLine[]; comments: HistoryLine[];
}
export interface AuditEvent {
  id: string; at: string; actor: string; area: AuditArea; action: string; object: string;
  outcome: 'success' | 'blocked' | 'failure'; detail: string; policy_version: string | null;
}
export interface Worker { id: string; name: string; status: WorkerStatus; enabled: boolean; last_seen_at: string; current_job: string | null }
export interface ModuleInfo { key: ModuleKey; name: string; description: string; available: boolean; profiles: ProfileKey[] }
export interface ProfileInfo {
  key: ProfileKey; name: string; description: string; modules: ModuleKey[]; available: boolean; duration: string;
  impact: 'Low' | 'Moderate' | 'Higher';
}
export interface Dashboard {
  counts: { assessments: number; open_findings: number; active_jobs: number };
  active_job: Job | null; recent: AssessmentSummary[]; capacity: Capacity;
}
export type LoginResult = { next: 'mfa' } | { next: 'enrol'; secret: string; otpauth_uri: string };
