// DESIGN_SYSTEM §5 vocabularies. Use these words exactly.
import type { IconName } from '../components/Icon';
import type { Severity, Confidence } from './types';

export type Tone = 'ok' | 'warn' | 'danger' | 'neutral' | 'info';
export interface StatusDef { label: string; tone: Tone; icon: IconName }
export type StatusKind = 'job' | 'module' | 'finding' | 'validation' | 'assessment' | 'check' | 'worker' | 'report';

const d = (label: string, tone: Tone, icon: IconName): StatusDef => ({ label, tone, icon });

export const VOCAB: Record<StatusKind, Record<string, StatusDef>> = {
  job: {
    queued: d('Queued', 'neutral', 'clock'),
    validating: d('Validating', 'info', 'spin'),
    scheduled: d('Scheduled', 'neutral', 'arrow'),
    running: d('Running', 'info', 'spin'),
    cancelling: d('Cancelling', 'warn', 'spin'),
    completed: d('Completed', 'ok', 'check'),
    'completed-warnings': d('Completed with warnings', 'warn', 'warn'),
    failed: d('Failed', 'danger', 'x'),
    cancelled: d('Cancelled', 'neutral', 'slash'),
    blocked: d('Blocked', 'danger', 'stop'),
    interrupted: d('Interrupted · needs review', 'warn', 'pause'),
  },
  module: {
    queued: d('Queued', 'neutral', 'ring'),
    running: d('Running', 'info', 'spin'),
    completed: d('Completed', 'ok', 'check'),
    'completed-warnings': d('Completed with warnings', 'warn', 'warn'),
    skipped: d('Skipped', 'neutral', 'skip'),
    blocked: d('Blocked', 'danger', 'stop'),
    failed: d('Failed', 'danger', 'x'),
    cancelled: d('Cancelled', 'neutral', 'slash'),
    unavailable: d('Unavailable', 'neutral', 'slash'),
    inconclusive: d('Inconclusive', 'warn', 'help'),
    interrupted: d('Interrupted', 'warn', 'pause'),
  },
  finding: {
    new: d('New', 'info', 'dot'),
    open: d('Open', 'neutral', 'ring'),
    'under-review': d('Under review', 'info', 'clock'),
    'false-positive': d('False positive', 'neutral', 'slash'),
    resolved: d('Resolved', 'ok', 'check'),
    reopened: d('Reopened', 'danger', 'warn'),
    'not-retested': d('Not retested', 'neutral', 'skip'),
    'accepted-risk': d('Accepted risk', 'warn', 'shield'),
  },
  validation: {
    allowed: d('Allowed', 'ok', 'check'),
    approval: d('Approval required', 'warn', 'clock'),
    blocked: d('Blocked', 'danger', 'stop'),
  },
  // 'active' has no badge: the latest job's state is shown instead (§5.5).
  assessment: {
    draft: d('Draft', 'neutral', 'doc'),
    'awaiting-approval': d('Awaiting approval', 'warn', 'clock'),
    blocked: d('Blocked', 'danger', 'stop'),
  },
  check: {
    pass: d('Pass', 'ok', 'check'),
    warn: d('Warning', 'warn', 'warn'),
    fail: d('Fail', 'danger', 'x'),
    skip: d('Skipped', 'neutral', 'skip'),
  },
  report: {
    ready: d('Ready', 'ok', 'check'),
    generating: d('Generating', 'info', 'spin'),
    failed: d('Failed', 'danger', 'x'),
  },
  worker: {
    healthy: d('Healthy', 'ok', 'check'),
    'heartbeat-lost': d('Heartbeat lost', 'danger', 'x'),
    standby: d('Standby', 'neutral', 'pause'),
    'not-provisioned': d('Not provisioned', 'neutral', 'slash'),
  },
};

export const VALIDATION_HEADING: Record<string, string> = {
  allowed: 'Allowed — target may be scanned',
  approval: 'Approval required — waiting for an approver',
  blocked: 'Blocked — no scan traffic will be sent',
};

export const SKIPPED_CHECK_DETAIL = 'Not evaluated after a blocking result';

export const SEVERITY: Record<Severity, { label: string; compact: string; bars: number }> = {
  critical: { label: 'Critical', compact: 'Critical', bars: 4 },
  high: { label: 'High', compact: 'High', bars: 3 },
  medium: { label: 'Medium', compact: 'Medium', bars: 2 },
  low: { label: 'Low', compact: 'Low', bars: 1 },
  info: { label: 'Informational', compact: 'Info', bars: 0 },
};

export const CONFIDENCE: Record<Confidence, { label: string; dots: number }> = {
  confirmed: { label: 'Confirmed', dots: 2 },
  suspected: { label: 'Suspected', dots: 1 },
};

export const PROFILE_NAMES = { quick: 'Quick Scan', pre: 'Pre-Assessment', deep: 'Deep Scan' } as const;

// DESIGN_SYSTEM §8 standard messages for blocked submissions.
export const BLOCKED_COPY = {
  emergency: 'An administrator used Emergency stop. New scans are blocked until it is lifted.',
  paused: 'An administrator has paused new scans. Submissions are not accepted until scanning resumes.',
  'queue-down': 'The scan queue service is not responding, so new submissions are refused.',
} as const;
