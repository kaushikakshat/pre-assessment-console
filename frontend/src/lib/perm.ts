// DESIGN_SYSTEM §11.2 capability matrix. The backend enforces the same rules; this only shapes the UI.
export type AccessLevel = 'owner' | 'admin' | 'view';
export type Action =
  | 'view' | 'export-report' | 'generate-report' | 'change-finding-state' | 'comment'
  | 'retest' | 'new-scan' | 'share' | 'sharing-tab' | 'activity-tab';

const ALL: Action[] = ['view', 'export-report', 'generate-report', 'change-finding-state', 'comment', 'retest', 'new-scan', 'share', 'sharing-tab', 'activity-tab'];
const READ: Action[] = ['view', 'export-report'];

const MATRIX: Record<AccessLevel, ReadonlySet<Action>> = {
  owner: new Set(ALL),
  view: new Set(READ),
  admin: new Set<Action>([...READ, 'generate-report', 'activity-tab']),
};

export function can(level: AccessLevel | null, action: Action): boolean {
  return level !== null && MATRIX[level].has(action);
}
