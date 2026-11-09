import { Icon, SeverityGlyph, ConfidenceGlyph } from './Icon';
import { VOCAB, SEVERITY, CONFIDENCE, type StatusKind } from '../lib/status';
import type { Severity, Confidence } from '../lib/types';

interface StatusBadgeProps { kind: StatusKind; status: string; label?: string; live?: boolean }

export function StatusBadge({ kind, status, label, live }: StatusBadgeProps) {
  const def = VOCAB[kind][status];
  // Unknown status: show it neutrally rather than hide or mislabel it (never a false success).
  const { tone, icon, label: text } = def ?? { tone: 'neutral', icon: 'help' as const, label: status };
  return (
    <span className={`badge tone-${tone}`} role={live ? 'status' : undefined}>
      <Icon name={icon} size={12} />
      {label ?? text}
    </span>
  );
}

export function SeverityBadge({ severity, compact }: { severity: Severity; compact?: boolean }) {
  const s = SEVERITY[severity];
  return (
    <span className={`badge sev-${severity}`} title={`Severity: ${s.label}`}>
      <SeverityGlyph bars={s.bars} />
      {compact ? s.compact : s.label}
    </span>
  );
}

export function ConfidenceTag({ confidence }: { confidence: Confidence }) {
  const c = CONFIDENCE[confidence];
  return (
    <span className="tag" title="Confidence">
      <ConfidenceGlyph dots={c.dots} />
      {c.label}
    </span>
  );
}
