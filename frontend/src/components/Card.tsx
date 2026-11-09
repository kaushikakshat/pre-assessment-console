import type { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Icon } from './Icon';
import { formatIST } from '../lib/format';

export function Card({ title, action, flush, children }: { title?: ReactNode; action?: ReactNode; flush?: boolean; children: ReactNode }) {
  return (
    <section className="card">
      {(title || action) && (
        <header className="card-head">
          <h2>{title}</h2>
          {action}
        </header>
      )}
      <div className={flush ? 'card-body flush' : 'card-body'}>{children}</div>
    </section>
  );
}

interface StatCardProps { label: string; value: ReactNode; context?: string; tone?: 'danger'; onClick?: () => void }

export function StatCard({ label, value, context, tone, onClick }: StatCardProps) {
  return (
    <button type="button" className="card stat" onClick={onClick}>
      <span className="stat-label">{label}</span>
      <span className={`stat-value${tone ? ` tone-text-${tone}` : ''}`}>{value}</span>
      {context && <span className="stat-context">{context}</span>}
    </button>
  );
}

export function KeyValue({ items }: { items: { label: string; value: ReactNode; mono?: boolean }[] }) {
  return (
    <dl className="kv">
      {items.map((i) => (
        <div key={i.label} className="kv-row">
          <dt>{i.label}</dt>
          <dd className={i.mono ? 'mono' : undefined}>{i.value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function DeniedState({ thing, reason }: { thing: string; reason: string }) {
  return (
    <section className="card denied">
      <span className="tone-text-danger"><Icon name="lock" size={28} /></span>
      <h2>{`You don't have access to ${thing}`}</h2>
      <p>{reason}</p>
      <Link to="/" className="btn btn-secondary btn-md">Back to dashboard</Link>
    </section>
  );
}

export function TbdMarker({ label, od, title }: { label: string; od: number; title?: string }) {
  return (
    <span className="tbd" title={title ?? `Open decision OD-${od}`}>
      <Icon name="flag" size={12} />
      {`${label} · OD-${od}`}
    </span>
  );
}

export function EvidenceBlock({ text }: { text: string }) {
  return (
    <figure className="evidence">
      <pre>
        {text.split(/(\[REDACTED\])/).map((part, i) => (part === '[REDACTED]' ? <mark key={i}>{part}</mark> : part))}
      </pre>
      <figcaption>Sanitized excerpt. Cookies, tokens and personal data are redacted.</figcaption>
    </figure>
  );
}

export function Timeline({ rows, empty = 'Nothing recorded yet.' }: { rows: { at: string; text: ReactNode }[]; empty?: string }) {
  if (rows.length === 0) return <p className="muted">{empty}</p>;
  return (
    <ul className="timeline">
      {rows.map((r, i) => <li key={i}><span className="muted">{formatIST(r.at)}</span><span>{r.text}</span></li>)}
    </ul>
  );
}
