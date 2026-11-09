import { EmptyState } from '../components';

// Placeholder for screens built in later tasks: no buttons or actions, so nothing looks usable that is not.
export function Stub({ title }: { title: string }) {
  return (
    <div className="stack-lg">
      <h1>{title}</h1>
      <section className="card"><EmptyState title="This screen is not available yet">It is part of a later release.</EmptyState></section>
    </div>
  );
}
