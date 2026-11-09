import type { ReactNode } from 'react';
import { EmptyState } from './Card';

export interface Column<T> {
  key: string;
  header: ReactNode;
  render: (row: T) => ReactNode;
  mono?: boolean;
  align?: 'right';
}
interface Selection<T> { selected: ReadonlySet<string>; onToggle: (key: string) => void; label: (row: T) => string; disabled?: (row: T) => boolean }
interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void; // convenience only: the title cell must also hold a real link/button
  selection?: Selection<T> & { header: string };
  empty: { title: string; text?: string; action?: ReactNode };
  caption?: string;
}

export function DataTable<T>({ columns, rows, rowKey, onRowClick, selection, empty, caption }: DataTableProps<T>) {
  if (rows.length === 0) {
    return <section className="card"><EmptyState title={empty.title} action={empty.action}>{empty.text}</EmptyState></section>;
  }
  return (
    <section className="card table-wrap">
      <table className="table">
        {caption && <caption className="sr-only">{caption}</caption>}
        <thead>
          <tr>
            {selection && <th scope="col" className="sel"><span className="sr-only">{selection.header}</span></th>}
            {columns.map((c) => <th key={c.key} scope="col" className={c.align}>{c.header}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const key = rowKey(row);
            const checked = selection?.selected.has(key) ?? false;
            return (
              <tr
                key={key}
                className={`${onRowClick ? 'clickable' : ''} ${checked ? 'selected' : ''}`}
                onClick={onRowClick && ((e) => { if (!(e.target as HTMLElement).closest('a,button,input,select,label')) onRowClick(row); })}
              >
                {selection && (
                  <td className="sel">
                    <input
                      type="checkbox" checked={checked} disabled={selection.disabled?.(row)}
                      aria-label={selection.label(row)} onChange={() => selection.onToggle(key)}
                    />
                  </td>
                )}
                {columns.map((c) => <td key={c.key} className={`${c.mono ? 'mono nowrap' : ''} ${c.align ?? ''}`}>{c.render(row)}</td>)}
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
