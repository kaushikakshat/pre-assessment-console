import { useState } from 'react';
import { Checkbox } from './Fields';
import type { Wordlist } from '../lib/types';

/** Collapsed-by-default wordlist picker. Fuzzing lists are enabled only for Deep Scan. */
export function Advanced({ wordlists, selected, deep, onToggle }: { wordlists: Wordlist[]; selected: string[]; deep: boolean; onToggle: (key: string) => void }) {
  const [open, setOpen] = useState(false);
  const group = (title: string, category: Wordlist['category']) => {
    const off = category === 'fuzzing' && !deep;
    const items = wordlists.filter((w) => w.category === category);
    return (
      <fieldset className="stack" disabled={off}>
        <legend className="group-title">{title}</legend>
        {off && <small className="muted">Fuzzing runs only in Deep Scan.</small>}
        {items.map((w) => (
          <Checkbox key={w.key} checked={!off && selected.includes(w.key)} disabled={off} onChange={() => onToggle(w.key)} label={`${w.label} · ${w.lines.toLocaleString('en-IN')} lines`} />
        ))}
      </fieldset>
    );
  };
  return (
    <div className="stack">
      <button type="button" className="btn btn-secondary btn-sm" aria-expanded={open} aria-controls={open ? 'advanced-panel' : undefined} onClick={() => setOpen(!open)}>Advanced</button>
      {open && <div id="advanced-panel" className="stack">{group('Discovery lists', 'discovery')}{group('Fuzzing lists', 'fuzzing')}</div>}
    </div>
  );
}
