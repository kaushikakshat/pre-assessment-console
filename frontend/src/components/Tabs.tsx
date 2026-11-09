import type { KeyboardEvent, ReactNode } from 'react';
import { useSearchParams } from 'react-router-dom';

interface TabDef { key: string; label: string; count?: number }

/** Peer views of one object; the active tab lives in `?tab=`. */
export function Tabs({ tabs, children }: { tabs: TabDef[]; children: (active: string) => ReactNode }) {
  const [params, setParams] = useSearchParams();
  const requested = params.get('tab');
  const active = tabs.some((t) => t.key === requested) ? requested! : tabs[0].key;
  const select = (key: string) => {
    const next = new URLSearchParams(params);
    next.set('tab', key);
    setParams(next, { replace: true });
    document.getElementById(`tab-${key}`)?.focus();
  };
  const onKey = (e: KeyboardEvent) => {
    const i = tabs.findIndex((t) => t.key === active);
    const step = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (step) { e.preventDefault(); select(tabs[(i + step + tabs.length) % tabs.length].key); }
  };
  return (
    <>
      <div role="tablist" className="tabs" onKeyDown={onKey}>
        {tabs.map((t) => (
          <button
            key={t.key} id={`tab-${t.key}`} type="button" role="tab" aria-selected={t.key === active}
            aria-controls={`panel-${t.key}`} tabIndex={t.key === active ? 0 : -1} onClick={() => select(t.key)}
          >
            {t.label}
            {t.count !== undefined && <span className="chip">{t.count}</span>}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`panel-${active}`} aria-labelledby={`tab-${active}`}>{children(active)}</div>
    </>
  );
}
