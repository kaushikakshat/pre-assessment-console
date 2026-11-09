import type { ReactNode } from 'react';

const C = (cx: number, cy: number, r: number, extra = {}) => <circle cx={cx} cy={cy} r={r} {...extra} />;
const P = (d: string, extra = {}) => <path d={d} {...extra} />;

const PATHS = {
  check: P('M3 8.5l3 3 7-7'),
  x: P('M4 4l8 8M12 4l-8 8'),
  warn: <>{P('M8 2l6.5 11.5h-13z')}{P('M8 6.5v3M8 11.6v.01')}</>,
  clock: <>{C(8, 8, 6)}{P('M8 4.5V8l2.5 1.5')}</>,
  arrow: <>{C(8, 8, 6)}{P('M6.8 5.6L9.2 8l-2.4 2.4')}</>,
  spin: P('M8 2a6 6 0 1 0 6 6', { className: 'icon-spin', style: { transformOrigin: '8px 8px' } }),
  stop: <>{P('M5.2 2h5.6L14 5.2v5.6L10.8 14H5.2L2 10.8V5.2z')}{P('M5.5 8h5')}</>,
  slash: <>{C(8, 8, 6)}{P('M3.8 12.2l8.4-8.4')}</>,
  pause: P('M6 4v8M10 4v8'),
  dot: C(8, 8, 3, { fill: 'currentColor' }),
  ring: C(8, 8, 5),
  skip: C(8, 8, 6, { strokeDasharray: '2 2.2' }),
  help: <>{C(8, 8, 6)}{P('M6.3 6.4a1.8 1.8 0 1 1 2.5 1.7c-.5.3-.8.6-.8 1.2M8 11.4v.01')}</>,
  info: <>{C(8, 8, 6)}{P('M8 7.5v4M8 4.9v.01')}</>,
  shield: P('M8 2l5 2v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4z'),
  lock: <><rect x="3.5" y="7" width="9" height="6.5" rx="1" />{P('M5.5 7V5a2.5 2.5 0 0 1 5 0v2')}</>,
  doc: P('M4 2h5l3 3v9H4zM9 2v3h3M6 8h4M6 10.5h4'),
  flag: P('M4 14V2M4 3h8l-2 3 2 3H4'),
  retest: P('M13 8a5 5 0 1 1-1.5-3.5M13 2.5v3h-3'),
  share: P('M8 10V2M5 5l3-3 3 3M3 9v4.5h10V9'),
  plus: P('M8 3v10M3 8h10'),
  search: <>{C(7, 7, 4.5)}{P('M10.5 10.5L14 14')}</>,
  bell: P('M4 11V7a4 4 0 0 1 8 0v4l1 1.5H3zM6.5 14h3'),
  user: <>{C(8, 5.5, 2.5)}{P('M3 13.5c0-2.5 2.2-4 5-4s5 1.5 5 4')}</>,
  users: <>{C(6, 5.5, 2.2)}{P('M2 13c0-2.2 1.8-3.5 4-3.5s4 1.3 4 3.5')}{C(11.5, 6, 1.8)}{P('M11.5 9.6c1.6 0 3 .9 3 2.9')}</>,
  folder: P('M2 4.5h4l1.5 1.5H14v7H2z'),
  home: P('M2.5 8L8 3l5.5 5M4 7v6.5h8V7'),
  queue: P('M2.5 4h11M2.5 8h11M2.5 12h7'),
  report: P('M3 13V8M7 13V3M11 13V6'),
  book: P('M2 3.5h4.5A1.5 1.5 0 0 1 8 5v8.5A1.5 1.5 0 0 0 6.5 12H2zM14 3.5H9.5A1.5 1.5 0 0 0 8 5v8.5A1.5 1.5 0 0 1 9.5 12H14z'),
  map: P('M2 4l4-1.5 4 1.5 4-1.5v9.5L10 13.5 6 12l-4 1.5zM6 2.5V12M10 4v9.5'),
  chevron: P('M6 3.5l4.5 4.5L6 12.5'),
  close: P('M4 4l8 8M12 4l-8 8'),
  logout: P('M6.5 2.5h-3v11h3M10 5l3 3-3 3M13 8H6.5'),
} satisfies Record<string, ReactNode>;

export type IconName = keyof typeof PATHS;
export const ICON_NAMES = Object.keys(PATHS) as IconName[];

export function Icon({ name, size = 16, label }: { name: IconName; size?: number; label?: string }) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth={1.75}
      strokeLinecap="round" strokeLinejoin="round" className="icon"
      {...(label ? { role: 'img', 'aria-label': label } : { 'aria-hidden': true })}
    >
      {PATHS[name]}
    </svg>
  );
}

/** Four ascending bars; filled count = level, the rest at 28% opacity. */
export function SeverityGlyph({ bars, size = 12 }: { bars: number; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" className="icon">
      {[0, 1, 2, 3].map((i) => (
        <rect key={i} x={1 + i * 4} y={12 - i * 3 - 2} width="3" height={4 + i * 3} rx="0.5" opacity={i < bars ? 1 : 0.28} />
      ))}
    </svg>
  );
}

/** Two dots; Confirmed = 2 filled, Suspected = 1 filled. */
export function ConfidenceGlyph({ dots, size = 12 }: { dots: number; size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor" stroke="currentColor" strokeWidth="1.5" aria-hidden="true" className="icon">
      {[0, 1].map((i) => (
        <circle key={i} cx={4.5 + i * 7} cy="8" r="2.5" fillOpacity={i < dots ? 1 : 0} />
      ))}
    </svg>
  );
}
