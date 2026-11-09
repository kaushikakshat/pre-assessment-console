import { useEffect, useState } from 'react';

export type Theme = 'light' | 'dark' | 'system';
const KEY = 'pa_theme';

function read(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    return v === 'light' || v === 'dark' ? v : 'system';
  } catch { return 'system'; }
}

export function applyTheme(t: Theme) {
  if (t === 'system') document.documentElement.removeAttribute('data-theme');
  else document.documentElement.setAttribute('data-theme', t);
}

export function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setTheme] = useState<Theme>(read);
  useEffect(() => applyTheme(theme), [theme]);
  return [theme, (t) => {
    setTheme(t);
    try { localStorage.setItem(KEY, t); } catch { /* storage blocked: theme applies for this visit only */ }
  }];
}
