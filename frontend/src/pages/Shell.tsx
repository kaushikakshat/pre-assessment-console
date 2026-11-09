import { useEffect, useState } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';
import { api } from '../lib/api';
import { useTheme, type Theme } from '../lib/theme';
import type { Dashboard } from '../lib/types';
import { Banner } from '../components/Banner';
import { Button } from '../components/Button';
import { Icon, type IconName } from '../components/Icon';

interface NavItem { to: string; label: string; icon: IconName; end?: boolean; count?: number }
interface NavGroup { title?: string; items: NavItem[] }

const ROLE_LABEL = { owner: 'Assessment Owner', admin: 'Platform Administrator' } as const;

const CRUMBS: Record<string, string> = {
  '/dashboard': 'Dashboard', '/assessments': 'My Assessments', '/queue': 'Scan Queue', '/help': 'Help & Safety Guidance',
  '/admin/users': 'Users & Roles', '/admin/jobs': 'Assessments / Jobs', '/admin/capacity': 'Scan Capacity & Scheduling', '/admin/audit': 'Audit Logs',
};

export function breadcrumbs(pathname: string): { label: string; to?: string }[] {
  if (pathname === '/admin') return [{ label: 'Admin console' }];
  if (pathname.startsWith('/admin/')) return [{ label: 'Admin console', to: '/admin' }, { label: CRUMBS[pathname] ?? 'Not found' }];
  const [, section, id, sub] = pathname.split('/');
  if (section === 'assessments' && id) {
    const trail = [{ label: 'My Assessments', to: '/assessments' }];
    if (id === 'new') return [...trail, { label: 'New assessment' }];
    return sub ? [...trail, { label: id, to: `/assessments/${id}` }, { label: 'New scan' }] : [...trail, { label: id }];
  }
  return [{ label: CRUMBS[`/${section}`] ?? 'Not found' }];
}

export function Shell() {
  const { user, signOut } = useAuth();
  const { pathname } = useLocation();
  const [theme, setTheme] = useTheme();
  const [dash, setDash] = useState<Dashboard | null>(null);
  const admin = user!.role === 'admin';

  useEffect(() => {
    api<Dashboard>('/dashboard').then(setDash).catch(() => setDash(null)); // counts and alert bar are optional chrome
  }, [pathname]);

  const mine: NavItem[] = [
    { to: '/dashboard', label: 'Dashboard', icon: 'home' },
    { to: '/assessments', label: 'My Assessments', icon: 'folder', count: dash?.counts.assessments },
    { to: '/queue', label: 'Scan Queue', icon: 'queue', count: dash?.counts.active_jobs },
  ];
  const help: NavItem = { to: '/help', label: 'Help & Safety Guidance', icon: 'book' };
  const groups: NavGroup[] = admin
    ? [
        { items: [
          { to: '/admin', label: 'Overview', icon: 'home', end: true },
          { to: '/admin/users', label: 'Users & Roles', icon: 'users' },
          { to: '/admin/jobs', label: 'Assessments / Jobs', icon: 'folder' },
          { to: '/admin/capacity', label: 'Scan Capacity & Scheduling', icon: 'clock' },
          { to: '/admin/audit', label: 'Audit Logs', icon: 'doc' },
        ] },
        { title: 'My testing', items: mine },
        { title: 'Account', items: [help] },
      ]
    : [{ items: mine }, { title: 'Account', items: [help] }];

  const blocked = dash?.capacity.blocked_reason;
  const crumbs = breadcrumbs(pathname);

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <strong>Pre-Assessment Console</strong>
          <span>{admin ? 'Admin console' : 'Web & API security pre-assessment'}</span>
        </div>
        <nav aria-label="Main">
          {groups.map((g, i) => (
            <div key={i} className="nav-group">
              {g.title && <h2 className="nav-title">{g.title}</h2>}
              <ul>
                {g.items.map((n) => (
                  <li key={n.to}>
                    <NavLink to={n.to} end={n.end} className="nav-item">
                      <Icon name={n.icon} />
                      <span className="nav-label">{n.label}</span>
                      {n.count !== undefined && <span className="count">{n.count}</span>}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
        <p className="sidebar-foot">
          {admin ? 'Admin actions are recorded in the audit log.' : 'Pre-assessment aid only — not a penetration test, certificate or clearance.'}
        </p>
      </aside>
      <div className="main-col">
        <header className="topbar">
          <nav aria-label="Breadcrumb" className="crumbs">
            <ol>
              {crumbs.map((c, i) => (
                <li key={i}>
                  {c.to ? <Link to={c.to}>{c.label}</Link> : <span aria-current="page">{c.label}</span>}
                </li>
              ))}
            </ol>
          </nav>
          <div className="topbar-right">
            {admin && <span className="badge tone-warn"><Icon name="shield" size={12} />Admin mode</span>}
            <label className="theme">
              <span className="sr-only">Theme</span>
              <select className="control sm" value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
                <option value="system">System theme</option>
                <option value="light">Light theme</option>
                <option value="dark">Dark theme</option>
              </select>
            </label>
            <span className="who"><strong>{user!.name}</strong><small>{ROLE_LABEL[user!.role]}</small></span>
            <Button size="sm" icon="logout" onClick={() => void signOut()}>Sign out</Button>
          </div>
        </header>
        {(blocked === 'emergency' || blocked === 'paused') && (
          <div className="alert-bar">
            <Banner tone="danger" title={blocked === 'emergency' ? 'Emergency stop in effect' : 'New scans are paused'}>
              An administrator has stopped new scanning. Your results and reports are still available.
            </Banner>
          </div>
        )}
        <main className="page"><Outlet /></main>
      </div>
    </div>
  );
}
