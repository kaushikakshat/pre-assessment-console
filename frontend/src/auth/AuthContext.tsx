import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { api, ApiError, setPasswordRequiredHandler, setUnauthorizedHandler } from '../lib/api';
import type { Me } from '../lib/types';
import { DeniedState } from '../components/Card';

interface AuthState { user: Me | null; loading: boolean; setUser: (u: Me | null) => void; signOut: () => Promise<void> }
const Ctx = createContext<AuthState>(null!);
export const useAuth = () => useContext(Ctx);

export const landingFor = (u: Me) => (u.role === 'admin' ? '/admin' : '/dashboard');

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api<Me>('/auth/me')
      .then(setUser)
      .catch((e) => { if (!(e instanceof ApiError)) throw e; setUser(null); }) // 401 or unreachable: show sign-in
      .finally(() => setLoading(false));
  }, []);

  const signOut = useCallback(async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch { /* the session is dropped locally either way */ }
    setUser(null);
  }, []);

  useEffect(() => { setUnauthorizedHandler(() => setUser(null)); return () => setUnauthorizedHandler(null); }, []);

  useEffect(() => {
    setPasswordRequiredHandler(() => setUser((u) => (u ? { ...u, must_change_password: true } : u)));
    return () => setPasswordRequiredHandler(null);
  }, []);

  return <Ctx.Provider value={{ user, loading, setUser, signOut }}>{children}</Ctx.Provider>;
}

export function RequireAuth() {
  const { user, loading } = useAuth();
  const loc = useLocation();
  if (loading) return <p className="boot" role="status">Loading…</p>;
  if (user?.must_change_password && loc.pathname !== '/account/password') return <Navigate to="/account/password" replace />;
  return user ? <Outlet /> : <Navigate to="/signin" replace state={{ from: loc.pathname }} />;
}

export function RequireAdmin() {
  const { user } = useAuth();
  return user?.role === 'admin'
    ? <Outlet />
    : <DeniedState thing="the admin console" reason="The admin console is limited to Platform Administrators. This attempt would be refused by the server and recorded." />;
}
