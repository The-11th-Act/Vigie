import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { authService } from '../services';
import { purgeLegacySession } from '../services/api';

// Who is signed in, held in memory only. The session itself is a pair of
// HttpOnly cookies the page cannot read; the API is the source of truth, asked
// once on start-up through /auth/me.
const AuthContext = createContext({
  user: null,
  loading: false,
  login: async () => {},
  logout: async () => {},
});

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    purgeLegacySession();
    let cancelled = false;
    authService
      .getMe()
      .then((res) => {
        if (!cancelled) setUser(res.data);
      })
      .catch(() => {
        if (!cancelled) setUser(null);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (username, password) => {
    const res = await authService.login(username, password);
    setUser({ username: res.data.username, role: res.data.role });
  }, []);

  const logout = useCallback(async () => {
    // Revoke server-side first; a failure (expired session, API down) must
    // still sign the user out here.
    try {
      await authService.logout();
    } catch {
      /* revocation is best-effort */
    }
    setUser(null);
  }, []);

  const value = useMemo(() => ({ user, loading, login, logout }), [user, loading, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}

export { AuthContext };
