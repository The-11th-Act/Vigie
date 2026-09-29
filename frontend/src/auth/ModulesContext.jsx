import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { meService } from '../services';

// The signed-in user's modules, as the API grants them. The server refuses
// every other module anyway: this only decides what the sidebar offers.
const ModulesContext = createContext({
  modules: [],
  loading: false,
  error: null,
  refresh: async () => {},
  replace: () => {},
});

export function ModulesProvider({ children }) {
  const [modules, setModules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const refresh = useCallback(async () => {
    try {
      const res = await meService.getModules();
      setModules(res.data.modules);
      setError(null);
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Could not load your modules');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Endpoints that change the arrangement answer with the new one.
  const replace = useCallback((data) => setModules(data.modules), []);

  const value = useMemo(
    () => ({ modules, loading, error, refresh, replace }),
    [modules, loading, error, refresh, replace]
  );
  return <ModulesContext.Provider value={value}>{children}</ModulesContext.Provider>;
}

export function useModules() {
  return useContext(ModulesContext);
}

export { ModulesContext };
