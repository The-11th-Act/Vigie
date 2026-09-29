import React, { useState } from 'react';
import { RotateCcw } from 'lucide-react';
import { adminService, userService } from '../services';
import { useFetch } from '../hooks/useFetch';
import { useModules } from '../auth/ModulesContext';

const ROLE_LABELS = {
  admin: 'Administrator',
  analyst: 'Analyst',
  remediator: 'Remediator',
};

const ROLE_HINTS = {
  admin: 'Everything, including this screen.',
  analyst: 'Triages the backlog: accepts risks, dismisses false positives.',
  remediator: 'Fixes what the backlog asks for; cannot accept a risk nor change an asset.',
};

function errorText(err) {
  return err.response?.data?.detail || err.message || 'The change was refused';
}

function ModulesSection() {
  const { refresh: refreshMyModules } = useModules();
  const { data, loading, error } = useFetch(async () => (await adminService.getModules()).data, []);
  const [overview, setOverview] = useState(null);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);

  const shown = overview || data;

  // Every change answers with the whole overview; the admin's own sidebar
  // may have changed with it.
  const apply = async (request) => {
    setBusy(true);
    setActionError(null);
    try {
      const res = await request();
      setOverview(res.data);
      refreshMyModules();
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const toggleInProfile = (role, key, granted) => {
    const profile = shown.profiles[role];
    const next = granted ? [...profile, key] : profile.filter((k) => k !== key);
    apply(() => adminService.setRoleProfile(role, next));
  };

  if (loading && !shown) return <div className="loading">Loading modules...</div>;
  if (error && !shown) return <div className="error-message">Error: {error}</div>;

  const roles = Object.keys(shown.profiles);
  return (
    <section style={{ marginBottom: '2.5rem' }}>
      <h2 style={{ fontSize: '1.15rem', marginBottom: '0.5rem' }}>Modules</h2>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
        A module switched off disappears for everybody. Otherwise each role sees the modules
        ticked for it; users can then hide or reorder their own.
      </p>
      {actionError && <div className="error-message" style={{ marginBottom: '1rem' }}>{actionError}</div>}
      <div className="glass-panel data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Module</th>
              <th>Enabled</th>
              {roles.map((role) => (
                <th key={role} title={ROLE_HINTS[role]}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    {ROLE_LABELS[role] || role}
                    {shown.customized.includes(role) && (
                      <button
                        type="button"
                        className="icon-button"
                        disabled={busy}
                        onClick={() => apply(() => adminService.resetRoleProfile(role))}
                        title="Back to the default profile"
                        aria-label={`Reset the ${ROLE_LABELS[role] || role} profile`}
                      >
                        <RotateCcw size={14} />
                      </button>
                    )}
                  </div>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.modules.map((module) => (
              <tr key={module.key}>
                <td>{module.label}</td>
                <td>
                  <input
                    type="checkbox"
                    checked={module.enabled}
                    disabled={busy || module.admin_only}
                    onChange={(e) => apply(() => adminService.toggleModule(module.key, e.target.checked))}
                    aria-label={`${module.label} enabled`}
                  />
                </td>
                {roles.map((role) => {
                  // Reserved modules are fixed: administrators always keep them.
                  const locked = module.admin_only;
                  return (
                    <td key={role}>
                      <input
                        type="checkbox"
                        checked={locked ? role === 'admin' : shown.profiles[role].includes(module.key)}
                        disabled={busy || locked || !module.enabled}
                        onChange={(e) => toggleInProfile(role, module.key, e.target.checked)}
                        aria-label={`${module.label} for ${ROLE_LABELS[role] || role}`}
                      />
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function UsersSection() {
  const { refresh: refreshMyModules } = useModules();
  const { data, loading, error, refetch } = useFetch(async () => (await userService.list()).data, []);
  const [rowError, setRowError] = useState({});

  const changeRole = async (user, role) => {
    setRowError((prev) => ({ ...prev, [user.id]: null }));
    try {
      await userService.updateRole(user.id, role);
      refetch();
      refreshMyModules();
    } catch (err) {
      setRowError((prev) => ({ ...prev, [user.id]: errorText(err) }));
    }
  };

  if (loading && !data) return <div className="loading">Loading users...</div>;
  if (error && !data) return <div className="error-message">Error: {error}</div>;

  return (
    <section>
      <h2 style={{ fontSize: '1.15rem', marginBottom: '0.5rem' }}>Users</h2>
      <div className="glass-panel data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Email</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            {data.map((user) => (
              <tr key={user.id}>
                <td>{user.username}</td>
                <td style={{ color: 'var(--text-muted)' }}>{user.email}</td>
                <td>
                  <select
                    className="select"
                    value={user.role}
                    onChange={(e) => changeRole(user, e.target.value)}
                    aria-label={`Role of ${user.username}`}
                  >
                    {Object.entries(ROLE_LABELS).map(([value, label]) => (
                      <option key={value} value={value}>{label}</option>
                    ))}
                  </select>
                  {rowError[user.id] && (
                    <div className="error-message" style={{ padding: '0.4rem 0.6rem', fontSize: '0.75rem', marginTop: '0.4rem' }}>
                      {rowError[user.id]}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

export default function AdminPanel() {
  return (
    <div>
      <h1 style={{ marginBottom: '1.5rem' }}>Administration</h1>
      <ModulesSection />
      <UsersSection />
    </div>
  );
}
