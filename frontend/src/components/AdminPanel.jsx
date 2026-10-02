import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ArrowDown, ArrowUp, RotateCcw } from 'lucide-react';
import { adminService, remediationService, userService } from '../services';
import { NO_TEAM, scopeLabel, teamLabel } from '../teams';
import { useApiQuery } from '../hooks/useApiQuery';
import { useModules } from '../auth/ModulesContext';
import { useAuth } from '../auth/AuthContext';
import { AccountActions, NewAccountForm } from './AdminAccounts';
import { controlStyle } from './RemediationShared';
import { move } from '../order';
import AdminThreatFeeds from './AdminThreatFeeds';
import AdminTicketing from './AdminTicketing';
import AdminWebhooks from './AdminWebhooks';

const MODULES_KEY = ['admin', 'modules'];

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
  const queryClient = useQueryClient();
  const { data: shown, loading, error } = useApiQuery(
    MODULES_KEY,
    async () => (await adminService.getModules()).data
  );
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState(null);

  // Every change answers with the whole overview, stored as the cached one;
  // the admin's own sidebar may have changed with it.
  const apply = async (request) => {
    setBusy(true);
    setActionError(null);
    try {
      const res = await request();
      queryClient.setQueryData(MODULES_KEY, res.data);
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
      <h3 style={{ fontSize: '1rem', margin: '1.25rem 0 0.5rem' }}>Order in the sidebar</h3>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '0.75rem' }}>
        The first module is where the role lands after signing in. Users can still reorder their own.
      </p>
      <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
        {roles.map((role) => (
          <ProfileOrder
            key={role}
            role={role}
            profile={shown.profiles[role]}
            labels={Object.fromEntries(shown.modules.map((m) => [m.key, m.label]))}
            busy={busy}
            onReorder={(next) => apply(() => adminService.setRoleProfile(role, next))}
          />
        ))}
      </div>
    </section>
  );
}

function ProfileOrder({ role, profile, labels, busy, onReorder }) {
  const roleLabel = ROLE_LABELS[role] || role;
  return (
    <div className="glass-panel" style={{ minWidth: 220, padding: '1rem' }}>
      <div style={{ fontWeight: 600, marginBottom: '0.5rem' }}>{roleLabel}</div>
      <ol style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        {profile.map((key, index) => (
          <li key={key} style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ flex: 1 }}>{labels[key] || key}</span>
            <button
              type="button"
              className="icon-button"
              disabled={busy || index === 0}
              onClick={() => onReorder(move(profile, index, -1))}
              aria-label={`Move ${labels[key] || key} up for ${roleLabel}`}
            >
              <ArrowUp size={14} />
            </button>
            <button
              type="button"
              className="icon-button"
              disabled={busy || index === profile.length - 1}
              onClick={() => onReorder(move(profile, index, 1))}
              aria-label={`Move ${labels[key] || key} down for ${roleLabel}`}
            >
              <ArrowDown size={14} />
            </button>
          </li>
        ))}
      </ol>
    </div>
  );
}

// The teams a user sees. Known teams (those owning hosts) as boxes, plus a
// field for a team no host belongs to yet.
function ScopeEditor({ user, knownTeams, onSaved }) {
  const [editing, setEditing] = useState(false);
  const [chosen, setChosen] = useState(user.teams);
  const [extra, setExtra] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  if (user.role === 'admin') {
    return <span style={{ color: 'var(--text-muted)' }}>Whole estate (administrator)</span>;
  }
  if (!editing) {
    return (
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <span>{scopeLabel(user.teams)}</span>
        <button
          type="button"
          className="icon-button"
          onClick={() => {
            setChosen(user.teams);
            setEditing(true);
          }}
          aria-label={`Edit the scope of ${user.username}`}
        >
          Edit
        </button>
      </div>
    );
  }

  const options = [...new Set([...knownTeams, ...chosen.filter((t) => t !== NO_TEAM)])].sort();
  const toggle = (team) =>
    setChosen((prev) => (prev.includes(team) ? prev.filter((t) => t !== team) : [...prev, team]));

  const save = async () => {
    setSaving(true);
    setError(null);
    const teams = extra.trim() ? [...chosen, extra.trim()] : chosen;
    try {
      await userService.updateTeams(user.id, teams);
      setEditing(false);
      setExtra('');
      onSaved();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <fieldset style={{ border: 'none', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
      <legend style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
        Nothing checked: the whole estate
      </legend>
      {[...options, NO_TEAM].map((team) => (
        <label key={team} style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
          <input type="checkbox" checked={chosen.includes(team)} onChange={() => toggle(team)} />
          {teamLabel(team)}
        </label>
      ))}
      <input
        style={controlStyle}
        value={extra}
        onChange={(e) => setExtra(e.target.value)}
        placeholder="Another team"
        aria-label={`Another team for ${user.username}`}
        maxLength={128}
      />
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button type="button" className="button" onClick={save} disabled={saving}>
          Save scope
        </button>
        <button type="button" className="icon-button" onClick={() => setEditing(false)}>
          Cancel
        </button>
      </div>
      {error && <div className="error-message">{error}</div>}
    </fieldset>
  );
}

function UsersSection() {
  const { refresh: refreshMyModules } = useModules();
  const me = useAuth().user?.username;
  const { data, loading, error, refetch } = useApiQuery(
    ['admin', 'users'],
    async () => (await userService.list()).data
  );
  // An administrator is never scoped: every team owning a host is listed.
  const { data: knownTeams } = useApiQuery(
    ['remediation', 'teams'],
    async () => (await remediationService.listTeams()).data.teams
  );
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
      <NewAccountForm roleLabels={ROLE_LABELS} onCreated={refetch} />
      <div className="glass-panel data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Email</th>
              <th>Role</th>
              <th>Scope</th>
              <th>Account</th>
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
                <td>
                  <ScopeEditor user={user} knownTeams={knownTeams || []} onSaved={refetch} />
                </td>
                <td>
                  <AccountActions user={user} isSelf={user.username === me} onChanged={refetch} />
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
      <AdminThreatFeeds />
      <AdminWebhooks />
      <AdminTicketing />
    </div>
  );
}
