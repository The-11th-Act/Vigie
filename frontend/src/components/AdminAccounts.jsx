import { useState } from 'react';
import { userService } from '../services';
import { controlStyle, muted } from './RemediationShared';

// A 422 lists its problems; anything else carries one sentence.
export function errorText(err) {
  const detail = err.response?.data?.detail;
  if (Array.isArray(detail)) {
    return detail.map((item) => item.msg?.replace(/^Value error, /, '') || String(item)).join('; ');
  }
  return detail || err.message || 'The change was refused';
}

const EMPTY = { username: '', email: '', password: '', role: 'analyst' };

// Accounts are opened here: there is no self-registration. The password is
// the initial one, handed over; the user changes it in Preferences.
export function NewAccountForm({ roleLabels, onCreated }) {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(EMPTY);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const set = (patch) => setForm((prev) => ({ ...prev, ...patch }));

  if (!open) {
    return (
      <button type="button" className="button" onClick={() => setOpen(true)} style={{ marginBottom: '0.75rem' }}>
        New account
      </button>
    );
  }

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await userService.create({ ...form, username: form.username.trim(), email: form.email.trim() });
      setForm(EMPTY);
      setOpen(false);
      onCreated();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <form
      className="glass-panel"
      onSubmit={submit}
      aria-label="New account"
      style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', marginBottom: '1rem', maxWidth: 640 }}
    >
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <input
          style={{ ...controlStyle, width: 170 }}
          value={form.username}
          onChange={(e) => set({ username: e.target.value })}
          placeholder="Username"
          aria-label="Username"
          maxLength={64}
          autoComplete="off"
        />
        <input
          style={{ ...controlStyle, flex: 1, minWidth: 200 }}
          type="email"
          value={form.email}
          onChange={(e) => set({ email: e.target.value })}
          placeholder="Email"
          aria-label="Email"
        />
        <select className="select" value={form.role} onChange={(e) => set({ role: e.target.value })} aria-label="Role">
          {Object.entries(roleLabels).map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
      </div>
      <input
        style={controlStyle}
        type="password"
        value={form.password}
        onChange={(e) => set({ password: e.target.value })}
        placeholder="Initial password (12 characters or more, a letter and a digit)"
        aria-label="Initial password"
        autoComplete="new-password"
        maxLength={72}
      />
      <div style={muted}>The scope (teams) is set on the account once created; none means the whole estate.</div>
      {error && <div className="error-message">{error}</div>}
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button
          type="submit"
          className="button"
          disabled={saving || !form.username.trim() || !form.email.trim() || !form.password}
        >
          Create account
        </button>
        <button type="button" className="icon-button" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}

// Disable, reset the password of, or delete one account. Not one's own: the
// API refuses an administrator locking themselves out.
export function AccountActions({ user, isSelf, onChanged }) {
  const [resetting, setResetting] = useState(false);
  const [password, setPassword] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [error, setError] = useState(null);

  const run = async (request, done) => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await request();
      if (done) done();
      onChanged();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const status = (
    <span className={`badge ${user.is_active ? 'badge-low' : 'badge-medium'}`}>
      {user.is_active ? 'Active' : 'Disabled'}
    </span>
  );
  if (isSelf) {
    return (
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
        {status}
        <span style={muted}>you</span>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
      <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center', flexWrap: 'wrap' }}>
        {status}
        <button
          type="button"
          className="icon-button"
          disabled={busy}
          onClick={() => run(() => userService.setActive(user.id, !user.is_active))}
          aria-label={`${user.is_active ? 'Disable' : 'Enable'} ${user.username}`}
        >
          {user.is_active ? 'Disable' : 'Enable'}
        </button>
        <button
          type="button"
          className="icon-button"
          disabled={busy}
          onClick={() => setResetting(!resetting)}
          aria-expanded={resetting}
          aria-label={`Reset the password of ${user.username}`}
        >
          Reset password
        </button>
        {confirmDelete ? (
          <>
            <button
              type="button"
              className="icon-button"
              disabled={busy}
              onClick={() => run(() => userService.remove(user.id))}
              aria-label={`Confirm the deletion of ${user.username}`}
            >
              Confirm delete
            </button>
            <button type="button" className="icon-button" onClick={() => setConfirmDelete(false)}>
              Keep
            </button>
          </>
        ) : (
          <button
            type="button"
            className="icon-button"
            disabled={busy}
            onClick={() => setConfirmDelete(true)}
            aria-label={`Delete ${user.username}`}
          >
            Delete
          </button>
        )}
      </div>
      {resetting && (
        <div style={{ display: 'flex', gap: '0.4rem' }}>
          <input
            style={{ ...controlStyle, flex: 1 }}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="New password"
            aria-label={`New password for ${user.username}`}
            autoComplete="new-password"
            maxLength={72}
          />
          <button
            type="button"
            className="button"
            disabled={busy || !password}
            onClick={() =>
              run(
                () => userService.resetPassword(user.id, password),
                () => {
                  setPassword('');
                  setResetting(false);
                  setNotice('Password set; their sessions are closed.');
                }
              )
            }
          >
            Set
          </button>
        </div>
      )}
      {notice && <div style={muted}>{notice}</div>}
      {error && <div className="error-message" style={{ fontSize: '0.75rem' }}>{error}</div>}
    </div>
  );
}
