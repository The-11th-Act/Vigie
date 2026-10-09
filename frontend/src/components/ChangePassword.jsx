import { useState } from 'react';
import { meService } from '../services';
import { useAuth } from '../auth/AuthContext';
import { errorText } from './AdminAccounts';
import { controlStyle, muted } from './RemediationShared';

// The current password as proof. The API then ends every session, this one
// included: whoever had the old password is out, and so are we, to sign in
// again with the new one.
export default function ChangePassword() {
  const { logout } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);
  const mismatch = confirm !== '' && confirm !== next;

  const submit = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    try {
      await meService.changePassword(current, next);
      await logout();
    } catch (err) {
      setError(errorText(err));
      setSaving(false);
    }
  };

  return (
    <section style={{ marginTop: '2rem' }}>
      <h2 style={{ fontSize: '1.15rem', marginBottom: '0.5rem' }}>Password</h2>
      <form
        className="glass-panel"
        onSubmit={submit}
        aria-label="Change my password"
        style={{ maxWidth: 560, display: 'flex', flexDirection: 'column', gap: '0.6rem' }}
      >
        <input
          style={controlStyle}
          type="password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          placeholder="Current password"
          aria-label="Current password"
          autoComplete="current-password"
        />
        <input
          style={controlStyle}
          type="password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          placeholder="New password (12 characters or more, a letter and a digit)"
          aria-label="New password"
          autoComplete="new-password"
          maxLength={72}
        />
        <input
          style={controlStyle}
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          placeholder="New password, again"
          aria-label="New password, again"
          autoComplete="new-password"
          maxLength={72}
        />
        {mismatch && <div style={{ ...muted, color: 'var(--high)' }}>The two new passwords differ.</div>}
        <div style={muted}>Every session closes, this one included: you will sign in again with the new password. Your personal API tokens are revoked too.</div>
        {error && <div className="error-message">{error}</div>}
        <div>
          <button
            type="submit"
            className="button"
            disabled={saving || !current || !next || next !== confirm}
          >
            Change password
          </button>
        </div>
      </form>
    </section>
  );
}
