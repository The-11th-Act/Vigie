import React, { useState } from 'react';
import { ArrowDown, ArrowUp } from 'lucide-react';
import { meService } from '../services';
import { useModules } from '../auth/ModulesContext';
import { knownModules } from '../modules';

function move(list, index, offset) {
  const next = [...list];
  const [item] = next.splice(index, 1);
  next.splice(index + offset, 0, item);
  return next;
}

// Arranges the sidebar. Only the modules the role grants are listed: hiding
// one removes it from the sidebar, it stays reachable by its address.
export default function Preferences() {
  const { modules, replace } = useModules();
  const [draft, setDraft] = useState(null);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState(null);
  const [error, setError] = useState(null);

  const items = draft || knownModules(modules);
  const changed = draft !== null;

  const update = (next) => {
    setDraft(next);
    setMessage(null);
  };

  const toggle = (key) =>
    update(items.map((item) => (item.key === key ? { ...item, hidden: !item.hidden } : item)));

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const res = await meService.updatePreferences(
        items.map((item) => item.key),
        items.filter((item) => item.hidden).map((item) => item.key)
      );
      replace(res.data);
      setDraft(null);
      setMessage('Saved.');
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Could not save');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      <h1>Preferences</h1>
      <p style={{ color: 'var(--text-muted)', margin: '0.5rem 0 1.5rem' }}>
        Choose which of your modules appear in the sidebar, and in which order.
      </p>

      {items.length === 0 ? (
        <div className="glass-panel" style={{ color: 'var(--text-muted)' }}>
          No module is available to your role. Ask an administrator.
        </div>
      ) : (
        <div className="glass-panel" style={{ maxWidth: 560 }}>
          <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {items.map((item, index) => (
              <li
                key={item.key}
                style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', opacity: item.hidden ? 0.55 : 1 }}
              >
                <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flex: 1 }}>
                  <input
                    type="checkbox"
                    checked={!item.hidden}
                    onChange={() => toggle(item.key)}
                    aria-label={`Show ${item.label} in the sidebar`}
                  />
                  {item.label}
                </label>
                <button
                  type="button"
                  className="icon-button"
                  disabled={index === 0}
                  onClick={() => update(move(items, index, -1))}
                  aria-label={`Move ${item.label} up`}
                >
                  <ArrowUp size={16} />
                </button>
                <button
                  type="button"
                  className="icon-button"
                  disabled={index === items.length - 1}
                  onClick={() => update(move(items, index, 1))}
                  aria-label={`Move ${item.label} down`}
                >
                  <ArrowDown size={16} />
                </button>
              </li>
            ))}
          </ul>

          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', marginTop: '1.25rem' }}>
            <button type="button" className="button" disabled={!changed || saving} onClick={save}>
              {saving ? 'Saving...' : 'Save'}
            </button>
            {changed && (
              <button type="button" className="icon-button" onClick={() => update(null)}>
                Cancel
              </button>
            )}
            {message && <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>{message}</span>}
          </div>
          {error && <div className="error-message" style={{ marginTop: '1rem' }}>{error}</div>}
        </div>
      )}
    </div>
  );
}
