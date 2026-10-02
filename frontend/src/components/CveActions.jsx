import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { vulnerabilityService } from '../services';
import { errorText } from './AdminAccounts';
import { controlStyle } from './RemediationShared';

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

// Correct a CVE of the catalogue (a wrong score, a truncated title), or
// remove it. A new score rescores every open finding of the CVE, whoever's
// they are: hence analysts and administrators who see the whole estate only,
// and deletion (which takes the findings with it) for administrators.
export default function CveActions({ vuln, canDelete }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] });
    // Scores moved, or findings went away with their CVE.
    queryClient.invalidateQueries({ queryKey: ['findings'] });
  };

  const run = async (request) => {
    setBusy(true);
    setError(null);
    try {
      await request();
      setEditing(false);
      setConfirmDelete(false);
      refresh();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const startEdit = () => {
    setForm({ title: vuln.title, cvss_score: String(vuln.cvss_score), severity: vuln.severity });
    setEditing(true);
    setError(null);
  };

  const save = () => {
    const changes = {};
    if (form.title.trim() !== vuln.title) changes.title = form.title.trim();
    if (Number(form.cvss_score) !== vuln.cvss_score) changes.cvss_score = Number(form.cvss_score);
    if (form.severity !== vuln.severity) changes.severity = form.severity;
    if (Object.keys(changes).length === 0) {
      setEditing(false);
      return;
    }
    run(() => vulnerabilityService.update(vuln.id, changes));
  };

  if (editing) {
    const score = Number(form.cvss_score);
    const invalid = !form.title.trim() || form.cvss_score === '' || Number.isNaN(score) || score < 0 || score > 10;
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', minWidth: 260 }}>
        <input
          style={controlStyle}
          value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })}
          aria-label={`Title of ${vuln.cve_id}`}
          maxLength={512}
        />
        <div style={{ display: 'flex', gap: '0.35rem' }}>
          <input
            style={{ ...controlStyle, width: 90 }}
            type="number"
            min="0"
            max="10"
            step="0.1"
            value={form.cvss_score}
            onChange={(e) => setForm({ ...form, cvss_score: e.target.value })}
            aria-label={`CVSS score of ${vuln.cve_id}`}
          />
          <select
            className="select"
            value={form.severity}
            onChange={(e) => setForm({ ...form, severity: e.target.value })}
            aria-label={`Severity of ${vuln.cve_id}`}
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          A new score rescores every open finding of this CVE.
        </div>
        <div style={{ display: 'flex', gap: '0.35rem' }}>
          <button type="button" className="button" disabled={busy || invalid} onClick={save}>
            Save
          </button>
          <button type="button" className="icon-button" onClick={() => setEditing(false)}>
            Cancel
          </button>
        </div>
        {error && <div className="error-message" style={{ fontSize: '0.75rem' }}>{error}</div>}
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
      <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
        <button type="button" className="icon-button" onClick={startEdit} aria-label={`Edit ${vuln.cve_id}`}>
          Edit
        </button>
        {canDelete &&
          (confirmDelete ? (
            <>
              <button
                type="button"
                className="icon-button"
                disabled={busy}
                onClick={() => run(() => vulnerabilityService.remove(vuln.id))}
                aria-label={`Confirm the deletion of ${vuln.cve_id}`}
              >
                Delete it and its findings
              </button>
              <button type="button" className="icon-button" onClick={() => setConfirmDelete(false)}>
                Keep
              </button>
            </>
          ) : (
            <button
              type="button"
              className="icon-button"
              onClick={() => setConfirmDelete(true)}
              aria-label={`Delete ${vuln.cve_id}`}
            >
              Delete
            </button>
          ))}
      </div>
      {error && <div className="error-message" style={{ fontSize: '0.75rem' }}>{error}</div>}
    </div>
  );
}
