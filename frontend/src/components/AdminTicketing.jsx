import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import { ticketingService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { muted } from './RemediationShared';

const TICKETING_KEY = ['admin', 'ticketing'];

const RESULT_LABELS = {
  exported: 'exported',
  pulled: 'moved by the teams',
  solved: 'solved',
  reopened: 'reopened',
  replaced: 'replaced',
  gone: 'deleted',
  foreign: 'other instance',
  errors: 'errors',
};

function errorText(err) {
  return err.response?.data?.detail || err.message || 'The request was refused';
}

function formatMoment(value) {
  return value ? new Date(value).toLocaleString() : 'never';
}

function Fact({ label, value, hint }) {
  return (
    <div title={hint} style={{ minWidth: 110 }}>
      <div style={{ fontSize: '1.25rem', fontWeight: 600 }}>{value}</div>
      <div style={muted}>{label}</div>
    </div>
  );
}

function lastResult(result) {
  if (!result) return null;
  const parts = Object.entries(RESULT_LABELS)
    .filter(([key]) => result[key])
    .map(([key, label]) => `${result[key]} ${label}`);
  return parts.length ? parts.join(', ') : 'nothing to do';
}

export default function AdminTicketing() {
  const queryClient = useQueryClient();
  const { data, loading, error } = useApiQuery(TICKETING_KEY, async () => (await ticketingService.status()).data);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [syncError, setSyncError] = useState(null);

  const syncNow = async () => {
    setBusy(true);
    setNotice(null);
    setSyncError(null);
    try {
      await ticketingService.syncNow();
      setNotice('Sync queued: the figures below update once the worker has run it.');
      queryClient.invalidateQueries({ queryKey: TICKETING_KEY });
    } catch (err) {
      setSyncError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section style={{ marginBottom: '2.5rem' }}>
      <h2 style={{ fontSize: '1.15rem', marginBottom: '0.5rem' }}>Ticketing: {data?.label || 'GLPI'}</h2>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
        Remediation tickets are mirrored in GLPI, where the teams work: their progress comes back here, and Vigie solves
        a GLPI ticket once the scans confirm the fix, or reopens it if a finding comes back.
      </p>
      {loading && !data && <div className="loading">Loading the connector...</div>}
      {error && !data && <div className="error-message">Error: {error}</div>}
      {data && !data.configured && (
        <div className="glass-panel" style={{ fontSize: '0.875rem' }}>
          Not configured. Set <code>GLPI_URL</code> and <code>GLPI_SYNC_ENABLED</code>, and give the worker its API
          tokens (<code>docker-compose.glpi.yml</code>): see <code>docs/EXPLOITATION.md</code>.
        </div>
      )}
      {data && data.configured && (
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <span className={`badge ${data.enabled ? 'badge-low' : 'badge-medium'}`}>
              {data.enabled ? `Sync every ${data.interval_minutes} min` : 'Sync disabled'}
            </span>
            <code style={{ fontSize: '0.8rem' }}>{data.url}</code>
            <button
              type="button"
              className="icon-button"
              onClick={syncNow}
              disabled={!data.enabled || busy}
              style={{ marginLeft: 'auto' }}
            >
              <RefreshCw size={14} /> Sync now
            </button>
          </div>
          <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap' }}>
            <Fact label="linked" value={data.linked} />
            <Fact label="to export" value={data.pending_export} />
            <Fact label="in error" value={data.errors} hint="The error is shown on each ticket in Remediation." />
            <Fact label="deleted in GLPI" value={data.gone} hint="No longer synced." />
            {data.foreign > 0 && (
              <Fact
                label="other instance"
                value={data.foreign}
                hint="Linked by another instance (a staging restored from production) or another GLPI server: shown, never synced."
              />
            )}
          </div>
          <div style={{ fontSize: '0.85rem' }}>
            <div>
              Last run: {formatMoment(data.last_run_at)}
              {data.last_result && <span style={muted}> ({lastResult(data.last_result)})</span>}
            </div>
            <div style={muted}>Last success: {formatMoment(data.last_success_at)}</div>
          </div>
          {data.last_error && <div className="error-message">Last run failed: {data.last_error}</div>}
          {notice && <div style={muted}>{notice}</div>}
          {syncError && <div className="error-message">{syncError}</div>}
        </div>
      )}
    </section>
  );
}
