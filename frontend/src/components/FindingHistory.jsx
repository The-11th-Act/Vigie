import React from 'react';
import { vulnerabilityService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { muted } from './RemediationShared';

function formatMoment(value) {
  return value ? new Date(value).toLocaleString() : '';
}

// Who moved a finding, when, and why: the trail an audit asks for (who
// accepted this risk, until when). "system" is the daily pass or a scan.
export default function FindingHistory({ findingId }) {
  const { data, loading, error } = useApiQuery(['findings', 'history', findingId], async () =>
    (await vulnerabilityService.getFindingHistory(findingId)).data
  );

  if (loading && !data) return <div style={muted}>Loading the history...</div>;
  if (error && !data) return <div className="error-message" style={{ fontSize: '0.75rem' }}>{error}</div>;
  if (!data || data.length === 0) return <div style={muted}>No change recorded yet.</div>;

  return (
    <ol aria-label="Triage history" style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.4rem', fontSize: '0.75rem' }}>
      {data.map((entry) => (
        <li key={entry.id} style={{ borderLeft: '2px solid var(--border)', paddingLeft: '0.5rem' }}>
          <div>
            <strong>{entry.old_status ? `${entry.old_status} → ${entry.new_status}` : entry.new_status}</strong>
            <span style={muted}> · {entry.username || 'unknown'} · {formatMoment(entry.created_at)}</span>
          </div>
          {entry.accepted_until && (
            <div style={muted}>Accepted until {new Date(entry.accepted_until).toLocaleDateString()}</div>
          )}
          {entry.status_note && <div style={{ whiteSpace: 'pre-line' }}>{entry.status_note}</div>}
        </li>
      ))}
    </ol>
  );
}
