import React, { useCallback } from 'react';
import { scanService } from '../services';
import { useFetch } from '../hooks/useFetch';

const HISTORY_SIZE = 10;

const STATUS_COLORS = {
  Success: 'var(--low)',
  Failed: 'var(--critical)',
  Running: 'var(--medium)',
  Pending: 'var(--text-muted)',
};

function formatDateTime(value) {
  if (!value) return '-';
  return new Date(value).toLocaleString();
}

/**
 * The last scans the user uploaded (every scan, for an admin).
 *
 * `refreshToken` is bumped by the upload form once a scan finishes, so the new
 * row shows up without a page reload.
 */
export default function ScanHistory({ refreshToken = 0 }) {
  const fetchScans = useCallback(async () => {
    const res = await scanService.list({ limit: HISTORY_SIZE });
    return res.data;
  }, []);

  const { data, loading, error } = useFetch(fetchScans, [refreshToken]);

  return (
    <div style={{ marginTop: '2rem' }}>
      <h2>Recent scans</h2>

      {loading && !data && <div className="loading">Loading scan history...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && data.items.length === 0 && (
        <div style={{ color: 'var(--text-muted)' }}>No scan uploaded yet.</div>
      )}

      {data && data.items.length > 0 && (
        <div className="glass-panel data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Date</th>
                <th>File</th>
                <th>Type</th>
                <th>Status</th>
                <th>Records</th>
                <th>New findings</th>
                <th>Reopened</th>
                <th title="Findings closed because the scan no longer saw them">Auto-closed</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((scan) => (
                <tr key={scan.id}>
                  <td>{formatDateTime(scan.created_at)}</td>
                  <td>{scan.filename}</td>
                  <td>{scan.scan_type}</td>
                  <td
                    style={{ color: STATUS_COLORS[scan.status] }}
                    title={scan.message || undefined}
                  >
                    {scan.status}
                  </td>
                  <td>{scan.processed_records}</td>
                  <td>{scan.new_associations}</td>
                  <td>{scan.reopened}</td>
                  <td>{scan.auto_remediated ?? 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
