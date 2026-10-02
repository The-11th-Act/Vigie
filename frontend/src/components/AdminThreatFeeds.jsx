import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { RefreshCw, Upload } from 'lucide-react';
import { threatIntelService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { errorText } from './AdminAccounts';
import { muted } from './RemediationShared';

const FEEDS_KEY = ['admin', 'threat-intel'];
const FEED_LABELS = { kev: 'CISA KEV', epss: 'FIRST EPSS' };

function formatMoment(value) {
  return value ? new Date(value).toLocaleString() : 'never';
}

function FeedRow({ feed }) {
  return (
    <tr>
      <td>{FEED_LABELS[feed.feed] || feed.feed}</td>
      <td>
        <span className={`badge ${feed.stale ? 'badge-medium' : 'badge-low'}`}>{feed.stale ? 'Stale' : 'Fresh'}</span>
      </td>
      <td>{formatMoment(feed.last_success_at)}</td>
      <td>{feed.records.toLocaleString()}</td>
      <td style={muted}>
        {[feed.source_version, feed.source_date].filter(Boolean).join(' · ') || '-'}
        {feed.last_error && (
          <div className="error-message" style={{ fontSize: '0.75rem', marginTop: '0.25rem' }}>
            Last attempt failed: {feed.last_error}
          </div>
        )}
      </td>
    </tr>
  );
}

// The KEV catalogue and the EPSS scores weigh on every risk score. Without
// Internet access the daily refresh is off and the files are imported here.
export default function AdminThreatFeeds() {
  const queryClient = useQueryClient();
  const { data, loading, error } = useApiQuery(FEEDS_KEY, async () => (await threatIntelService.status()).data);
  const [feed, setFeed] = useState('kev');
  const [file, setFile] = useState(null);
  const [force, setForce] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(null);
  const [actionError, setActionError] = useState(null);

  const act = async (request, describe) => {
    setBusy(true);
    setNotice(null);
    setActionError(null);
    try {
      const res = await request();
      setNotice(describe(res.data));
      queryClient.invalidateQueries({ queryKey: FEEDS_KEY });
    } catch (err) {
      setActionError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  const refresh = () =>
    act(
      () => threatIntelService.refresh(),
      () => 'Refresh queued: the feeds update once the worker has pulled them.'
    );

  const importFile = (event) => {
    event.preventDefault();
    act(
      () => threatIntelService.importFeed(feed, file, force),
      (result) =>
        `${FEED_LABELS[result.feed] || result.feed} ${result.status}: ${result.records.toLocaleString()} records, ` +
        `${result.changed} CVE(s) changed, ${result.rescored} finding(s) rescored.`
    );
  };

  return (
    <section style={{ marginBottom: '2.5rem' }}>
      <h2 style={{ fontSize: '1.15rem', marginBottom: '0.5rem' }}>Threat feeds</h2>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
        CISA KEV (exploited in the wild) and FIRST EPSS (probability of exploitation) weigh on every risk score.
        {data && !data.enabled && ' The daily refresh is off (THREAT_INTEL_ENABLED): import the files below.'}
      </p>
      {loading && !data && <div className="loading">Loading the feeds...</div>}
      {error && !data && <div className="error-message">Error: {error}</div>}
      {data && (
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Feed</th>
                  <th>State</th>
                  <th>Last applied</th>
                  <th>Records</th>
                  <th>Source</th>
                </tr>
              </thead>
              <tbody>
                {data.feeds.map((item) => (
                  <FeedRow key={item.feed} feed={item} />
                ))}
              </tbody>
            </table>
          </div>
          <div style={muted}>Stale after {data.stale_after_hours} hours without a successful update.</div>

          <div>
            <button type="button" className="icon-button" onClick={refresh} disabled={busy || !data.enabled}>
              <RefreshCw size={14} /> Refresh now
            </button>
          </div>

          <form onSubmit={importFile} aria-label="Import a feed file" style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap' }}>
            <select className="select" value={feed} onChange={(e) => setFeed(e.target.value)} aria-label="Feed to import">
              <option value="kev">CISA KEV (JSON)</option>
              <option value="epss">FIRST EPSS (CSV, gzip or not)</option>
            </select>
            <input
              type="file"
              accept=".json,.csv,.gz"
              onChange={(e) => setFile(e.target.files[0] || null)}
              aria-label="Feed file"
            />
            <label style={{ ...muted, display: 'flex', gap: '0.3rem', alignItems: 'center' }}>
              <input type="checkbox" checked={force} onChange={(e) => setForce(e.target.checked)} />
              Apply even if older or much smaller than the current one
            </label>
            <button type="submit" className="button" disabled={busy || !file}>
              <Upload size={14} /> Import
            </button>
          </form>
          {notice && <div style={muted}>{notice}</div>}
          {actionError && <div className="error-message">{actionError}</div>}
        </div>
      )}
    </section>
  );
}
