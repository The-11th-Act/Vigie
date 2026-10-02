import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import FindingHistory from './FindingHistory';
import { vulnerabilityService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { useAuth } from '../auth/AuthContext';
import { Download } from 'lucide-react';
import Pagination from './Pagination';

const PAGE_SIZE = 20;
const STATUSES = ['Open', 'False Positive', 'Risk Accepted', 'Remediated'];
const STATUSES_REQUIRING_NOTE = new Set(['False Positive', 'Risk Accepted']);

// Mirrors the EPSS bands of the risk model (app/services/risk_scoring.py).
const EPSS_THRESHOLDS = [
  { value: '0.5', label: 'EPSS ≥ 50%' },
  { value: '0.1', label: 'EPSS ≥ 10%' },
  { value: '0.01', label: 'EPSS ≥ 1%' },
];

// A date picked in the form means "until the end of that day", local time.
function endOfDay(isoDate) {
  return new Date(`${isoDate}T23:59:00`).toISOString();
}

function tomorrow() {
  const day = new Date();
  day.setDate(day.getDate() + 1);
  return day.toISOString().slice(0, 10);
}

function formatEpss(score) {
  const percent = score * 100;
  return `EPSS ${percent < 10 ? percent.toFixed(1) : Math.round(percent)}%`;
}

function describeFactor(factor) {
  if (factor.multiplier != null) return `${factor.label} (×${factor.multiplier})`;
  if (factor.points != null) return `${factor.label} (+${factor.points.toFixed(2)})`;
  return factor.label;
}

function kevTitle(vuln) {
  const parts = ['Known exploited in the wild (CISA KEV)'];
  if (vuln.kev_date_added) parts.push(`listed ${formatDate(vuln.kev_date_added)}`);
  if (vuln.kev_due_date) parts.push(`CISA due date ${formatDate(vuln.kev_due_date)}`);
  if (vuln.kev_ransomware) parts.push('used in ransomware campaigns');
  return parts.join(' · ');
}

// One entry per action: two sources prescribing the same KB show it once.
function remediationsOf(finding) {
  const byReference = new Map();
  for (const link of finding.remediations || []) {
    const current = byReference.get(link.action.reference);
    if (!current || (!current.fixed_version && link.fixed_version)) {
      byReference.set(link.action.reference, link);
    }
  }
  return [...byReference.values()];
}

function RemediationCell({ finding }) {
  const links = remediationsOf(finding);
  if (links.length === 0) {
    return <span style={{ color: 'var(--text-muted)' }}>-</span>;
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem', maxWidth: 260 }}>
      {links.map(({ action, fixed_version: fixedVersion }) => {
        const label = action.kind === 'kb' ? action.reference : action.title || action.reference;
        const detail = [action.title, fixedVersion && `Fixed in ${fixedVersion}`]
          .filter(Boolean)
          .join(' · ');
        return (
          <div key={action.reference} title={detail || undefined} style={{ fontSize: '0.8rem' }}>
            {action.kind === 'kb' ? (
              <span className="badge badge-low" style={{ fontFamily: 'monospace' }}>{label}</span>
            ) : (
              <span style={{ display: 'block', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {action.kind === 'no_fix' ? 'No fix available' : label}
              </span>
            )}
            {fixedVersion && (
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>→ {fixedVersion}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function formatDate(value) {
  if (!value) return '-';
  return new Date(value).toLocaleDateString();
}

export default function FindingsBacklog() {
  // A remediator marks fixes done; deciding a risk is acceptable is not
  // theirs, and the API refuses it. The current status stays listed.
  const isRemediator = useAuth().user?.role === 'remediator';
  const triageOptions = (finding) =>
    isRemediator
      ? STATUSES.filter((s) => !STATUSES_REQUIRING_NOTE.has(s) || s === finding.status)
      : STATUSES;
  const [page, setPage] = useState(0);
  const [statusFilter, setStatusFilter] = useState('');
  const [minRisk, setMinRisk] = useState('');
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [kevOnly, setKevOnly] = useState(false);
  const [minEpss, setMinEpss] = useState('');
  const [rowState, setRowState] = useState({});
  const [historyOf, setHistoryOf] = useState(null);
  const queryClient = useQueryClient();

  // The same filters feed the screen and the export, so the file holds
  // exactly what the analyst is looking at (every page of it).
  const filterParams = {
    status_filter: statusFilter || undefined,
    min_risk: minRisk || undefined,
    overdue_only: overdueOnly || undefined,
    kev_only: kevOnly || undefined,
    min_epss: minEpss || undefined,
  };


  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState(null);

  const handleExport = async () => {
    setExporting(true);
    setExportError(null);
    try {
      const res = await vulnerabilityService.exportFindings(filterParams);
      const url = URL.createObjectURL(res.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = `vigie-backlog-${new Date().toISOString().slice(0, 10)}.csv`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setExportError(err.message || 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  const { data, loading, error, refetch } = useApiQuery(
    ['findings', 'backlog', { page, ...filterParams }],
    async () =>
      (await vulnerabilityService.getFindings({ skip: page * PAGE_SIZE, limit: PAGE_SIZE, ...filterParams }))
        .data
  );

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  const getRow = (id) =>
    rowState[id] || { status: '', note: '', until: '', submitting: false, error: null };

  const setRow = (id, patch) => {
    setRowState((prev) => ({ ...prev, [id]: { ...getRow(id), ...patch } }));
  };

  const handleStatusChange = (finding, newStatus) => {
    setRow(finding.id, { status: newStatus, note: '', until: '', error: null });
  };

  const handleSubmit = async (finding) => {
    const row = getRow(finding.id);
    const nextStatus = row.status || finding.status;

    setRow(finding.id, { submitting: true, error: null });
    try {
      await vulnerabilityService.updateFinding(finding.id, {
        status: nextStatus,
        status_note: row.note || undefined,
        // Left empty, the API applies its default duration.
        accepted_until:
          nextStatus === 'Risk Accepted' && row.until ? endOfDay(row.until) : undefined,
      });
      setRow(finding.id, { submitting: false, status: '', note: '', until: '' });
      refetch();
      // The change is the newest line of its history.
      queryClient.invalidateQueries({ queryKey: ['findings', 'history', finding.id] });
    } catch (err) {
      setRow(finding.id, {
        submitting: false,
        error: err.response?.data?.detail || err.message || 'Update failed',
      });
    }
  };

  return (
    <div>
      <h1>Risk-Ranked Backlog ({data?.total || 0})</h1>

      <div
        className="filters"
        style={{ marginBottom: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}
      >
        <select
          value={statusFilter}
          onChange={(e) => {
            setStatusFilter(e.target.value);
            setPage(0);
          }}
          style={{
            padding: '0.6rem 0.75rem', background: 'rgba(255,255,255,0.05)',
            border: '1px solid var(--border)', borderRadius: '8px',
            color: 'var(--text-main)', fontSize: '0.875rem', outline: 'none', cursor: 'pointer',
          }}
        >
          <option value="">All Statuses</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>

        <input
          type="number"
          min="0"
          max="10"
          step="0.1"
          placeholder="Min risk score"
          value={minRisk}
          onChange={(e) => {
            setMinRisk(e.target.value);
            setPage(0);
          }}
          style={{
            width: 140, padding: '0.6rem 0.75rem',
            background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
            borderRadius: '8px', color: 'var(--text-main)', fontSize: '0.875rem', outline: 'none',
          }}
        />

        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          <input
            type="checkbox"
            checked={overdueOnly}
            onChange={(e) => {
              setOverdueOnly(e.target.checked);
              setPage(0);
            }}
          />
          Overdue only
        </label>

        <select
          aria-label="Exploitation likelihood"
          value={minEpss}
          onChange={(e) => {
            setMinEpss(e.target.value);
            setPage(0);
          }}
          style={{
            padding: '0.6rem 0.75rem', background: 'rgba(255,255,255,0.05)',
            border: '1px solid var(--border)', borderRadius: '8px',
            color: 'var(--text-main)', fontSize: '0.875rem', outline: 'none', cursor: 'pointer',
          }}
        >
          <option value="">Any EPSS</option>
          {EPSS_THRESHOLDS.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>

        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => {
              setKevOnly(e.target.checked);
              setPage(0);
            }}
          />
          Known exploited (KEV) only
        </label>

        <button
          type="button"
          className="button"
          onClick={handleExport}
          disabled={exporting}
          style={{ marginLeft: 'auto', padding: '0.5rem 0.9rem', fontSize: '0.85rem' }}
        >
          <Download size={16} />
          {exporting ? 'Exporting...' : 'Export CSV'}
        </button>
      </div>
      {exportError && <div className="error-message">Export failed: {exportError}</div>}

      {loading && <div className="loading">Loading backlog...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && (
        <>
          <div className="glass-panel data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>CVE</th>
                  <th>Fix</th>
                  <th>Risk</th>
                  <th>Deadline</th>
                  <th>Status</th>
                  <th>Triage</th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                      No findings match these filters
                    </td>
                  </tr>
                ) : (
                  data.items.map((finding) => {
                    const row = getRow(finding.id);
                    const pendingStatus = row.status || finding.status;
                    const noteRequired = STATUSES_REQUIRING_NOTE.has(pendingStatus);
                    const isChanged = row.status && row.status !== finding.status;

                    return (
                      <tr key={finding.id}>
                        <td>
                          {finding.asset?.hostname || finding.asset?.ip_address || `Asset #${finding.asset_id}`}
                          {finding.asset?.internet_facing && (
                            <div>
                              <span className="badge badge-medium" title="Reachable from the Internet">
                                Exposed
                              </span>
                            </div>
                          )}
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                            <span style={{ fontWeight: 600, color: 'var(--accent)', fontFamily: 'monospace' }}>
                              {finding.vulnerability?.cve_id}
                            </span>
                            {finding.vulnerability?.in_kev && (
                              <span className="badge badge-critical" title={kevTitle(finding.vulnerability)}>
                                KEV
                              </span>
                            )}
                            {finding.vulnerability?.epss_score != null && (
                              <span
                                className="badge badge-low"
                                title="Probability of exploitation in the next 30 days (FIRST EPSS)"
                              >
                                {formatEpss(finding.vulnerability.epss_score)}
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', maxWidth: 320, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {finding.vulnerability?.title}
                          </div>
                        </td>
                        <td>
                          <RemediationCell finding={finding} />
                        </td>
                        <td>
                          <span
                            className={`badge badge-${finding.risk_level.toLowerCase()}`}
                            title={finding.risk_factors?.length ? finding.risk_factors.map(describeFactor).join('\n') : undefined}
                          >
                            {finding.risk_score.toFixed(2)}
                          </span>
                        </td>
                        <td>
                          {formatDate(finding.remediation_deadline)}
                          {finding.is_overdue && (
                            <div style={{ fontSize: '0.75rem', color: 'var(--high)' }}>Overdue</div>
                          )}
                        </td>
                        <td>
                          {finding.status}
                          {finding.accepted_until && (
                            <div
                              style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
                              title="Reopened automatically after this date"
                            >
                              until {formatDate(finding.accepted_until)}
                            </div>
                          )}
                          {finding.sources?.length > 0 && (
                            <div
                              style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}
                              title="Scanners reporting this finding; it closes once all of them stop"
                            >
                              {finding.sources.map((s) => s.source).join(' · ')}
                            </div>
                          )}
                        </td>
                        <td>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', minWidth: 220 }}>
                            <select
                              value={pendingStatus}
                              onChange={(e) => handleStatusChange(finding, e.target.value)}
                              style={{
                                padding: '0.4rem 0.5rem', background: 'rgba(255,255,255,0.05)',
                                border: '1px solid var(--border)', borderRadius: '6px',
                                color: 'var(--text-main)', fontSize: '0.8rem', outline: 'none', cursor: 'pointer',
                              }}
                            >
                              {triageOptions(finding).map((s) => <option key={s} value={s}>{s}</option>)}
                            </select>

                            {isChanged && noteRequired && (
                              <textarea
                                placeholder="Justification required..."
                                value={row.note}
                                onChange={(e) => setRow(finding.id, { note: e.target.value })}
                                rows={2}
                                style={{
                                  padding: '0.4rem 0.5rem', background: 'rgba(255,255,255,0.05)',
                                  border: '1px solid var(--border)', borderRadius: '6px',
                                  color: 'var(--text-main)', fontSize: '0.8rem', outline: 'none', resize: 'vertical',
                                }}
                              />
                            )}

                            {isChanged && pendingStatus === 'Risk Accepted' && (
                              <label style={{ display: 'flex', flexDirection: 'column', gap: '0.2rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                Accepted until (empty: default duration)
                                <input
                                  type="date"
                                  min={tomorrow()}
                                  value={row.until}
                                  onChange={(e) => setRow(finding.id, { until: e.target.value })}
                                  style={{
                                    padding: '0.3rem 0.5rem', background: 'rgba(255,255,255,0.05)',
                                    border: '1px solid var(--border)', borderRadius: '6px',
                                    color: 'var(--text-main)', fontSize: '0.8rem', outline: 'none',
                                  }}
                                />
                              </label>
                            )}

                            {isChanged && (
                              <button
                                className="button"
                                disabled={row.submitting || (noteRequired && !row.note.trim())}
                                onClick={() => handleSubmit(finding)}
                                style={{ padding: '0.4rem 0.75rem', fontSize: '0.8rem', justifyContent: 'center' }}
                              >
                                {row.submitting ? 'Saving...' : 'Save'}
                              </button>
                            )}

                            {row.error && <div className="error-message" style={{ padding: '0.4rem 0.6rem', fontSize: '0.75rem' }}>{row.error}</div>}

                            <button
                              type="button"
                              className="icon-button"
                              onClick={() => setHistoryOf(historyOf === finding.id ? null : finding.id)}
                              aria-expanded={historyOf === finding.id}
                              aria-label={`History of ${finding.vulnerability?.cve_id || 'this finding'} on ${finding.asset?.hostname || finding.asset?.ip_address || 'this host'}`}
                              style={{ fontSize: '0.75rem', alignSelf: 'flex-start' }}
                            >
                              History
                            </button>
                            {historyOf === finding.id && <FindingHistory findingId={finding.id} />}
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          <Pagination page={page} totalPages={totalPages} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}
