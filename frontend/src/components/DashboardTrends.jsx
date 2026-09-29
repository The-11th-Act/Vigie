import React, { useCallback, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { dashboardService } from '../services';
import { useFetch } from '../hooks/useFetch';
import { useAuth } from '../auth/AuthContext';
import { controlStyle, muted } from './RemediationShared';

const NOT_SET = '__none__';
const TOOLTIP_STYLE = { backgroundColor: 'rgba(15, 17, 21, 0.95)', border: '1px solid #333', borderRadius: '8px' };

function formatDay(value) {
  return new Date(`${value}T00:00:00Z`).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

function orDash(value, suffix = '') {
  return value === null || value === undefined ? '-' : `${value}${suffix}`;
}

// Monday of the week of a day, as the key a weekly bar groups on.
function weekOf(day) {
  const date = new Date(`${day}T00:00:00Z`);
  const offset = (date.getUTCDay() + 6) % 7;
  date.setUTCDate(date.getUTCDate() - offset);
  return date.toISOString().slice(0, 10);
}

export function weekly(points) {
  const weeks = new Map();
  for (const point of points) {
    const key = weekOf(point.day);
    const week = weeks.get(key) || { week: key, new_findings: 0, fixed: 0 };
    week.new_findings += point.new_findings;
    week.fixed += point.fixed;
    weeks.set(key, week);
  }
  return [...weeks.values()];
}

function Kpi({ label, value, hint, tone }) {
  return (
    <div className="glass-panel kpi-card" title={hint}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={tone ? { color: tone } : undefined}>{value}</div>
    </div>
  );
}

function Delta({ now, before, lowerIsBetter = true, digits = 0 }) {
  const change = now - before;
  if (!before && !now) return null;
  const better = lowerIsBetter ? change < 0 : change > 0;
  const color = change === 0 ? 'var(--text-muted)' : better ? '#22c55e' : 'var(--high)';
  const sign = change > 0 ? '+' : '';
  return (
    <div style={{ fontSize: '0.8rem', color }}>
      {sign}{change.toFixed(digits)} since the start of the period
    </div>
  );
}

export default function DashboardTrends() {
  const isAdmin = useAuth().user?.role === 'admin';
  const [team, setTeam] = useState('');
  const [period, setPeriod] = useState(30);
  const [history, setHistory] = useState(90);
  const [rebuilding, setRebuilding] = useState(false);
  const [rebuildError, setRebuildError] = useState(null);

  const fetchPerformance = useCallback(
    async () =>
      (await dashboardService.getPerformance({ days: period, owner_team: team || undefined })).data,
    [period, team]
  );
  const fetchTrends = useCallback(
    async () =>
      (await dashboardService.getTrends({ days: history, owner_team: team || undefined })).data,
    [history, team]
  );
  const { data: perf, loading, error } = useFetch(fetchPerformance, [period, team]);
  const { data: trends, refetch: refetchTrends } = useFetch(fetchTrends, [history, team]);

  const rebuild = async () => {
    setRebuilding(true);
    setRebuildError(null);
    try {
      await dashboardService.rebuildSnapshots();
      refetchTrends();
    } catch (err) {
      setRebuildError(err.response?.data?.detail || err.message || 'Rebuild failed');
    } finally {
      setRebuilding(false);
    }
  };

  const points = trends?.points || [];
  const firstExact = points.find((p) => !p.estimated);
  const hasEstimated = points.some((p) => p.estimated);

  return (
    <div>
      <h1>Trends &amp; remediation</h1>

      <div style={{ margin: '1rem 0', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <select aria-label="Team" value={team} onChange={(e) => setTeam(e.target.value)} style={{ ...controlStyle, cursor: 'pointer' }}>
          <option value="">All teams</option>
          {(perf?.team_names || []).map((name) => <option key={name} value={name}>{name}</option>)}
          <option value={NOT_SET}>Unassigned hosts</option>
        </select>
        <select aria-label="Period" value={period} onChange={(e) => setPeriod(Number(e.target.value))} style={{ ...controlStyle, cursor: 'pointer' }}>
          {[7, 30, 90].map((d) => <option key={d} value={d}>Last {d} days</option>)}
        </select>
      </div>

      {loading && !perf && <div className="loading">Loading performance...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {perf && (
        <div className="kpi-grid">
          <Kpi label="Fixed" value={perf.fixed.toLocaleString()} hint="Findings actually fixed (not accepted or dismissed) in the period" />
          <Kpi
            label="Deadlines kept"
            value={orDash(perf.sla_percent, ' %')}
            hint="Share of the fixes made before their remediation deadline"
            tone={perf.sla_percent !== null && perf.sla_percent < 80 ? 'var(--high)' : undefined}
          />
          <Kpi label="Mean time to remediate" value={orDash(perf.mttr_days, ' d')} hint="From detection to fix, for the fixes of the period" />
          <Kpi label="Risk removed" value={perf.risk_removed.toFixed(1)} hint="Sum of the risk of the findings fixed in the period" />
          <div className="glass-panel kpi-card">
            <div className="kpi-label">Open findings</div>
            <div className="kpi-value">{perf.open_now.toLocaleString()}</div>
            <Delta now={perf.open_now} before={perf.open_at_start} />
          </div>
          <div className="glass-panel kpi-card">
            <div className="kpi-label">Open risk</div>
            <div className="kpi-value">{perf.open_risk_now.toFixed(1)}</div>
            <Delta now={perf.open_risk_now} before={perf.open_risk_at_start} digits={1} />
          </div>
        </div>
      )}

      <div className="glass-panel" style={{ marginTop: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
          <h3 style={{ color: 'var(--text-muted)', flex: 1 }}>Open backlog, day by day</h3>
          <select aria-label="History" value={history} onChange={(e) => setHistory(Number(e.target.value))} className="select">
            {[30, 90, 180, 365].map((d) => <option key={d} value={d}>{d} days</option>)}
          </select>
        </div>
        {points.length === 0 ? (
          <div style={muted}>
            No history yet: the daily pass records one day at a time, and rebuilds the last 90 days on its first run.
            {isAdmin && (
              <div style={{ marginTop: '0.75rem' }}>
                <button type="button" className="button" disabled={rebuilding} onClick={rebuild} style={{ padding: '0.45rem 0.9rem', fontSize: '0.85rem' }}>
                  {rebuilding ? 'Building...' : 'Build the history now'}
                </button>
                {rebuildError && <div className="error-message" style={{ marginTop: '0.5rem' }}>{rebuildError}</div>}
              </div>
            )}
          </div>
        ) : (
          <>
            <div style={{ height: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={points} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis dataKey="day" tickFormatter={formatDay} stroke="#94a3b8" minTickGap={24} />
                  <YAxis yAxisId="risk" stroke="#ef4444" />
                  <YAxis yAxisId="count" orientation="right" stroke="#3b82f6" allowDecimals={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} labelFormatter={formatDay} />
                  <Legend />
                  <Line yAxisId="risk" type="monotone" dataKey="open_risk" name="Open risk" stroke="#ef4444" dot={false} />
                  <Line yAxisId="count" type="monotone" dataKey="open_findings" name="Open findings" stroke="#3b82f6" dot={false} />
                  <Line yAxisId="count" type="monotone" dataKey="overdue" name="Overdue" stroke="#f97316" dot={false} strokeDasharray="4 3" />
                </LineChart>
              </ResponsiveContainer>
            </div>
            {hasEstimated && (
              <div style={{ ...muted, marginTop: '0.5rem' }}>
                {firstExact
                  ? `Before ${formatDay(firstExact.day)}, days are rebuilt from detection and fix dates (estimated).`
                  : 'These days are rebuilt from detection and fix dates (estimated).'}
              </div>
            )}
          </>
        )}
      </div>

      {points.length > 0 && (
        <div className="glass-panel" style={{ marginTop: '2rem', height: 300 }}>
          <h3 style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>New findings and fixes, per week</h3>
          <ResponsiveContainer width="100%" height="85%">
            <BarChart data={weekly(points)} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis dataKey="week" tickFormatter={formatDay} stroke="#94a3b8" />
              <YAxis stroke="#94a3b8" allowDecimals={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} labelFormatter={(w) => `Week of ${formatDay(w)}`} />
              <Legend />
              <Bar dataKey="new_findings" name="New" fill="#f97316" radius={[4, 4, 0, 0]} />
              <Bar dataKey="fixed" name="Fixed" fill="#22c55e" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {perf && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.5rem', marginTop: '2rem' }}>
          <div className="glass-panel">
            <h3 style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>Time to remediate by criticality</h3>
            <table className="data-table">
              <tbody>
                {Object.entries(perf.mttr_by_criticality).map(([level, days]) => (
                  <tr key={level}>
                    <td><span className={`badge badge-${level.toLowerCase()}`}>{level}</span></td>
                    <td>{days === null ? <span style={muted}>no fix in the period</span> : `${days} days`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="glass-panel data-table-container" style={{ gridColumn: '1 / -1' }}>
            <h3 style={{ color: 'var(--text-muted)', marginBottom: '1rem' }}>Teams</h3>
            {perf.teams.length === 0 ? (
              <div style={muted}>No open finding and no fix in the period.</div>
            ) : (
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Team</th>
                    <th>Open</th>
                    <th>Overdue</th>
                    <th>Open risk</th>
                    <th>Fixed</th>
                    <th>Deadlines kept</th>
                    <th>Time to fix</th>
                    <th title="Active now / resolved in the period">Tickets</th>
                  </tr>
                </thead>
                <tbody>
                  {perf.teams.map((row) => (
                    <tr key={row.key}>
                      <td style={row.key === NOT_SET ? { color: 'var(--text-muted)' } : undefined}>{row.team}</td>
                      <td>{row.open}{row.kev > 0 && <span className="badge badge-critical" style={{ marginLeft: '0.4rem' }}>{row.kev} KEV</span>}</td>
                      <td style={row.overdue ? { color: 'var(--high)' } : undefined}>{row.overdue}</td>
                      <td style={{ fontWeight: 600 }}>{row.open_risk.toFixed(1)}</td>
                      <td>{row.fixed}</td>
                      <td>{orDash(row.sla_percent, ' %')}</td>
                      <td>{orDash(row.mttr_days, ' d')}</td>
                      <td>{row.active_tickets} / {row.resolved_tickets}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
