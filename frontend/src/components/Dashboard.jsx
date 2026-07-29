import React from 'react';
import { useFetch } from '../hooks/useFetch';
import { dashboardService } from '../services';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import { AlertTriangle, Server, ShieldAlert, Activity, Clock } from 'lucide-react';

export default function Dashboard() {
  const { data: stats, loading, error } = useFetch(() => dashboardService.getStats().then(r => r.data));
  const { data: topRisks, loading: topRisksLoading } = useFetch(() => dashboardService.getTopRisks(10).then(r => r.data));

  if (loading) return <div className="loading">Loading dashboard...</div>;
  if (error) return <div className="error-message">Error: {error}</div>;

  const chartData = [
    { name: 'Critical', value: stats.severity_breakdown.Critical, color: '#ef4444' },
    { name: 'High', value: stats.severity_breakdown.High, color: '#f97316' },
    { name: 'Medium', value: stats.severity_breakdown.Medium, color: '#eab308' },
    { name: 'Low', value: stats.severity_breakdown.Low, color: '#3b82f6' }
  ];

  return (
    <div>
      <h1>Security Posture Dashboard</h1>

      <div className="kpi-grid">
        <div className="glass-panel kpi-card">
          <div className="kpi-label"><Server size={14} style={{marginRight: 6}} />Total Assets Monitored</div>
          <div className="kpi-value">{stats.total_assets.toLocaleString()}</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-label"><ShieldAlert size={14} style={{marginRight: 6}} />Open Vulnerabilities</div>
          <div className="kpi-value">{stats.total_open_vulnerabilities.toLocaleString()}</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-label"><Activity size={14} style={{marginRight: 6}} />Critical Risks</div>
          <div className="kpi-value" style={{color: 'var(--critical)'}}>{stats.severity_breakdown.Critical.toLocaleString()}</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-label"><Clock size={14} style={{marginRight: 6}} />Overdue SLAs</div>
          <div className="kpi-value" style={{color: 'var(--high)'}}>{(stats.overdue_count || 0).toLocaleString()}</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-label"><AlertTriangle size={14} style={{marginRight: 6}} />Average CVSS</div>
          <div className="kpi-value">{(stats.average_cvss || 0).toFixed(2)}</div>
        </div>
      </div>

      <div className="glass-panel" style={{height: '400px', marginTop: '2rem'}}>
        <h3 style={{marginBottom: '1.5rem', color: 'var(--text-muted)'}}>Vulnerabilities by Severity</h3>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{top: 20, right: 30, left: 20, bottom: 5}}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
            <XAxis dataKey="name" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" allowDecimals={false} />
            <Tooltip contentStyle={{backgroundColor: 'rgba(15, 17, 21, 0.95)', border: '1px solid #333', borderRadius: '8px'}}/>
            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="glass-panel" style={{marginTop: '2rem'}}>
        <h3 style={{marginBottom: '1.5rem', color: 'var(--text-muted)'}}>Top Risks</h3>
        {topRisksLoading && <div className="loading">Loading top risks...</div>}
        {!topRisksLoading && (!topRisks || topRisks.length === 0) && (
          <div style={{color: 'var(--text-muted)', fontSize: '0.9rem'}}>No open findings.</div>
        )}
        {!topRisksLoading && topRisks && topRisks.length > 0 && (
          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>CVE</th>
                  <th>Risk</th>
                  <th>Deadline</th>
                </tr>
              </thead>
              <tbody>
                {topRisks.map(risk => (
                  <tr key={risk.finding_id}>
                    <td>{risk.hostname || risk.ip_address || `Asset #${risk.asset_id}`}</td>
                    <td>
                      <div style={{fontWeight: 600, color: 'var(--accent)', fontFamily: 'monospace'}}>{risk.cve_id}</div>
                      <div style={{fontSize: '0.8rem', color: 'var(--text-muted)', maxWidth: 320, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}}>{risk.title}</div>
                    </td>
                    <td>
                      <span className={`badge badge-${risk.risk_level.toLowerCase()}`}>
                        {risk.risk_score?.toFixed(2)}
                      </span>
                    </td>
                    <td>
                      {risk.remediation_deadline ? new Date(risk.remediation_deadline).toLocaleDateString() : '-'}
                      {risk.is_overdue && <div style={{fontSize: '0.75rem', color: 'var(--high)'}}>Overdue</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}