import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

export default function Dashboard() {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    axios.get('/api/v1/dashboard/stats').then(res => setStats(res.data)).catch(console.error);
  }, []);

  if (!stats) return <div style={{padding: '2rem'}}>Loading enterprise dashboard...</div>;

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
          <div className="kpi-label">Total Assets Monitored</div>
          <div className="kpi-value">{stats.total_assets.toLocaleString()}</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-label">Open Vulnerabilities</div>
          <div className="kpi-value">{stats.total_open_vulnerabilities.toLocaleString()}</div>
        </div>
        <div className="glass-panel kpi-card">
          <div className="kpi-label">Critical Risks</div>
          <div className="kpi-value" style={{color: 'var(--critical)'}}>{stats.severity_breakdown.Critical.toLocaleString()}</div>
        </div>
      </div>

      <div className="glass-panel" style={{height: '400px', marginTop: '2rem'}}>
        <h3 style={{marginBottom: '1.5rem', color: 'var(--text-muted)'}}>Vulnerabilities by Severity</h3>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} margin={{top: 20, right: 30, left: 20, bottom: 5}}>
            <XAxis dataKey="name" stroke="#94a3b8" />
            <YAxis stroke="#94a3b8" />
            <Tooltip contentStyle={{backgroundColor: 'rgba(15, 17, 21, 0.9)', border: '1px solid #333', borderRadius: '8px'}}/>
            <Bar dataKey="value" radius={[4, 4, 0, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
