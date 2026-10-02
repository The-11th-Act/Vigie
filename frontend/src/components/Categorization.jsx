import { useState } from 'react';
import { categorizationService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { controlStyle, formatDate, muted } from './RemediationShared';

const METRICS = {
  total_risk: { label: 'Open risk', format: (v) => v.toFixed(1) },
  findings: { label: 'Findings', format: (v) => String(v) },
  assets: { label: 'Hosts', format: (v) => String(v) },
};

// Heavier cells redder: the eye goes to the worst crossing first.
function heat(value, max) {
  if (!value || !max) return 'transparent';
  return `rgba(239, 68, 68, ${(0.08 + 0.55 * (value / max)).toFixed(3)})`;
}

function CellFindings({ row, col, columns, kevOnly, rowLabel, colLabel, onClose }) {
  const { data, loading, error } = useApiQuery(
    ['categorization', 'cell', { row, col, columns, kevOnly }],
    async () =>
      (
        await categorizationService.cellFindings({
          columns,
          kev_only: kevOnly || undefined,
          category: row,
          value: col,
          limit: 100,
        })
      ).data
  );

  return (
    <div className="glass-panel" style={{ marginTop: '1.25rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '0.75rem' }}>
        <h2 style={{ fontSize: '1.05rem', flex: 1 }}>
          {rowLabel} × {colLabel}
          {data && <span style={{ ...muted, marginLeft: '0.5rem' }}>{data.total} open finding{data.total === 1 ? '' : 's'}</span>}
        </h2>
        <button type="button" className="icon-button" onClick={onClose}>Close</button>
      </div>
      {loading && <div className="loading">Loading findings...</div>}
      {error && <div className="error-message">Error: {error}</div>}
      {data && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Asset</th>
              <th>CVE</th>
              <th>Fix</th>
              <th>Risk</th>
              <th>Deadline</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((finding) => {
              const fixes = [...new Set((finding.remediations || []).map((r) =>
                r.action.kind === 'kb' ? r.action.reference : r.action.title || r.action.reference
              ))];
              return (
                <tr key={finding.id}>
                  <td>
                    {finding.asset?.hostname || finding.asset?.ip_address}
                    {finding.asset?.owner_team && <div style={muted}>{finding.asset.owner_team}</div>}
                  </td>
                  <td>
                    <span style={{ fontFamily: 'monospace', color: 'var(--accent)' }}>{finding.vulnerability?.cve_id}</span>
                    {finding.vulnerability?.in_kev && (
                      <span className="badge badge-critical" style={{ marginLeft: '0.4rem' }}>KEV</span>
                    )}
                    <div style={{ ...muted, maxWidth: 320, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {finding.vulnerability?.title}
                    </div>
                  </td>
                  <td style={{ fontSize: '0.8rem' }}>{fixes.join(', ') || '-'}</td>
                  <td>
                    <span className={`badge badge-${finding.risk_level.toLowerCase()}`}>{finding.risk_score.toFixed(2)}</span>
                  </td>
                  <td>
                    {formatDate(finding.remediation_deadline)}
                    {finding.is_overdue && <div style={{ ...muted, color: 'var(--high)' }}>Overdue</div>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {data && data.total > data.items.length && (
        <div style={{ ...muted, marginTop: '0.5rem' }}>
          The {data.items.length} worst shown; the API Extracts module exports them all.
        </div>
      )}
    </div>
  );
}

export default function Categorization() {
  const [columns, setColumns] = useState('asset_type');
  const [metric, setMetric] = useState('total_risk');
  const [kevOnly, setKevOnly] = useState(false);
  const [selected, setSelected] = useState(null);

  const { data, loading, error } = useApiQuery(
    ['categorization', 'matrix', { columns, kevOnly }],
    async () => (await categorizationService.matrix({ columns, kev_only: kevOnly || undefined })).data
  );

  const cells = {};
  let max = 0;
  for (const cell of data?.cells || []) {
    cells[`${cell.row}|${cell.col}`] = cell;
    max = Math.max(max, cell[metric]);
  }
  const rowTotal = (row) =>
    (data?.cells || []).filter((c) => c.row === row).reduce((sum, c) => sum + c[metric], 0);
  const label = (list, key) => list.find((item) => item.key === key)?.label || key;

  return (
    <div>
      <h1>Categorization</h1>
      <p style={{ color: 'var(--text-muted)', margin: '0.5rem 0 1.25rem' }}>
        Open findings by kind of software and kind of host. Click a cell for its findings.
      </p>

      <div style={{ marginBottom: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <label style={{ ...muted, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          Hosts by
          <select
            aria-label="Host dimension"
            value={columns}
            onChange={(e) => {
              setColumns(e.target.value);
              setSelected(null);
            }}
            style={{ ...controlStyle, cursor: 'pointer' }}
          >
            {(data?.dimensions || [{ key: 'asset_type', label: 'Asset type' }]).map((d) => (
              <option key={d.key} value={d.key}>{d.label}</option>
            ))}
          </select>
        </label>
        <label style={{ ...muted, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          Show
          <select aria-label="Measure" value={metric} onChange={(e) => setMetric(e.target.value)} style={{ ...controlStyle, cursor: 'pointer' }}>
            {Object.entries(METRICS).map(([key, m]) => <option key={key} value={key}>{m.label}</option>)}
          </select>
        </label>
        <label style={{ ...muted, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => {
              setKevOnly(e.target.checked);
              setSelected(null);
            }}
          />
          Known exploited (KEV) only
        </label>
      </div>

      {loading && !data && <div className="loading">Loading matrix...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && data.cells.length === 0 && (
        <div className="glass-panel" style={{ color: 'var(--text-muted)' }}>No open finding matches.</div>
      )}

      {data && data.cells.length > 0 && (
        <div className="glass-panel data-table-container">
          <table className="data-table" style={{ tableLayout: 'auto' }}>
            <thead>
              <tr>
                <th>Software \ {data.dimension.label}</th>
                {data.columns.map((col) => <th key={col.key} style={{ textAlign: 'center' }}>{col.label}</th>)}
                <th style={{ textAlign: 'center' }}>Total</th>
              </tr>
            </thead>
            <tbody>
              {data.rows.map((row) => (
                <tr key={row.key}>
                  <td style={{ fontWeight: 600 }}>{row.label}</td>
                  {data.columns.map((col) => {
                    const cell = cells[`${row.key}|${col.key}`];
                    if (!cell) return <td key={col.key} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>·</td>;
                    const isSelected = selected?.row === row.key && selected?.col === col.key;
                    return (
                      <td key={col.key} style={{ padding: 0 }}>
                        <button
                          type="button"
                          onClick={() => setSelected(cell)}
                          aria-label={`${row.label} on ${col.label}: ${cell.findings} findings`}
                          aria-pressed={isSelected}
                          title={`${cell.findings} findings on ${cell.assets} hosts · risk ${cell.total_risk.toFixed(1)} · ${cell.kev} KEV · ${cell.overdue} overdue`}
                          style={{
                            width: '100%',
                            minHeight: 48,
                            border: isSelected ? '2px solid var(--accent)' : '1px solid transparent',
                            background: heat(cell[metric], max),
                            color: 'var(--text-main)',
                            cursor: 'pointer',
                            font: 'inherit',
                            padding: '0.4rem',
                          }}
                        >
                          <div style={{ fontWeight: 600 }}>{METRICS[metric].format(cell[metric])}</div>
                          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                            {cell.kev > 0 ? `${cell.kev} KEV` : `${cell.assets} host${cell.assets === 1 ? '' : 's'}`}
                          </div>
                        </button>
                      </td>
                    );
                  })}
                  <td style={{ textAlign: 'center', ...muted }}>{METRICS[metric].format(rowTotal(row.key))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && data && (
        <CellFindings
          key={`${selected.row}|${selected.col}|${columns}|${kevOnly}`}
          row={selected.row}
          col={selected.col}
          columns={columns}
          kevOnly={kevOnly}
          rowLabel={label(data.rows, selected.row)}
          colLabel={label(data.columns, selected.col)}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
}
