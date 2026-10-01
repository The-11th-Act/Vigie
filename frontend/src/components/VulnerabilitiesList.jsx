import React, { useState } from 'react';
import { vulnerabilityService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import Pagination from './Pagination';
import SearchInput from './SearchInput';

const PAGE_SIZE = 20;
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

export default function VulnerabilitiesList() {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const debouncedSearch = useDebouncedValue(search);
  const [severity, setSeverity] = useState('');

  const { data, loading, error } = useApiQuery(
    ['vulnerabilities', 'catalog', { page, search: debouncedSearch, severity }],
    async () => {
      const res = await vulnerabilityService.list({
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
        search: debouncedSearch || undefined,
        severity: severity || undefined,
      });
      return res.data;
    }
  );

  const handleSearchChange = (value) => {
    setSearch(value);
    setPage(0);
  };

  const handleSeverityChange = (e) => {
    setSeverity(e.target.value);
    setPage(0);
  };

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div>
      <h1>Vulnerability Database ({data?.total || 0})</h1>

      <div className="filters" style={{marginBottom: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap'}}>
        <SearchInput
          value={search}
          onChange={handleSearchChange}
          placeholder="Search by CVE or title..."
          style={{flex: 1, maxWidth: 400}}
        />
        <select
          aria-label="Severity"
          value={severity}
          onChange={handleSeverityChange}
          style={{
            padding: '0.6rem 0.75rem', background: 'rgba(255,255,255,0.05)',
            border: '1px solid var(--border)', borderRadius: '8px',
            color: 'var(--text-main)', fontSize: '0.875rem', outline: 'none', cursor: 'pointer',
          }}
        >
          <option value="">All Severities</option>
          {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {loading && <div className="loading">Loading vulnerabilities...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && (
        <>
          <div className="glass-panel data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Title</th>
                  <th>CVSS</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 ? (
                  <tr><td colSpan={4} style={{textAlign: 'center', padding: '2rem', color: 'var(--text-muted)'}}>No vulnerabilities found</td></tr>
                ) : (
                  data.items.map(vuln => (
                    <tr key={vuln.id}>
                      <td style={{fontWeight: 600, color: 'var(--accent)', fontFamily: 'monospace'}}>{vuln.cve_id}</td>
                      <td style={{maxWidth: '400px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}}>
                        {vuln.title}
                      </td>
                      <td style={{fontFamily: 'monospace'}}>{vuln.cvss_score.toFixed(1)}</td>
                      <td>
                        <span className={`badge badge-${vuln.severity.toLowerCase()}`}>
                          {vuln.severity}
                        </span>
                      </td>
                    </tr>
                  ))
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