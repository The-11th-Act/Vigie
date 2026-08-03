import React, { useState, useCallback, useEffect, useRef } from 'react';
import { vulnerabilityService } from '../services';
import { useFetch } from '../hooks/useFetch';
import { Search, ChevronLeft, ChevronRight } from 'lucide-react';

const PAGE_SIZE = 20;
const SEVERITIES = ['Critical', 'High', 'Medium', 'Low'];

export default function VulnerabilitiesList() {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [severity, setSeverity] = useState('');

  const fetchVulns = useCallback(async () => {
    const res = await vulnerabilityService.list({
      skip: page * PAGE_SIZE,
      limit: PAGE_SIZE,
      search: debouncedSearch || undefined,
      severity: severity || undefined,
    });
    return res.data;
  }, [page, debouncedSearch, severity]);

  const { data, loading, error } = useFetch(fetchVulns, [page, debouncedSearch, severity]);

  // Debounce held in a ref rather than on `window`: a module-level global was
  // shared with every other list and leaked its timer between components.
  const searchTimer = useRef(null);

  useEffect(() => {
    searchTimer.current = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(0);
    }, 300);
    return () => clearTimeout(searchTimer.current);
  }, [search]);

  const handleSeverityChange = (e) => {
    setSeverity(e.target.value);
    setPage(0);
  };

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div>
      <h1>Vulnerability Database ({data?.total || 0})</h1>

      <div className="filters" style={{marginBottom: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap'}}>
        <div style={{position: 'relative', flex: 1, maxWidth: 400}}>
          <Search size={16} style={{position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)'}} />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by CVE or title..."
            style={{
              width: '100%', padding: '0.6rem 0.75rem 0.6rem 2.25rem',
              background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
              borderRadius: '8px', color: 'var(--text-main)', fontSize: '0.875rem', outline: 'none',
            }}
          />
        </div>
        <select
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

          {totalPages > 1 && (
            <div className="pagination" style={{display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '1rem', marginTop: '1.5rem'}}>
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                style={{background: 'none', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.4rem 0.6rem', color: 'var(--text-main)', cursor: page === 0 ? 'not-allowed' : 'pointer', opacity: page === 0 ? 0.4 : 1}}
              >
                <ChevronLeft size={18} />
              </button>
              <span style={{color: 'var(--text-muted)', fontSize: '0.875rem'}}>
                Page {page + 1} of {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                style={{background: 'none', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.4rem 0.6rem', color: 'var(--text-main)', cursor: page >= totalPages - 1 ? 'not-allowed' : 'pointer', opacity: page >= totalPages - 1 ? 0.4 : 1}}
              >
                <ChevronRight size={18} />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}