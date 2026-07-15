import React, { useState, useCallback } from 'react';
import { assetService } from '../services';
import { useFetch } from '../hooks/useFetch';
import { Search, ChevronLeft, ChevronRight } from 'lucide-react';

const PAGE_SIZE = 20;

export default function AssetsList() {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  const fetchAssets = useCallback(async () => {
    const res = await assetService.list({
      skip: page * PAGE_SIZE,
      limit: PAGE_SIZE,
      search: debouncedSearch || undefined,
    });
    return res.data;
  }, [page, debouncedSearch]);

  const { data, loading, error } = useFetch(fetchAssets, [page, debouncedSearch]);

  const handleSearch = (e) => {
    setSearch(e.target.value);
    setPage(0);
    clearTimeout(window._searchTimer);
    window._searchTimer = setTimeout(() => setDebouncedSearch(e.target.value), 300);
  };

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div>
      <h1>Assets Inventory ({data?.total || 0})</h1>

      <div className="search-bar" style={{marginBottom: '1rem', display: 'flex', gap: '0.5rem'}}>
        <div style={{position: 'relative', flex: 1, maxWidth: 400}}>
          <Search size={16} style={{position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)'}} />
          <input
            type="text"
            value={search}
            onChange={handleSearch}
            placeholder="Search by IP or hostname..."
            style={{
              width: '100%', padding: '0.6rem 0.75rem 0.6rem 2.25rem',
              background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
              borderRadius: '8px', color: 'var(--text-main)', fontSize: '0.875rem', outline: 'none',
            }}
          />
        </div>
      </div>

      {loading && <div className="loading">Loading assets...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && (
        <>
          <div className="glass-panel data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>IP Address</th>
                  <th>Hostname</th>
                  <th>Operating System</th>
                  <th>Criticality</th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 ? (
                  <tr><td colSpan={5} style={{textAlign: 'center', padding: '2rem', color: 'var(--text-muted)'}}>No assets found</td></tr>
                ) : (
                  data.items.map(asset => (
                    <tr key={asset.id}>
                      <td>{asset.id}</td>
                      <td style={{fontFamily: 'monospace'}}>{asset.ip_address}</td>
                      <td>{asset.hostname || '-'}</td>
                      <td>{asset.operating_system || '-'}</td>
                      <td>
                        <span className={`badge badge-${asset.business_criticality.toLowerCase()}`}>
                          {asset.business_criticality}
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
                className="pagination-btn"
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
                className="pagination-btn"
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