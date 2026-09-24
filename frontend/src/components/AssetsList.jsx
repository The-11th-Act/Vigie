import React, { useState, useCallback, useEffect, useRef } from 'react';
import { assetService } from '../services';
import { useFetch } from '../hooks/useFetch';
import { Search, ChevronLeft, ChevronRight, Plus, Pencil, Trash2 } from 'lucide-react';

const PAGE_SIZE = 20;
const CRITICALITIES = ['Low', 'Medium', 'High', 'Critical'];

const EMPTY_FORM = {
  ip_address: '',
  hostname: '',
  operating_system: '',
  business_criticality: 'Medium',
};

const inputStyle = {
  width: '100%',
  padding: '0.6rem 0.75rem',
  background: 'rgba(255,255,255,0.05)',
  border: '1px solid var(--border)',
  borderRadius: '8px',
  color: 'var(--text-main)',
  fontSize: '0.875rem',
  outline: 'none',
};

export default function AssetsList() {
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');

  const [editing, setEditing] = useState(null); // null | 'new' | asset
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState(null);

  const isAdmin = localStorage.getItem('role') === 'admin';

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

  const fetchAssets = useCallback(async () => {
    const res = await assetService.list({
      skip: page * PAGE_SIZE,
      limit: PAGE_SIZE,
      search: debouncedSearch || undefined,
    });
    return res.data;
  }, [page, debouncedSearch]);

  const { data, loading, error, refetch } = useFetch(fetchAssets, [page, debouncedSearch]);

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  const openCreate = () => {
    setEditing('new');
    setForm(EMPTY_FORM);
    setFormError(null);
  };

  const openEdit = (asset) => {
    setEditing(asset);
    setForm({
      ip_address: asset.ip_address,
      hostname: asset.hostname || '',
      operating_system: asset.operating_system || '',
      business_criticality: asset.business_criticality,
    });
    setFormError(null);
  };

  const closeForm = () => {
    setEditing(null);
    setFormError(null);
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setSaving(true);
    setFormError(null);
    try {
      if (editing === 'new') {
        await assetService.create({
          ...form,
          hostname: form.hostname || null,
          operating_system: form.operating_system || null,
        });
      } else {
        // The address is the asset's identity for ingestion, so editing only
        // sends the fields the API accepts on update.
        await assetService.update(editing.id, {
          hostname: form.hostname || null,
          operating_system: form.operating_system || null,
          business_criticality: form.business_criticality,
        });
      }
      closeForm();
      refetch();
    } catch (err) {
      setFormError(err.response?.data?.detail || err.message || 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (asset) => {
    const label = asset.hostname || asset.ip_address;
    if (!window.confirm(`Delete ${label} and all of its findings?`)) return;
    try {
      await assetService.delete(asset.id);
      refetch();
    } catch (err) {
      window.alert(err.response?.data?.detail || 'Delete failed');
    }
  };

  return (
    <div>
      <h1>Assets Inventory ({data?.total || 0})</h1>

      <div style={{marginBottom: '1rem', display: 'flex', gap: '0.75rem', alignItems: 'center'}}>
        <div style={{position: 'relative', flex: 1, maxWidth: 400}}>
          <Search size={16} style={{position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)'}} />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search by IP or hostname..."
            style={{...inputStyle, paddingLeft: '2.25rem'}}
          />
        </div>
        <button className="button" onClick={openCreate}>
          <Plus size={16} />
          New asset
        </button>
      </div>

      {editing && (
        <form
          onSubmit={handleSave}
          className="glass-panel"
          style={{marginBottom: '1.5rem', display: 'flex', flexDirection: 'column', gap: '0.75rem'}}
        >
          <h3 style={{color: 'var(--text-muted)'}}>
            {editing === 'new' ? 'New asset' : `Edit ${editing.hostname || editing.ip_address}`}
          </h3>

          {formError && <div className="error-message">{formError}</div>}

          <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem'}}>
            <label style={{display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}>
              IP address
              <input
                type="text"
                required
                value={form.ip_address}
                disabled={editing !== 'new'}
                onChange={(e) => setForm({...form, ip_address: e.target.value})}
                style={{...inputStyle, opacity: editing !== 'new' ? 0.5 : 1}}
              />
            </label>
            <label style={{display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}>
              Hostname
              <input
                type="text"
                value={form.hostname}
                onChange={(e) => setForm({...form, hostname: e.target.value})}
                style={inputStyle}
              />
            </label>
            <label style={{display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}>
              Operating system
              <input
                type="text"
                value={form.operating_system}
                onChange={(e) => setForm({...form, operating_system: e.target.value})}
                style={inputStyle}
              />
            </label>
            <label style={{display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}>
              Business criticality
              <select
                value={form.business_criticality}
                onChange={(e) => setForm({...form, business_criticality: e.target.value})}
                style={{...inputStyle, cursor: 'pointer'}}
              >
                {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </label>
          </div>

          <div style={{display: 'flex', gap: '0.5rem'}}>
            <button type="submit" className="button" disabled={saving}>
              {saving ? 'Saving...' : 'Save'}
            </button>
            <button
              type="button"
              onClick={closeForm}
              style={{background: 'none', border: '1px solid var(--border)', borderRadius: '8px', padding: '0.75rem 1.5rem', color: 'var(--text-main)', cursor: 'pointer'}}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

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
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 ? (
                  <tr><td colSpan={6} style={{textAlign: 'center', padding: '2rem', color: 'var(--text-muted)'}}>No assets found</td></tr>
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
                      <td>
                        <div style={{display: 'flex', gap: '0.5rem'}}>
                          <button
                            onClick={() => openEdit(asset)}
                            title="Edit"
                            style={{background: 'none', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.3rem 0.45rem', color: 'var(--text-main)', cursor: 'pointer'}}
                          >
                            <Pencil size={15} />
                          </button>
                          {/* Deletion cascades to every finding, so it stays admin-only. */}
                          {isAdmin && (
                            <button
                              onClick={() => handleDelete(asset)}
                              title="Delete"
                              style={{background: 'none', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.3rem 0.45rem', color: 'var(--critical)', cursor: 'pointer'}}
                            >
                              <Trash2 size={15} />
                            </button>
                          )}
                        </div>
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
