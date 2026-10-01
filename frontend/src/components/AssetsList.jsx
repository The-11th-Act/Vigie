import React, { useState } from 'react';
import { assetService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { useDebouncedValue } from '../hooks/useDebouncedValue';
import { useAuth } from '../auth/AuthContext';
import { Plus, Pencil, Trash2 } from 'lucide-react';
import Pagination from './Pagination';
import SearchInput from './SearchInput';

const PAGE_SIZE = 20;
const CRITICALITIES = ['Low', 'Medium', 'High', 'Critical'];
// Mirrors ASSET_TYPES in app/services/categorization.py.
export const ASSET_TYPES = {
  server: 'Server',
  workstation: 'Workstation',
  network: 'Network device',
  cloud: 'Cloud resource',
  ot: 'OT / industrial',
  other: 'Other',
};

const EMPTY_FORM = {
  ip_address: '',
  hostname: '',
  operating_system: '',
  business_criticality: 'Medium',
  internet_facing: false,
  owner_team: '',
  asset_type: '',
  environment: '',
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
  const debouncedSearch = useDebouncedValue(search);

  const [editing, setEditing] = useState(null); // null | 'new' | asset
  const [form, setForm] = useState(EMPTY_FORM);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState(null);

  // Only hides controls: the API enforces the role on its own, from the
  // database.
  const role = useAuth().user?.role;
  const isAdmin = role === 'admin';
  // Criticality and exposure weigh on every score: a remediator reads them.
  const canEdit = role !== 'remediator';

  const handleSearchChange = (value) => {
    setSearch(value);
    setPage(0);
  };

  const { data, loading, error, refetch } = useApiQuery(
    ['assets', 'list', { page, search: debouncedSearch }],
    async () => {
      const res = await assetService.list({
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
        search: debouncedSearch || undefined,
      });
      return res.data;
    }
  );

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
      internet_facing: Boolean(asset.internet_facing),
      owner_team: asset.owner_team || '',
      asset_type: asset.asset_type || '',
      environment: asset.environment || '',
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
          // Left empty, the API infers the type from the OS.
          asset_type: form.asset_type || null,
          environment: form.environment || null,
        });
      } else {
        // The address is the asset's identity for ingestion, so editing only
        // sends the fields the API accepts on update.
        await assetService.update(editing.id, {
          hostname: form.hostname || null,
          operating_system: form.operating_system || null,
          business_criticality: form.business_criticality,
          internet_facing: form.internet_facing,
          // Empty clears it; the subnet rules only apply to new hosts.
          owner_team: form.owner_team || null,
          asset_type: form.asset_type || null,
          environment: form.environment || null,
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
        <SearchInput
          value={search}
          onChange={handleSearchChange}
          placeholder="Search by IP or hostname..."
          style={{flex: 1, maxWidth: 400}}
        />
        {canEdit && (
          <button className="button" onClick={openCreate}>
            <Plus size={16} />
            New asset
          </button>
        )}
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
            <label
              title="Remediation tickets go to this team. Left empty on a new asset, the subnet rules decide."
              style={{display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}
            >
              Owner team
              <input
                type="text"
                maxLength={128}
                value={form.owner_team}
                onChange={(e) => setForm({...form, owner_team: e.target.value})}
                style={inputStyle}
              />
            </label>
            <label
              title="Left empty, it is inferred from the operating system"
              style={{display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}
            >
              Asset type
              <select
                value={form.asset_type}
                onChange={(e) => setForm({...form, asset_type: e.target.value})}
                style={{...inputStyle, cursor: 'pointer'}}
              >
                <option value="">Infer from the OS</option>
                {Object.entries(ASSET_TYPES).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
            </label>
            <label style={{display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}>
              Environment
              <input
                type="text"
                maxLength={32}
                placeholder="production, staging..."
                value={form.environment}
                onChange={(e) => setForm({...form, environment: e.target.value})}
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
            <label
              title="Raises the risk of every finding on this asset (×1.2)"
              style={{display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.8rem', color: 'var(--text-muted)'}}
            >
              <input
                type="checkbox"
                checked={form.internet_facing}
                onChange={(e) => setForm({...form, internet_facing: e.target.checked})}
              />
              Exposed to the Internet
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
                  <th>Type</th>
                  <th>Criticality</th>
                  <th>Team</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 ? (
                  <tr><td colSpan={8} style={{textAlign: 'center', padding: '2rem', color: 'var(--text-muted)'}}>No assets found</td></tr>
                ) : (
                  data.items.map(asset => (
                    <tr key={asset.id}>
                      <td>{asset.id}</td>
                      <td style={{fontFamily: 'monospace'}}>{asset.ip_address}</td>
                      <td>{asset.hostname || '-'}</td>
                      <td>{asset.operating_system || '-'}</td>
                      <td style={asset.asset_type ? undefined : {color: 'var(--text-muted)'}}>
                        {ASSET_TYPES[asset.asset_type] || asset.asset_type || 'Unknown'}
                        {asset.environment && (
                          <div style={{fontSize: '0.75rem', color: 'var(--text-muted)'}}>{asset.environment}</div>
                        )}
                      </td>
                      <td>
                        <span className={`badge badge-${asset.business_criticality.toLowerCase()}`}>
                          {asset.business_criticality}
                        </span>
                        {asset.internet_facing && (
                          <span className="badge badge-medium" style={{marginLeft: 6}} title="Reachable from the Internet">
                            Exposed
                          </span>
                        )}
                      </td>
                      <td style={asset.owner_team ? undefined : {color: 'var(--text-muted)'}}>
                        {asset.owner_team || 'Unassigned'}
                      </td>
                      <td>
                        <div style={{display: 'flex', gap: '0.5rem'}}>
                          {canEdit && (
                            <button
                              onClick={() => openEdit(asset)}
                              title="Edit"
                              style={{background: 'none', border: '1px solid var(--border)', borderRadius: '6px', padding: '0.3rem 0.45rem', color: 'var(--text-main)', cursor: 'pointer'}}
                            >
                              <Pencil size={15} />
                            </button>
                          )}
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

          <Pagination page={page} totalPages={totalPages} onPageChange={setPage} />
        </>
      )}
    </div>
  );
}
