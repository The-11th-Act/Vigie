import { useMemo, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { Copy, Download, Eye, Save, Trash2 } from 'lucide-react';
import { extractService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { controlStyle, download, formatDate, muted } from './RemediationShared';

const EXPIRIES = [30, 90, 180, 365];
const SAVED_KEY = ['extracts', 'saved'];

function errorText(err) {
  return err.response?.data?.detail || err.message || 'The request failed';
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// Query parameters of an extract: only what differs from the defaults, so the
// URL handed to a reporting tool stays readable.
export function extractParams(dataset, columns, filters, format) {
  const params = { format };
  if (columns.length && columns.length < dataset.columns.length) {
    params.columns = columns.join(',');
  }
  for (const [key, value] of Object.entries(filters)) {
    if (value !== '' && value !== false && value != null) params[key] = String(value);
  }
  return params;
}

function curlCommand(path, params) {
  const query = new URLSearchParams(params).toString();
  return `curl -H "Authorization: Bearer $VIGIE_TOKEN" "${window.location.origin}/api/v1${path}?${query}"`;
}

function FilterInput({ spec, value, onChange }) {
  const label = { ...muted, display: 'flex', flexDirection: 'column', gap: '0.25rem' };
  if (spec.type === 'bool') {
    return (
      <label style={{ ...muted, display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
        <input type="checkbox" checked={Boolean(value)} onChange={(e) => onChange(e.target.checked)} />
        {spec.label}
      </label>
    );
  }
  if (spec.type === 'enum') {
    return (
      <label style={label}>
        {spec.label}
        <select className="select" value={value || ''} onChange={(e) => onChange(e.target.value)} aria-label={spec.label}>
          <option value="">Any</option>
          {spec.options.map((option) => <option key={option} value={option}>{option}</option>)}
        </select>
      </label>
    );
  }
  return (
    <label style={label}>
      {spec.label}
      <input
        type={spec.type === 'float' ? 'number' : 'text'}
        min={spec.minimum ?? undefined}
        max={spec.maximum ?? undefined}
        step={spec.type === 'float' ? 'any' : undefined}
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value)}
        aria-label={spec.label}
        style={{ ...controlStyle, padding: '0.4rem 0.5rem', fontSize: '0.8rem' }}
      />
    </label>
  );
}

function Builder({ datasets, onSaved }) {
  const [datasetKey, setDatasetKey] = useState(datasets[0]?.key || '');
  const dataset = datasets.find((d) => d.key === datasetKey) || datasets[0];
  const [columns, setColumns] = useState(dataset ? dataset.columns.map((c) => c.key) : []);
  const [filters, setFilters] = useState({});
  const [format, setFormat] = useState('csv');
  const [preview, setPreview] = useState(null);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState(null);

  const chooseDataset = (key) => {
    const next = datasets.find((d) => d.key === key);
    setDatasetKey(key);
    setColumns(next.columns.map((c) => c.key));
    setFilters({});
    setPreview(null);
    setMessage(null);
  };

  const params = useMemo(
    () => (dataset ? extractParams(dataset, columns, filters, format) : {}),
    [dataset, columns, filters, format]
  );

  if (!dataset) return <div style={muted}>No dataset is available to your role.</div>;

  const toggleColumn = (key) =>
    setColumns((current) =>
      current.includes(key)
        ? current.filter((k) => k !== key)
        // Keep the dataset's own order.
        : dataset.columns.map((c) => c.key).filter((k) => k === key || current.includes(k))
    );

  const act = async (action) => {
    setBusy(true);
    setMessage(null);
    try {
      await action();
    } catch (err) {
      setMessage({ ok: false, text: errorText(err) });
    } finally {
      setBusy(false);
    }
  };

  const runPreview = () =>
    act(async () => {
      const res = await extractService.preview(dataset.key, params);
      setPreview(res.data);
    });

  const runDownload = () =>
    act(async () => {
      const res = await extractService.download(dataset.key, params);
      await download(res, `vigie-${dataset.key}.${format}`);
    });

  const save = () =>
    act(async () => {
      await extractService.save({
        name: name.trim(),
        dataset: dataset.key,
        columns,
        filters: Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== '' && v !== false)),
        format,
      });
      setName('');
      setMessage({ ok: true, text: 'Saved. Its URL is in the list below.' });
      onSaved();
    });

  const command = curlCommand(`/extracts/${dataset.key}`, params);
  const previewColumns = columns.filter((key) => preview?.[0] && key in preview[0]);

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label style={{ ...muted, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          Dataset
          <select className="select" value={dataset.key} onChange={(e) => chooseDataset(e.target.value)} aria-label="Dataset">
            {datasets.map((d) => <option key={d.key} value={d.key}>{d.label}</option>)}
          </select>
        </label>
        <label style={{ ...muted, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
          Format
          <select className="select" value={format} onChange={(e) => setFormat(e.target.value)} aria-label="Format">
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="xlsx">Excel (XLSX)</option>
          </select>
        </label>
      </div>

      <div>
        <div style={{ ...muted, marginBottom: '0.4rem', display: 'flex', gap: '0.75rem' }}>
          COLUMNS
          <button type="button" className="icon-button" onClick={() => setColumns(dataset.columns.map((c) => c.key))}>All</button>
          <button type="button" className="icon-button" onClick={() => setColumns([])}>None</button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '0.3rem' }}>
          {dataset.columns.map((column) => (
            <label key={column.key} style={{ fontSize: '0.8rem', display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
              <input type="checkbox" checked={columns.includes(column.key)} onChange={() => toggleColumn(column.key)} />
              {column.label}
            </label>
          ))}
        </div>
      </div>

      {dataset.filters.length > 0 && (
        <div>
          <div style={{ ...muted, marginBottom: '0.4rem' }}>FILTERS</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.6rem', alignItems: 'end' }}>
            {dataset.filters.map((spec) => (
              <FilterInput
                key={spec.key}
                spec={spec}
                value={filters[spec.key]}
                onChange={(value) => setFilters((current) => ({ ...current, [spec.key]: value }))}
              />
            ))}
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <button type="button" className="icon-button" disabled={busy || !columns.length} onClick={runPreview}>
          <Eye size={14} /> Preview
        </button>
        <button type="button" className="button" disabled={busy || !columns.length} onClick={runDownload} style={{ padding: '0.45rem 0.9rem', fontSize: '0.85rem' }}>
          <Download size={14} /> Download
        </button>
        <input
          type="text"
          placeholder="Name, to save it"
          maxLength={128}
          value={name}
          onChange={(e) => setName(e.target.value)}
          aria-label="Extract name"
          style={{ ...controlStyle, padding: '0.45rem 0.6rem', fontSize: '0.8rem', width: 200 }}
        />
        <button type="button" className="icon-button" disabled={busy || !name.trim() || !columns.length} onClick={save}>
          <Save size={14} /> Save
        </button>
      </div>
      {message && (
        <div className={message.ok ? undefined : 'error-message'} style={message.ok ? muted : undefined} role="status">
          {message.text}
        </div>
      )}

      <div>
        <div style={{ ...muted, marginBottom: '0.3rem' }}>SAME EXTRACT FROM A SCRIPT (with a personal token)</div>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-start' }}>
          <code
            data-testid="curl-command"
            style={{ flex: 1, fontSize: '0.75rem', padding: '0.6rem', background: 'rgba(0,0,0,0.3)', borderRadius: 6, wordBreak: 'break-all' }}
          >
            {command}
          </code>
          <button type="button" className="icon-button" onClick={() => copy(command)} aria-label="Copy the command">
            <Copy size={14} />
          </button>
        </div>
      </div>

      {preview && (
        <div className="data-table-container">
          {preview.length === 0 ? (
            <div style={muted}>No row matches.</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>{previewColumns.map((key) => <th key={key}>{key}</th>)}</tr>
              </thead>
              <tbody>
                {preview.map((row, index) => (
                  <tr key={index}>
                    {previewColumns.map((key) => (
                      <td key={key} style={{ fontSize: '0.8rem' }}>
                        {row[key] === null ? '' : String(row[key])}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div style={{ ...muted, marginTop: '0.4rem' }}>First {preview.length} rows.</div>
        </div>
      )}
    </div>
  );
}

function SavedExtracts({ datasets }) {
  const { data, error, refetch } = useApiQuery(
    SAVED_KEY,
    async () => (await extractService.listSaved()).data
  );
  const [actionError, setActionError] = useState(null);
  const labels = Object.fromEntries(datasets.map((d) => [d.key, d.label]));

  const run = async (saved) => {
    setActionError(null);
    try {
      const res = await extractService.runSaved(saved.id);
      await download(res, `vigie-${saved.dataset}.${saved.format}`);
    } catch (err) {
      setActionError(errorText(err));
    }
  };

  const remove = async (saved) => {
    setActionError(null);
    try {
      await extractService.deleteSaved(saved.id);
      refetch();
    } catch (err) {
      setActionError(errorText(err));
    }
  };

  if (error) return <div className="error-message">Error: {error}</div>;
  if (!data) return null;
  if (data.length === 0) {
    return <div style={muted}>No saved extract yet: build one above and give it a name.</div>;
  }
  return (
    <>
      {actionError && <div className="error-message">{actionError}</div>}
      <div className="glass-panel data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Dataset</th>
              <th>URL for a reporting tool</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((saved) => {
              const url = `${window.location.origin}${saved.run_path}`;
              return (
                <tr key={saved.id}>
                  <td>{saved.name}</td>
                  <td>
                    {labels[saved.dataset] || saved.dataset}
                    <div style={muted}>{saved.format.toUpperCase()}</div>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '0.75rem', wordBreak: 'break-all' }}>{url}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.4rem' }}>
                      <button type="button" className="icon-button" onClick={() => copy(url)} aria-label={`Copy the URL of ${saved.name}`}>
                        <Copy size={14} />
                      </button>
                      <button type="button" className="icon-button" onClick={() => run(saved)} aria-label={`Download ${saved.name}`}>
                        <Download size={14} />
                      </button>
                      <button type="button" className="icon-button" onClick={() => remove(saved)} aria-label={`Delete ${saved.name}`}>
                        <Trash2 size={14} />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}

function Tokens() {
  const { data, error, refetch } = useApiQuery(
    ['extracts', 'tokens'],
    async () => (await extractService.listTokens()).data
  );
  const [name, setName] = useState('');
  const [days, setDays] = useState(90);
  const [created, setCreated] = useState(null);
  const [copied, setCopied] = useState(false);
  const [actionError, setActionError] = useState(null);

  const create = async () => {
    setActionError(null);
    setCopied(false);
    try {
      const res = await extractService.createToken(name.trim(), days);
      setCreated(res.data);
      setName('');
      refetch();
    } catch (err) {
      setActionError(errorText(err));
    }
  };

  const revoke = async (token) => {
    setActionError(null);
    try {
      await extractService.revokeToken(token.id);
      if (created?.id === token.id) setCreated(null);
      refetch();
    } catch (err) {
      setActionError(errorText(err));
    }
  };

  return (
    <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={muted}>
        A personal token lets a script or a reporting tool read what your role can see, as
        <code> Authorization: Bearer &lt;token&gt;</code>. It is read-only, expires, and stops if your role loses this module.
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          type="text"
          placeholder="Token name (e.g. Power BI)"
          maxLength={64}
          value={name}
          onChange={(e) => setName(e.target.value)}
          aria-label="Token name"
          style={{ ...controlStyle, padding: '0.45rem 0.6rem', fontSize: '0.8rem', width: 220 }}
        />
        <select className="select" value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Token lifetime">
          {EXPIRIES.map((d) => <option key={d} value={d}>{d} days</option>)}
        </select>
        <button type="button" className="button" disabled={!name.trim()} onClick={create} style={{ padding: '0.45rem 0.9rem', fontSize: '0.85rem' }}>
          Create token
        </button>
      </div>

      {created && (
        <div role="alert" style={{ border: '1px solid var(--medium)', borderRadius: 8, padding: '0.75rem', fontSize: '0.85rem' }}>
          <strong>Copy it now: it will not be shown again.</strong>
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem', alignItems: 'center' }}>
            <code data-testid="new-token" style={{ flex: 1, wordBreak: 'break-all', fontSize: '0.8rem' }}>{created.token}</code>
            <button
              type="button"
              className="icon-button"
              onClick={async () => setCopied(await copy(created.token))}
              aria-label="Copy the token"
            >
              <Copy size={14} /> {copied ? 'Copied' : 'Copy'}
            </button>
            <button type="button" className="icon-button" onClick={() => setCreated(null)}>Done</button>
          </div>
        </div>
      )}
      {actionError && <div className="error-message">{actionError}</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && data.length > 0 && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Token</th>
              <th>Expires</th>
              <th>Last used</th>
              <th>Status</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {data.map((token) => (
              <tr key={token.id}>
                <td>{token.name}</td>
                <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{token.prefix}…</td>
                <td>{formatDate(token.expires_at)}</td>
                <td>{formatDate(token.last_used_at)}</td>
                <td>
                  {token.active ? (
                    <span className="badge badge-low">Active</span>
                  ) : (
                    <span style={muted}>{token.revoked_at ? 'Revoked' : 'Expired'}</span>
                  )}
                </td>
                <td>
                  {token.active && (
                    <button type="button" className="icon-button" onClick={() => revoke(token)} aria-label={`Revoke ${token.name}`}>
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function Extracts() {
  const queryClient = useQueryClient();
  const { data: datasets, loading, error } = useApiQuery(
    ['extracts', 'datasets'],
    async () => (await extractService.datasets()).data
  );

  return (
    <div>
      <h1>API Extracts</h1>
      <p style={{ color: 'var(--text-muted)', margin: '0.5rem 0 1.25rem' }}>
        Build an extract, preview it, download it, or save it as a URL a script or a reporting tool pulls with a personal token.
      </p>
      {loading && <div className="loading">Loading datasets...</div>}
      {error && <div className="error-message">Error: {error}</div>}
      {datasets && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.75rem' }}>
          <section>
            <h2 style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}>Build an extract</h2>
            <Builder
              datasets={datasets}
              onSaved={() => queryClient.invalidateQueries({ queryKey: SAVED_KEY })}
            />
          </section>
          <section>
            <h2 style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}>Saved extracts</h2>
            <SavedExtracts datasets={datasets} />
          </section>
          <section>
            <h2 style={{ fontSize: '1.1rem', marginBottom: '0.75rem' }}>Personal API tokens</h2>
            <Tokens />
          </section>
        </div>
      )}
    </div>
  );
}
