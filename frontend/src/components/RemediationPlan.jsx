import React, { useCallback, useEffect, useRef, useState } from 'react';
import { ChevronDown, ChevronLeft, ChevronRight, ChevronUp, Download, ExternalLink, Search, Ticket } from 'lucide-react';
import { remediationService } from '../services';
import { useFetch } from '../hooks/useFetch';
import RemediationTickets from './RemediationTickets';
import {
  FixLabel,
  HostsTable,
  KINDS,
  controlStyle,
  download,
  formatDate,
  muted,
  safeName,
} from './RemediationShared';

const PAGE_SIZE = 25;

// The hosts still waiting for one fix, loaded when its row is opened.
function ActionHosts({ actionId }) {
  const fetchAction = useCallback(async () => (await remediationService.getAction(actionId)).data, [actionId]);
  const { data, loading, error } = useFetch(fetchAction, [actionId]);
  const [exportError, setExportError] = useState(null);

  if (loading) return <div className="loading">Loading hosts...</div>;
  if (error) return <div className="error-message">Error: {error}</div>;

  const { action, hosts } = data;
  const exportHosts = async () => {
    setExportError(null);
    try {
      const res = await remediationService.exportHosts(action.id);
      await download(res, `vigie-${safeName(action.reference)}-hosts.csv`);
    } catch (err) {
      setExportError(err.message || 'Export failed');
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', padding: '0.5rem 0' }}>
      <div style={{ display: 'flex', gap: '1rem', alignItems: 'flex-start', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 260, fontSize: '0.875rem', whiteSpace: 'pre-line' }}>
          {action.solution || <span style={muted}>The scanner gave no solution text.</span>}
        </div>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {action.url && (
            <a className="icon-button" href={action.url} target="_blank" rel="noopener noreferrer">
              <ExternalLink size={14} /> Vendor advisory
            </a>
          )}
          <button type="button" className="icon-button" onClick={exportHosts}>
            <Download size={14} /> Export hosts (CSV)
          </button>
        </div>
      </div>
      {exportError && <div className="error-message">Export failed: {exportError}</div>}
      <HostsTable hosts={hosts} />
    </div>
  );
}

function FixesView({ onTicketsCreated }) {
  const [page, setPage] = useState(0);
  const [kind, setKind] = useState('');
  const [kevOnly, setKevOnly] = useState(false);
  const [search, setSearch] = useState('');
  const [debouncedSearch, setDebouncedSearch] = useState('');
  const [openId, setOpenId] = useState(null);
  const [ticketing, setTicketing] = useState(null);
  const [message, setMessage] = useState(null);

  const searchTimer = useRef(null);
  useEffect(() => {
    searchTimer.current = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(0);
    }, 300);
    return () => clearTimeout(searchTimer.current);
  }, [search]);

  const fetchActions = useCallback(async () => {
    const res = await remediationService.listActions({
      skip: page * PAGE_SIZE,
      limit: PAGE_SIZE,
      kind: kind || undefined,
      kev_only: kevOnly || undefined,
      search: debouncedSearch || undefined,
    });
    return res.data;
  }, [page, kind, kevOnly, debouncedSearch]);

  const { data, loading, error, refetch } = useFetch(fetchActions, [page, kind, kevOnly, debouncedSearch]);
  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  const createTickets = async (item) => {
    setTicketing(item.action.id);
    setMessage(null);
    try {
      const res = await remediationService.createTickets(item.action.id);
      const { created, added } = res.data;
      const parts = [];
      if (created.length) {
        parts.push(`${created.length} ticket${created.length > 1 ? 's' : ''} created (${created.map((t) => t.owner_team || 'Unassigned').join(', ')})`);
      }
      if (added) parts.push(`${added} finding${added > 1 ? 's' : ''} added to existing tickets`);
      setMessage({ ok: true, text: `${item.action.reference}: ${parts.join('; ')}.` });
      refetch();
      onTicketsCreated();
    } catch (err) {
      setMessage({ ok: false, text: err.response?.data?.detail || err.message || 'Could not create the tickets' });
    } finally {
      setTicketing(null);
    }
  };

  return (
    <div>
      <div style={{ marginBottom: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ position: 'relative' }}>
          <Search size={16} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="search"
            placeholder="KB, product, fix..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Search fixes"
            style={{ ...controlStyle, paddingLeft: '2rem', width: 240 }}
          />
        </div>
        <select
          aria-label="Kind of fix"
          value={kind}
          onChange={(e) => {
            setKind(e.target.value);
            setPage(0);
          }}
          style={{ ...controlStyle, cursor: 'pointer' }}
        >
          <option value="">All kinds</option>
          {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
        </select>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
          <input
            type="checkbox"
            checked={kevOnly}
            onChange={(e) => {
              setKevOnly(e.target.checked);
              setPage(0);
            }}
          />
          Fixing known exploited (KEV) only
        </label>
      </div>

      {message && (
        <div
          className={message.ok ? 'glass-panel' : 'error-message'}
          style={{ marginBottom: '1rem', padding: '0.75rem 1rem', fontSize: '0.875rem' }}
          role="status"
        >
          {message.text}
        </div>
      )}
      {loading && !data && <div className="loading">Loading fixes...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && (
        <>
          <div className="glass-panel data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Fix</th>
                  <th title="Hosts still missing it">Hosts</th>
                  <th title="Open findings it closes (distinct CVEs)">Findings</th>
                  <th>KEV</th>
                  <th>Overdue</th>
                  <th title="Sum of the risk of the open findings it closes">Risk removed</th>
                  <th>Next deadline</th>
                  <th title="Open findings already in a ticket">Tickets</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.items.length === 0 ? (
                  <tr>
                    <td colSpan={9} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                      No open fix matches. Fixes appear as scans report them.
                    </td>
                  </tr>
                ) : (
                  data.items.map((item) => {
                    const open = openId === item.action.id;
                    const untracked = item.findings - (item.tracked || 0);
                    return (
                      <React.Fragment key={item.action.id}>
                        <tr>
                          <td style={{ maxWidth: 380 }}><FixLabel action={item.action} /></td>
                          <td>{item.assets}</td>
                          <td>
                            {item.findings}
                            <div style={muted}>{item.cves} CVE{item.cves > 1 ? 's' : ''}</div>
                          </td>
                          <td>{item.kev > 0 ? <span className="badge badge-critical">{item.kev}</span> : '-'}</td>
                          <td style={item.overdue > 0 ? { color: 'var(--high)' } : undefined}>{item.overdue || '-'}</td>
                          <td style={{ fontWeight: 600 }}>{item.total_risk.toFixed(1)}</td>
                          <td>{formatDate(item.next_deadline)}</td>
                          <td>
                            {untracked > 0 ? (
                              <button
                                type="button"
                                className="icon-button"
                                disabled={ticketing === item.action.id}
                                onClick={() => createTickets(item)}
                                title={`${untracked} open finding${untracked > 1 ? 's' : ''} in no ticket yet`}
                                aria-label={`Create tickets for ${item.action.reference}`}
                              >
                                <Ticket size={14} /> {ticketing === item.action.id ? 'Creating...' : 'Create'}
                              </button>
                            ) : (
                              <span style={muted}>All ticketed</span>
                            )}
                          </td>
                          <td>
                            <button
                              type="button"
                              className="icon-button"
                              onClick={() => setOpenId(open ? null : item.action.id)}
                              aria-expanded={open}
                              aria-label={`${open ? 'Hide' : 'Show'} hosts for ${item.action.reference}`}
                            >
                              {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />} Hosts
                            </button>
                          </td>
                        </tr>
                        {open && (
                          <tr>
                            <td colSpan={9}>
                              <ActionHosts actionId={item.action.id} />
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {data.unremediated.findings > 0 && (
            <div className="glass-panel" style={{ marginTop: '1rem', fontSize: '0.875rem' }}>
              <strong>No identified fix:</strong> {data.unremediated.findings} open finding
              {data.unremediated.findings > 1 ? 's' : ''} on {data.unremediated.assets} host
              {data.unremediated.assets > 1 ? 's' : ''} (risk {data.unremediated.total_risk.toFixed(1)}).{' '}
              <span style={{ color: 'var(--text-muted)' }}>
                Scanned before fixes were recorded, or reported without one: see the Risk Backlog.
              </span>
            </div>
          )}

          {totalPages > 1 && (
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '1rem', marginTop: '1.5rem' }}>
              <button
                type="button"
                className="icon-button"
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                disabled={page === 0}
                aria-label="Previous page"
              >
                <ChevronLeft size={18} />
              </button>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                Page {page + 1} of {totalPages}
              </span>
              <button
                type="button"
                className="icon-button"
                onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                aria-label="Next page"
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

const TABS = [
  { key: 'fixes', label: 'Fixes' },
  { key: 'tickets', label: 'Tickets' },
];

export default function RemediationPlan() {
  const [tab, setTab] = useState('fixes');
  // Bumped when tickets are created, so the tickets tab reloads when opened.
  const [ticketsVersion, setTicketsVersion] = useState(0);

  return (
    <div>
      <h1>Remediation</h1>
      <p style={{ color: 'var(--text-muted)', margin: '0.5rem 0 1rem' }}>
        What to deploy, the fix removing the most open risk first; tickets split it by the team owning the hosts.
      </p>
      <div role="tablist" style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem' }}>
        {TABS.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={tab === key ? 'button' : 'icon-button'}
            onClick={() => setTab(key)}
            style={{ padding: '0.45rem 1rem', fontSize: '0.875rem' }}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === 'fixes' ? (
        <FixesView onTicketsCreated={() => setTicketsVersion((v) => v + 1)} />
      ) : (
        <RemediationTickets key={ticketsVersion} />
      )}
    </div>
  );
}
