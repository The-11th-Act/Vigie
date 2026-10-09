import React, { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronUp, Download, ExternalLink, TriangleAlert } from 'lucide-react';
import { remediationService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { useAuth } from '../auth/AuthContext';
import Pagination from './Pagination';
import {
  FixLabel,
  HostsTable,
  controlStyle,
  download,
  formatDate,
  muted,
  safeName,
} from './RemediationShared';

const STATUS_LABELS = {
  open: 'Open',
  in_progress: 'In progress',
  deployed: 'Deployed, awaiting scan',
  resolved: 'Resolved',
  cancelled: 'Cancelled',
};
const STATUS_BADGES = {
  open: 'badge-high',
  in_progress: 'badge-medium',
  deployed: 'badge-low',
  resolved: 'badge-low',
  cancelled: '',
};
// What a person may set: resolution belongs to the scans.
const SETTABLE = ['open', 'in_progress', 'deployed', 'cancelled'];
const UNASSIGNED = '__unassigned__';
const PAGE_SIZE = 50;

// external_system values a ticketing connector writes: the link is its own.
const CONNECTOR_LABELS = { glpi: 'GLPI' };

function externalLabel(ticket) {
  const connector = CONNECTOR_LABELS[ticket.external_system];
  return connector ? `${connector} #${ticket.external_ref}` : ticket.external_ref;
}

function ConnectorLink({ ticket }) {
  return (
    <div style={{ ...muted, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      <span>
        {ticket.external_url ? (
          <a href={ticket.external_url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>
            <ExternalLink size={11} /> {externalLabel(ticket)}
          </a>
        ) : (
          externalLabel(ticket)
        )}
        {ticket.external_state && ` (${ticket.external_state.replace('_', ' ')} there)`}
      </span>
      <span>The team moves it in {CONNECTOR_LABELS[ticket.external_system]}; Vigie solves or reopens it there.</span>
      {ticket.external_error && (
        <span className="error-message" style={{ fontSize: '0.8rem' }}>
          <TriangleAlert size={12} /> Last sync failed: {ticket.external_error}
        </span>
      )}
    </div>
  );
}

function errorText(err) {
  return err.response?.data?.detail || err.message || 'The change was refused';
}

function TicketDetail({ ticketId }) {
  const role = useAuth().user?.role;
  const queryClient = useQueryClient();
  const { data, loading, error } = useApiQuery(
    ['remediation', 'ticket', ticketId],
    async () => (await remediationService.getTicket(ticketId)).data
  );
  const [draft, setDraft] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState(null);

  if (loading && !data) return <div className="loading">Loading ticket...</div>;
  if (error) return <div className="error-message">Error: {error}</div>;

  const { ticket, action, hosts, history } = data;
  const active = ['open', 'in_progress', 'deployed'].includes(ticket.status);
  const linkedByConnector = Boolean(CONNECTOR_LABELS[ticket.external_system]);
  const form = draft || {
    status: ticket.status,
    note: '',
    external_ref: ticket.external_ref || '',
    external_url: ticket.external_url || '',
  };
  const set = (patch) => setDraft({ ...form, ...patch });
  // Cancelling means not fixing: an analyst's call (the API enforces it).
  const options = SETTABLE.filter((s) => s !== 'cancelled' || role !== 'remediator');
  const needsNote = form.status === 'cancelled' && ticket.status !== 'cancelled';

  const save = async () => {
    setSaving(true);
    setSaveError(null);
    try {
      await remediationService.updateTicket(ticket.id, {
        status: form.status !== ticket.status ? form.status : undefined,
        note: form.note || undefined,
        // A connector's link is its own: not sent, so never edited.
        ...(linkedByConnector
          ? {}
          : { external_ref: form.external_ref, external_url: form.external_url }),
      });
      setDraft(null);
      // This ticket, the ticket list and the fixes it counts in.
      queryClient.invalidateQueries({ queryKey: ['remediation'] });
    } catch (err) {
      setSaveError(errorText(err));
    } finally {
      setSaving(false);
    }
  };

  const exportHosts = async () => {
    try {
      const res = await remediationService.exportTicketHosts(ticket.id);
      await download(res, `vigie-${safeName(action.reference)}-ticket-${ticket.id}.csv`);
    } catch (err) {
      setSaveError(errorText(err));
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', padding: '0.5rem 0' }}>
      <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', alignItems: 'flex-start' }}>
        <div style={{ flex: 1, minWidth: 260, fontSize: '0.875rem', whiteSpace: 'pre-line' }}>
          {action.solution || <span style={muted}>The scanner gave no solution text.</span>}
          {action.url && (
            <div style={{ marginTop: '0.5rem' }}>
              <a href={action.url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>
                Vendor advisory
              </a>
            </div>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', minWidth: 260 }}>
          <label style={{ ...muted, display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
            Status
            <select
              className="select"
              value={form.status}
              disabled={!active}
              onChange={(e) => set({ status: e.target.value })}
              aria-label="Ticket status"
            >
              {!options.includes(ticket.status) && (
                <option value={ticket.status}>{STATUS_LABELS[ticket.status]}</option>
              )}
              {options.map((s) => <option key={s} value={s}>{STATUS_LABELS[s]}</option>)}
            </select>
          </label>
          <textarea
            rows={2}
            placeholder={needsNote ? 'Why is this not being fixed? (required)' : 'Note (optional)'}
            value={form.note}
            onChange={(e) => set({ note: e.target.value })}
            aria-label="Ticket note"
            style={{ ...controlStyle, fontSize: '0.8rem', resize: 'vertical' }}
          />
          {linkedByConnector ? (
            <ConnectorLink ticket={ticket} />
          ) : (
            <>
              <input
                type="text"
                placeholder="External reference (e.g. SEC-1234)"
                value={form.external_ref}
                onChange={(e) => set({ external_ref: e.target.value })}
                aria-label="External reference"
                style={{ ...controlStyle, fontSize: '0.8rem' }}
              />
              <input
                type="url"
                placeholder="External link (https://...)"
                value={form.external_url}
                onChange={(e) => set({ external_url: e.target.value })}
                aria-label="External link"
                style={{ ...controlStyle, fontSize: '0.8rem' }}
              />
            </>
          )}
          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button
              type="button"
              className="button"
              disabled={!draft || saving || (needsNote && !form.note.trim())}
              onClick={save}
              style={{ padding: '0.45rem 0.9rem', fontSize: '0.8rem' }}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
            <button type="button" className="icon-button" onClick={exportHosts}>
              <Download size={14} /> Export hosts (CSV)
            </button>
          </div>
          {!active && (
            <div style={muted}>
              {ticket.status === 'resolved'
                ? 'Resolved by the scans; it reopens by itself if a finding comes back.'
                : 'Cancelled: its findings can go into a new ticket.'}
            </div>
          )}
          {saveError && <div className="error-message" style={{ fontSize: '0.8rem' }}>{saveError}</div>}
        </div>
      </div>

      <HostsTable hosts={hosts} />

      <div>
        <div style={{ ...muted, marginBottom: '0.4rem', textTransform: 'uppercase' }}>History</div>
        <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.3rem', fontSize: '0.8rem' }}>
          {history.map((entry, index) => (
            <li key={index}>
              <span style={muted}>{entry.created_at ? new Date(entry.created_at).toLocaleString() : ''}</span>{' '}
              <strong>{entry.username || 'unknown'}</strong>{' '}
              {entry.old_status && entry.old_status !== entry.new_status
                ? `${STATUS_LABELS[entry.old_status] || entry.old_status} → ${STATUS_LABELS[entry.new_status] || entry.new_status}`
                : entry.old_status
                  ? 'noted'
                  : `created (${STATUS_LABELS[entry.new_status] || entry.new_status})`}
              {entry.note && <span style={{ color: 'var(--text-muted)' }}> — {entry.note}</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export default function RemediationTickets() {
  const [status, setStatus] = useState('active');
  const [team, setTeam] = useState('');
  const [page, setPage] = useState(0);
  const [openId, setOpenId] = useState(null);

  const { data: teams } = useApiQuery(
    ['remediation', 'teams'],
    async () => (await remediationService.listTeams()).data.teams
  );

  // Paged like the other lists: a single request capped at 200 left every
  // ticket past the 200th out of sight, with nothing saying so.
  const { data, loading, error } = useApiQuery(
    ['remediation', 'tickets', { status, team, page }],
    async () => {
      const res = await remediationService.listTickets({
        status,
        owner_team: team || undefined,
        skip: page * PAGE_SIZE,
        limit: PAGE_SIZE,
      });
      return res.data;
    }
  );
  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div>
      <div style={{ marginBottom: '1rem', display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <select
          aria-label="Ticket status filter"
          value={status}
          onChange={(e) => {
            setStatus(e.target.value);
            setPage(0);
          }}
          style={{ ...controlStyle, cursor: 'pointer' }}
        >
          <option value="active">Active</option>
          <option value="all">All tickets</option>
          {Object.entries(STATUS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
        <select
          aria-label="Team filter"
          value={team}
          onChange={(e) => {
            setTeam(e.target.value);
            setPage(0);
          }}
          style={{ ...controlStyle, cursor: 'pointer' }}
        >
          <option value="">All teams</option>
          {(teams || []).map((name) => <option key={name} value={name}>{name}</option>)}
          <option value={UNASSIGNED}>Unassigned</option>
        </select>
      </div>

      {loading && !data && <div className="loading">Loading tickets...</div>}
      {error && <div className="error-message">Error: {error}</div>}

      {data && (
        <div className="glass-panel data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Ticket</th>
                <th>Team</th>
                <th>Status</th>
                <th title="Open findings left / all findings of the ticket">Progress</th>
                <th title="Sum of the risk still open">Open risk</th>
                <th>Next deadline</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.items.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                    No ticket here. Create them from the Fixes tab.
                  </td>
                </tr>
              ) : (
                data.items.map((ticket) => {
                  const open = openId === ticket.id;
                  const { metrics } = ticket;
                  return (
                    <React.Fragment key={ticket.id}>
                      <tr>
                        <td style={{ maxWidth: 360 }}>
                          <FixLabel action={ticket.action} compact />
                          {ticket.external_ref && (
                            <div style={muted}>
                              {ticket.external_url ? (
                                <a href={ticket.external_url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent)' }}>
                                  <ExternalLink size={11} /> {externalLabel(ticket)}
                                </a>
                              ) : (
                                externalLabel(ticket)
                              )}
                              {ticket.external_error && (
                                <span title={`Last sync failed: ${ticket.external_error}`} style={{ color: 'var(--critical)', marginLeft: '0.35rem' }}>
                                  <TriangleAlert size={11} aria-label="Sync error" />
                                </span>
                              )}
                            </div>
                          )}
                        </td>
                        <td style={ticket.owner_team ? undefined : { color: 'var(--text-muted)' }}>
                          {ticket.owner_team || 'Unassigned'}
                        </td>
                        <td>
                          <span className={`badge ${STATUS_BADGES[ticket.status] || ''}`}>
                            {STATUS_LABELS[ticket.status] || ticket.status}
                          </span>
                        </td>
                        <td>
                          {metrics.findings_open} / {metrics.findings_total}
                          <div style={muted}>
                            {metrics.hosts_open} host{metrics.hosts_open === 1 ? '' : 's'} left
                          </div>
                        </td>
                        <td style={{ fontWeight: 600 }}>{metrics.open_risk.toFixed(1)}</td>
                        <td>
                          {formatDate(metrics.next_deadline)}
                          {metrics.overdue > 0 && (
                            <div style={{ ...muted, color: 'var(--high)' }}>{metrics.overdue} overdue</div>
                          )}
                        </td>
                        <td>
                          <button
                            type="button"
                            className="icon-button"
                            onClick={() => setOpenId(open ? null : ticket.id)}
                            aria-expanded={open}
                            aria-label={`${open ? 'Close' : 'Open'} ticket ${ticket.title}`}
                          >
                            {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />} Details
                          </button>
                        </td>
                      </tr>
                      {open && (
                        <tr>
                          <td colSpan={7}>
                            <TicketDetail ticketId={ticket.id} />
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
      )}
      {data && <Pagination page={page} totalPages={totalPages} onPageChange={setPage} />}
    </div>
  );
}
