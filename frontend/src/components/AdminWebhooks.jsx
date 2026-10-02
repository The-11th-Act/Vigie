import { useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { ChevronDown, ChevronUp, Copy, Send, Trash2 } from 'lucide-react';
import { webhookService } from '../services';
import { useApiQuery } from '../hooks/useApiQuery';
import { controlStyle, muted } from './RemediationShared';

const WEBHOOKS_KEY = ['admin', 'webhooks'];

const DELIVERY_BADGES = {
  delivered: 'badge-low',
  pending: 'badge-medium',
  failed: 'badge-critical',
};

function errorText(err) {
  return err.response?.data?.detail?.[0]?.msg || err.response?.data?.detail || err.message || 'The change was refused';
}

function formatMoment(value) {
  return value ? new Date(value).toLocaleString() : '-';
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

function SecretNotice({ webhook, onDone }) {
  const [copied, setCopied] = useState(false);
  return (
    <div role="alert" className="glass-panel" style={{ border: '1px solid var(--medium)', marginBottom: '1rem', fontSize: '0.85rem' }}>
      <strong>Signing secret of {webhook.name}: copy it now, it will not be shown again.</strong>
      <div style={{ ...muted, marginTop: '0.25rem' }}>
        The receiver checks <code>X-Vigie-Signature</code>: HMAC-SHA256 of <code>&lt;X-Vigie-Timestamp&gt;.&lt;body&gt;</code> under this secret.
      </div>
      <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem', alignItems: 'center' }}>
        <code data-testid="webhook-secret" style={{ flex: 1, wordBreak: 'break-all', fontSize: '0.8rem' }}>{webhook.secret}</code>
        <button type="button" className="icon-button" onClick={async () => setCopied(await copy(webhook.secret))} aria-label="Copy the secret">
          <Copy size={14} /> {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" className="icon-button" onClick={onDone}>Done</button>
      </div>
    </div>
  );
}

function EventChoice({ events, chosen, onChange }) {
  const toggle = (name) =>
    onChange(chosen.includes(name) ? chosen.filter((e) => e !== name) : [...chosen, name]);
  return (
    <fieldset style={{ border: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
      <legend style={{ ...muted, marginBottom: '0.3rem' }}>Events</legend>
      {events.map((event) => (
        <label key={event.name} style={{ fontSize: '0.85rem', display: 'flex', gap: '0.4rem', alignItems: 'baseline' }}>
          <input type="checkbox" checked={chosen.includes(event.name)} onChange={() => toggle(event.name)} />
          <code>{event.name}</code>
          <span style={muted}>{event.description}</span>
        </label>
      ))}
    </fieldset>
  );
}

function NewWebhook({ events, onCreated }) {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [chosen, setChosen] = useState([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState(null);

  const create = async (e) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      const res = await webhookService.create({ name: name.trim(), url: url.trim(), events: chosen });
      setName('');
      setUrl('');
      setChosen([]);
      onCreated(res.data);
    } catch (err) {
      setError(errorText(err));
    } finally {
      setSaving(false);
    }
  };

  return (
    <form className="glass-panel" onSubmit={create} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginBottom: '1rem' }}>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Name (e.g. SOC channel)"
          maxLength={64}
          value={name}
          onChange={(e) => setName(e.target.value)}
          aria-label="Webhook name"
          style={{ ...controlStyle, width: 220 }}
        />
        <input
          type="url"
          placeholder="https://..."
          maxLength={1024}
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          aria-label="Webhook URL"
          style={{ ...controlStyle, flex: 1, minWidth: 280 }}
        />
      </div>
      <EventChoice events={events} chosen={chosen} onChange={setChosen} />
      {error && <div className="error-message">{error}</div>}
      <div>
        <button type="submit" className="button" disabled={saving || !name.trim() || !url.trim() || chosen.length === 0}>
          Add webhook
        </button>
      </div>
    </form>
  );
}

function Deliveries({ webhook }) {
  const queryClient = useQueryClient();
  const { data, loading, error } = useApiQuery(
    ['admin', 'webhooks', 'deliveries', webhook.id],
    async () => (await webhookService.deliveries(webhook.id)).data
  );
  const [actionError, setActionError] = useState(null);

  const retry = async (delivery) => {
    setActionError(null);
    try {
      await webhookService.retryDelivery(webhook.id, delivery.id);
      queryClient.invalidateQueries({ queryKey: WEBHOOKS_KEY });
    } catch (err) {
      setActionError(errorText(err));
    }
  };

  if (loading && !data) return <div className="loading">Loading deliveries...</div>;
  if (error && !data) return <div className="error-message">Error: {error}</div>;
  if (!data.length) return <div style={muted}>Nothing sent yet.</div>;
  return (
    <>
      {actionError && <div className="error-message">{actionError}</div>}
      <table className="data-table" aria-label={`Deliveries of ${webhook.name}`}>
        <thead>
          <tr>
            <th>Event</th>
            <th>Status</th>
            <th>Attempts</th>
            <th>Last answer</th>
            <th>Queued</th>
            <th>Next attempt</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {data.map((delivery) => (
            <tr key={delivery.id}>
              <td><code>{delivery.event}</code></td>
              <td><span className={`badge ${DELIVERY_BADGES[delivery.status] || ''}`}>{delivery.status}</span></td>
              <td>{delivery.attempts}</td>
              <td style={{ maxWidth: 280 }}>
                {delivery.response_status && <span>HTTP {delivery.response_status} </span>}
                {delivery.last_error && <span style={muted}>{delivery.last_error}</span>}
              </td>
              <td>{formatMoment(delivery.created_at)}</td>
              <td>{delivery.status === 'pending' ? formatMoment(delivery.next_attempt_at) : '-'}</td>
              <td>
                {delivery.status === 'failed' && (
                  <button type="button" className="icon-button" onClick={() => retry(delivery)}>Send again</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function WebhookRow({ webhook, events, onSecret }) {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [editingEvents, setEditingEvents] = useState(null);
  const [error, setError] = useState(null);
  const [notice, setNotice] = useState(null);

  const run = async (request, message) => {
    setError(null);
    setNotice(null);
    try {
      const res = await request();
      queryClient.invalidateQueries({ queryKey: WEBHOOKS_KEY });
      if (message) setNotice(message);
      return res;
    } catch (err) {
      setError(errorText(err));
      return null;
    }
  };

  const rotate = async () => {
    const res = await run(() => webhookService.rotateSecret(webhook.id));
    if (res) onSecret(res.data);
  };

  const saveEvents = async () => {
    const res = await run(() => webhookService.update(webhook.id, { events: editingEvents }));
    if (res) setEditingEvents(null);
  };

  let state = <span className="badge badge-low">Active</span>;
  if (!webhook.usable) {
    state = (
      <span className="badge badge-high" title="Sealed by another instance's signing key: rotate its secret to use it here">
        Other instance
      </span>
    );
  } else if (!webhook.enabled) {
    state = <span style={muted}>Disabled</span>;
  }

  return (
    <>
      <tr>
        <td>
          <strong>{webhook.name}</strong>
          <div style={{ ...muted, wordBreak: 'break-all' }}>{webhook.url}</div>
        </td>
        <td style={{ fontSize: '0.8rem' }}>
          {webhook.events.map((event) => <div key={event}><code>{event}</code></div>)}
        </td>
        <td>{state}</td>
        <td style={{ fontSize: '0.8rem' }}>
          <div>Sent: {formatMoment(webhook.last_success_at)}</div>
          {webhook.last_error && (
            <div style={{ color: 'var(--high)' }} title={webhook.last_error}>
              Failed: {formatMoment(webhook.last_failure_at)}
            </div>
          )}
          {(webhook.pending > 0 || webhook.failed > 0) && (
            <div style={muted}>{webhook.pending} pending, {webhook.failed} abandoned</div>
          )}
        </td>
        <td>
          <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              className="icon-button"
              disabled={!webhook.usable || !webhook.enabled}
              onClick={() => run(() => webhookService.ping(webhook.id), 'Test event queued: see the deliveries.')}
              aria-label={`Send a test event to ${webhook.name}`}
            >
              <Send size={14} /> Test
            </button>
            {webhook.usable && (
              <>
                <button
                  type="button"
                  className="icon-button"
                  onClick={() => run(() => webhookService.update(webhook.id, { enabled: !webhook.enabled }))}
                >
                  {webhook.enabled ? 'Disable' : 'Enable'}
                </button>
                <button type="button" className="icon-button" onClick={() => setEditingEvents(webhook.events)}>
                  Events
                </button>
              </>
            )}
            <button type="button" className="icon-button" onClick={rotate}>
              {webhook.usable ? 'Rotate secret' : 'Use here (new secret)'}
            </button>
            <button
              type="button"
              className="icon-button"
              onClick={() => setOpen(!open)}
              aria-expanded={open}
              aria-label={`Deliveries of ${webhook.name}`}
            >
              {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />} Deliveries
            </button>
            {confirmDelete ? (
              <button type="button" className="icon-button" onClick={() => run(() => webhookService.remove(webhook.id))}>
                Confirm delete
              </button>
            ) : (
              <button type="button" className="icon-button" onClick={() => setConfirmDelete(true)} aria-label={`Delete ${webhook.name}`}>
                <Trash2 size={14} />
              </button>
            )}
          </div>
          {notice && <div style={muted}>{notice}</div>}
          {error && <div className="error-message">{error}</div>}
        </td>
      </tr>
      {editingEvents && (
        <tr>
          <td colSpan={5}>
            <EventChoice events={events} chosen={editingEvents} onChange={setEditingEvents} />
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
              <button type="button" className="button" disabled={editingEvents.length === 0} onClick={saveEvents}>Save events</button>
              <button type="button" className="icon-button" onClick={() => setEditingEvents(null)}>Cancel</button>
            </div>
          </td>
        </tr>
      )}
      {open && (
        <tr>
          <td colSpan={5}>
            <Deliveries webhook={webhook} />
          </td>
        </tr>
      )}
    </>
  );
}

export default function AdminWebhooks() {
  const queryClient = useQueryClient();
  const { data, loading, error } = useApiQuery(WEBHOOKS_KEY, async () => (await webhookService.list()).data);
  const { data: events } = useApiQuery(['admin', 'webhooks', 'events'], async () => (await webhookService.events()).data);
  const [secret, setSecret] = useState(null);

  const showSecret = (webhook) => {
    setSecret(webhook);
    queryClient.invalidateQueries({ queryKey: WEBHOOKS_KEY });
  };

  return (
    <section style={{ marginBottom: '2.5rem' }}>
      <h2 style={{ fontSize: '1.15rem', marginBottom: '0.5rem' }}>Webhooks</h2>
      <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
        Vigie posts the chosen events, signed, to these URLs: a chat channel, a SOAR, a ticketing bridge.
        Failed deliveries are retried for about a day.
      </p>
      {secret && <SecretNotice webhook={secret} onDone={() => setSecret(null)} />}
      {events && <NewWebhook events={events} onCreated={showSecret} />}
      {loading && !data && <div className="loading">Loading webhooks...</div>}
      {error && !data && <div className="error-message">Error: {error}</div>}
      {data && data.length > 0 && (
        <div className="glass-panel data-table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Webhook</th>
                <th>Events</th>
                <th>State</th>
                <th>Activity</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {data.map((webhook) => (
                <WebhookRow key={webhook.id} webhook={webhook} events={events || []} onSecret={showSecret} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
