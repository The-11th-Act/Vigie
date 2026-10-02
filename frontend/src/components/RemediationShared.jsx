
// Pieces shared by the fixes and the tickets of the Remediation module.

export const KINDS = [
  { value: 'kb', label: 'Microsoft KB' },
  { value: 'vendor_fix', label: 'Vendor fix' },
  { value: 'workaround', label: 'Workaround' },
  { value: 'mitigation', label: 'Mitigation' },
  { value: 'no_fix', label: 'No fix available' },
];
const KIND_LABELS = Object.fromEntries(KINDS.map((kind) => [kind.value, kind.label]));

export const controlStyle = {
  padding: '0.6rem 0.75rem',
  background: 'rgba(255,255,255,0.05)',
  border: '1px solid var(--border)',
  borderRadius: '8px',
  color: 'var(--text-main)',
  fontSize: '0.875rem',
  outline: 'none',
};

export const muted = { fontSize: '0.75rem', color: 'var(--text-muted)' };

export function formatDate(value) {
  return value ? new Date(value).toLocaleDateString() : '-';
}

export function FixLabel({ action, compact = false }) {
  if (action.kind === 'kb') {
    return (
      <div>
        <span className="badge badge-low" style={{ fontFamily: 'monospace' }}>{action.reference}</span>
        {!compact && action.title && <div style={{ ...muted, marginTop: '0.25rem' }}>{action.title}</div>}
      </div>
    );
  }
  return (
    <div>
      <div style={{ fontWeight: compact ? 400 : 600 }}>{action.title || action.reference}</div>
      {!compact && (
        <div style={muted}>
          {KIND_LABELS[action.kind] || action.kind} · {action.reference}
        </div>
      )}
    </div>
  );
}

export async function download(response, filename) {
  const url = URL.createObjectURL(response.data);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function safeName(reference) {
  return reference.replace(/[^\w.-]/g, '_');
}

// Hosts still waiting for a fix, with this host's versions and CVEs.
export function HostsTable({ hosts }) {
  if (hosts.length === 0) {
    return <div style={{ ...muted, padding: '0.5rem 0' }}>No host is waiting for this fix any more.</div>;
  }
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Host</th>
          <th>Version</th>
          <th>CVEs</th>
          <th>Max risk</th>
          <th>Deadline</th>
        </tr>
      </thead>
      <tbody>
        {hosts.map((host) => (
          <tr key={host.asset_id}>
            <td>
              {host.hostname || host.ip_address}
              <div style={muted}>
                {[host.hostname && host.ip_address, host.operating_system, host.business_criticality]
                  .filter(Boolean)
                  .join(' · ')}
                {host.internet_facing && ' · Exposed'}
              </div>
            </td>
            <td style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
              {host.installed_versions.join(', ') || '-'}
              {host.fixed_versions.length > 0 && ` → ${host.fixed_versions.join(', ')}`}
            </td>
            <td title={host.cves.join('\n')}>
              {host.cves.length}
              {host.in_kev && (
                <span className="badge badge-critical" style={{ marginLeft: '0.4rem' }}>KEV</span>
              )}
            </td>
            <td>{host.max_risk.toFixed(2)}</td>
            <td>
              {formatDate(host.next_deadline)}
              {host.overdue && <div style={{ ...muted, color: 'var(--high)' }}>Overdue</div>}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
