import api, { COOKIE_SESSION } from './api'

export const authService = {
  // Cookie mode: the API answers with HttpOnly session cookies and keeps the
  // tokens out of the response body.
  login: (username, password) =>
    api.post('/auth/login', { username, password }, { headers: COOKIE_SESSION }),

  // Probed on start-up: a 401 just means nobody is signed in.
  getMe: () =>
    api.get('/auth/me', { skipLoginRedirect: true }),

  // The refresh token is the session cookie; the API clears the cookies.
  logout: () =>
    api.post('/auth/logout'),
}

// Public: read before sign-in, so a staging environment shows as such on the
// sign-in screen too.
export const instanceService = {
  get: () =>
    api.get('/instance', { skipLoginRedirect: true }),
}

export const dashboardService = {
  getStats: () =>
    api.get('/dashboard/stats'),

  getTopRisks: (limit = 10) =>
    api.get('/dashboard/top-risks', { params: { limit } }),

  // Day by day, from the daily snapshots.
  getTrends: (params = {}) =>
    api.get('/dashboard/trends', { params }),

  getPerformance: (params = {}) =>
    api.get('/dashboard/performance', { params }),

  // Admin: rebuild missing history now rather than at the next daily pass.
  rebuildSnapshots: () =>
    api.post('/dashboard/snapshots/rebuild'),
}

export const assetService = {
  list: (params = {}) =>
    api.get('/assets/', { params }),

  create: (data) =>
    api.post('/assets/', data),

  update: (id, data) =>
    api.put(`/assets/${id}`, data),

  delete: (id) =>
    api.delete(`/assets/${id}`),
}

export const vulnerabilityService = {
  list: (params = {}) =>
    api.get('/vulnerabilities/', { params }),

  // A new CVSS score rescores every open finding of the CVE.
  update: (id, data) =>
    api.put(`/vulnerabilities/${id}`, data),

  // Admin: the CVE goes, and every finding of it.
  remove: (id) =>
    api.delete(`/vulnerabilities/${id}`),

  getFindings: (params = {}) =>
    api.get('/vulnerabilities/findings', { params }),

  updateFinding: (id, data) =>
    api.patch(`/vulnerabilities/findings/${id}`, data),

  // Who changed the finding's status, when, and why.
  getFindingHistory: (id) =>
    api.get(`/vulnerabilities/findings/${id}/history`),

  // Through axios rather than a plain link, so an expired session is
  // refreshed like for any other call.
  exportFindings: (params = {}) =>
    api.get('/vulnerabilities/findings/export.csv', { params, responseType: 'blob' }),
}

export const scanService = {
  upload: (file, scanType) => {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('scan_type', scanType)
    return api.post('/scans/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },

  getStatus: (taskId) =>
    api.get(`/scans/status/${taskId}`),

  list: (params = {}) =>
    api.get('/scans/', { params }),
}

export const meService = {
  // The modules the sidebar shows, in the user's order (hidden ones flagged).
  getModules: () =>
    api.get('/me/modules'),

  updatePreferences: (order, hidden) =>
    api.put('/me/preferences', { order, hidden }),

  // Ends every session, this one included: sign in again afterwards.
  changePassword: (currentPassword, newPassword) =>
    api.put('/me/password', { current_password: currentPassword, new_password: newPassword }),
}

export const adminService = {
  getModules: () =>
    api.get('/admin/modules'),

  toggleModule: (key, enabled) =>
    api.patch(`/admin/modules/${key}`, { enabled }),

  setRoleProfile: (role, modules) =>
    api.put(`/admin/roles/${role}/modules`, { modules }),

  resetRoleProfile: (role) =>
    api.delete(`/admin/roles/${role}/modules`),
}

export const webhookService = {
  list: () =>
    api.get('/admin/webhooks/'),

  events: () =>
    api.get('/admin/webhooks/events'),

  create: (data) =>
    api.post('/admin/webhooks/', data),

  update: (id, data) =>
    api.patch(`/admin/webhooks/${id}`, data),

  remove: (id) =>
    api.delete(`/admin/webhooks/${id}`),

  rotateSecret: (id) =>
    api.post(`/admin/webhooks/${id}/rotate-secret`),

  ping: (id) =>
    api.post(`/admin/webhooks/${id}/ping`),

  deliveries: (id) =>
    api.get(`/admin/webhooks/${id}/deliveries`),

  retryDelivery: (id, deliveryId) =>
    api.post(`/admin/webhooks/${id}/deliveries/${deliveryId}/retry`),
}

export const threatIntelService = {
  status: () =>
    api.get('/threat-intel/status'),

  // Admin: pull both feeds now, when the daily refresh is on.
  refresh: () =>
    api.post('/threat-intel/refresh'),

  // Admin: apply a file downloaded out of band (installations without Internet).
  importFeed: (feed, file, force = false) => {
    const form = new FormData()
    form.append('feed', feed)
    form.append('force', force ? 'true' : 'false')
    form.append('file', file)
    return api.post('/threat-intel/import', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
}

export const ticketingService = {
  status: () =>
    api.get('/admin/ticketing/'),

  syncNow: () =>
    api.post('/admin/ticketing/sync'),
}

export const userService = {
  list: () =>
    api.get('/users/'),

  updateRole: (id, role) =>
    api.patch(`/users/${id}/role`, { role }),

  // The teams whose hosts the user sees; [] gives back the whole estate.
  updateTeams: (id, teams) =>
    api.put(`/users/${id}/teams`, { teams }),

  // Accounts are opened by an administrator: there is no self-registration.
  create: (data) =>
    api.post('/users/', data),

  setActive: (id, active) =>
    api.patch(`/users/${id}/active`, { active }),

  resetPassword: (id, password) =>
    api.put(`/users/${id}/password`, { password }),

  remove: (id) =>
    api.delete(`/users/${id}`),
}

export const remediationService = {
  // Open fixes, the one removing the most risk first.
  listActions: (params = {}) =>
    api.get('/remediation/actions', { params }),

  getAction: (id) =>
    api.get(`/remediation/actions/${id}`),

  exportHosts: (id) =>
    api.get(`/remediation/actions/${id}/hosts.csv`, { responseType: 'blob' }),

  // One ticket per team owning the hosts; findings already ticketed stay put.
  createTickets: (actionId) =>
    api.post(`/remediation/actions/${actionId}/tickets`),

  listTickets: (params = {}) =>
    api.get('/remediation/tickets', { params }),

  getTicket: (id) =>
    api.get(`/remediation/tickets/${id}`),

  updateTicket: (id, data) =>
    api.patch(`/remediation/tickets/${id}`, data),

  exportTicketHosts: (id) =>
    api.get(`/remediation/tickets/${id}/hosts.csv`, { responseType: 'blob' }),

  listTeams: () =>
    api.get('/remediation/teams'),
}

export const extractService = {
  datasets: () =>
    api.get('/extracts/datasets'),

  // A preview is the same extract, as JSON and cut short.
  preview: (dataset, params) =>
    api.get(`/extracts/${dataset}`, { params: { ...params, format: 'json', limit: 20 } }),

  download: (dataset, params) =>
    api.get(`/extracts/${dataset}`, { params, responseType: 'blob' }),

  listSaved: () =>
    api.get('/extracts/saved'),

  save: (data) =>
    api.post('/extracts/saved', data),

  deleteSaved: (id) =>
    api.delete(`/extracts/saved/${id}`),

  runSaved: (id) =>
    api.get(`/extracts/saved/${id}/run`, { responseType: 'blob' }),

  listTokens: () =>
    api.get('/extracts/tokens'),

  createToken: (name, expiresInDays) =>
    api.post('/extracts/tokens', { name, expires_in_days: expiresInDays }),

  revokeToken: (id) =>
    api.delete(`/extracts/tokens/${id}`),
}

export const categorizationService = {
  matrix: (params = {}) =>
    api.get('/categorization/matrix', { params }),

  // The open findings of one cell of the matrix.
  cellFindings: (params = {}) =>
    api.get('/categorization/findings', { params }),
}
