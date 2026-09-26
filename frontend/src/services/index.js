import api, { COOKIE_SESSION } from './api'

export const authService = {
  // Cookie mode: the API answers with HttpOnly session cookies and keeps the
  // tokens out of the response body.
  login: (username, password) =>
    api.post('/auth/login', { username, password }, { headers: COOKIE_SESSION }),

  register: (email, username, password) =>
    api.post('/auth/register', { email, username, password }),

  // Probed on start-up: a 401 just means nobody is signed in.
  getMe: () =>
    api.get('/auth/me', { skipLoginRedirect: true }),

  // The refresh token is the session cookie; the API clears the cookies.
  logout: () =>
    api.post('/auth/logout'),
}

export const dashboardService = {
  getStats: () =>
    api.get('/dashboard/stats'),

  getTopRisks: (limit = 10) =>
    api.get('/dashboard/top-risks', { params: { limit } }),
}

export const assetService = {
  list: (params = {}) =>
    api.get('/assets/', { params }),

  get: (id) =>
    api.get(`/assets/${id}`),

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

  create: (data) =>
    api.post('/vulnerabilities/', data),

  getByAsset: (assetId, params = {}) =>
    api.get(`/vulnerabilities/assets/${assetId}`, { params }),

  getFindings: (params = {}) =>
    api.get('/vulnerabilities/findings', { params }),

  updateFinding: (id, data) =>
    api.patch(`/vulnerabilities/findings/${id}`, data),

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