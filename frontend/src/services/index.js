import api from './api'

export const authService = {
  login: (username, password) =>
    api.post('/auth/login', { username, password }),

  register: (email, username, password, role = 'analyst') =>
    api.post('/auth/register', { email, username, password, role }),

  getMe: () =>
    api.get('/auth/me'),
}

export const dashboardService = {
  getStats: () =>
    api.get('/dashboard/stats'),
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
}