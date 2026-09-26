import axios from 'axios'

// Browser sessions live in HttpOnly cookies set by the API: no token is ever
// readable from JavaScript, so a script injected into the page cannot steal one.
// State-changing requests echo the CSRF cookie in a header, which another site
// can trigger but never read.
const CSRF_COOKIE = 'vigie_csrf'
const CSRF_HEADER = 'X-CSRF-Token'
export const COOKIE_SESSION = { 'X-Session-Mode': 'cookie' }
const SAFE_METHODS = new Set(['get', 'head', 'options'])

// Keys written by the previous, localStorage-based session. Purged on start-up
// so a token left behind by an older version does not linger in the browser.
const LEGACY_KEYS = ['access_token', 'refresh_token', 'role', 'username']

export function purgeLegacySession() {
  LEGACY_KEYS.forEach((key) => localStorage.removeItem(key))
}

export function readCookie(name) {
  const prefix = `${name}=`
  const match = document.cookie.split('; ').find((part) => part.startsWith(prefix))
  return match ? decodeURIComponent(match.slice(prefix.length)) : null
}

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  if (!SAFE_METHODS.has((config.method || 'get').toLowerCase())) {
    const csrf = readCookie(CSRF_COOKIE)
    if (csrf) config.headers[CSRF_HEADER] = csrf
  }
  return config
})

// A single in-flight refresh shared by every request that got a 401, so a page
// firing several calls at once does not burn (and rotate away) the refresh
// token multiple times over.
let refreshInFlight = null

function refreshSession() {
  if (!refreshInFlight) {
    refreshInFlight = axios
      .post('/api/v1/auth/refresh', null, {
        headers: { ...COOKIE_SESSION, [CSRF_HEADER]: readCookie(CSRF_COOKIE) || '' },
      })
      .finally(() => {
        refreshInFlight = null
      })
  }
  return refreshInFlight
}

function redirectToLogin(config) {
  // The session probe on start-up expects a 401 when nobody is signed in, and
  // the login page must not reload itself in a loop.
  if (config?.skipLoginRedirect || window.location.pathname === '/login') return
  window.location.href = '/login'
}

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const original = error.config

    // Retry once, and never for the auth calls themselves — that would loop.
    const canRetry =
      error.response?.status === 401 &&
      original &&
      !original._retried &&
      !original.url?.includes('/auth/refresh') &&
      !original.url?.includes('/auth/login')

    if (canRetry) {
      original._retried = true
      try {
        await refreshSession()
        return api(original)
      } catch {
        redirectToLogin(original)
        return Promise.reject(error)
      }
    }

    if (error.response?.status === 401) {
      redirectToLogin(original)
    }
    return Promise.reject(error)
  }
)

export default api
