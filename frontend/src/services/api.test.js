import { describe, it, expect, vi, afterEach } from 'vitest'

import api, { purgeLegacySession, readCookie } from './api'
import { authService } from './index'

function setCookie(value) {
  document.cookie = value
}

afterEach(() => {
  document.cookie = 'vigie_csrf=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/'
})

// Runs the request interceptors without sending anything.
async function outgoing(config) {
  let captured
  const adapter = (cfg) => {
    captured = cfg
    return Promise.resolve({ data: {}, status: 200, statusText: 'OK', headers: {}, config: cfg })
  }
  await api.request({ ...config, adapter })
  return captured
}

describe('api — browser session', () => {
  it('echoes the CSRF cookie on a state-changing request', async () => {
    setCookie('vigie_csrf=abc123; path=/')
    const request = await outgoing({ method: 'post', url: '/assets/' })
    expect(request.headers['X-CSRF-Token']).toBe('abc123')
  })

  it('does not bother for a read', async () => {
    setCookie('vigie_csrf=abc123; path=/')
    const request = await outgoing({ method: 'get', url: '/assets/' })
    expect(request.headers['X-CSRF-Token']).toBeUndefined()
  })

  it('never sends an Authorization header from the browser storage', async () => {
    localStorage.setItem('access_token', 'stale')
    const request = await outgoing({ method: 'get', url: '/assets/' })
    expect(request.headers.Authorization).toBeUndefined()
  })

  it('reads a cookie by name', () => {
    setCookie('vigie_csrf=x%3Dy; path=/')
    expect(readCookie('vigie_csrf')).toBe('x=y')
    expect(readCookie('absent')).toBeNull()
  })

  it('purges the tokens an older version left in localStorage', () => {
    for (const key of ['access_token', 'refresh_token', 'role', 'username']) {
      localStorage.setItem(key, 'old')
    }
    purgeLegacySession()
    expect(localStorage.length).toBe(0)
  })

  it('asks the API for cookies on login', async () => {
    const post = vi.spyOn(api, 'post').mockResolvedValue({ data: {} })
    await authService.login('admin', 'pw')
    expect(post).toHaveBeenCalledWith(
      '/auth/login',
      { username: 'admin', password: 'pw' },
      { headers: { 'X-Session-Mode': 'cookie' } },
    )
  })
})
