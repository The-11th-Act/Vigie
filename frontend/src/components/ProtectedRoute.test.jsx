import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import ProtectedRoute from './ProtectedRoute'
import { AuthProvider } from '../auth/AuthContext'
import { authService } from '../services'

vi.mock('../services', () => ({
  authService: { getMe: vi.fn(), login: vi.fn(), logout: vi.fn() },
}))

function renderAt(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<div>login screen</div>} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <div>dashboard</div>
              </ProtectedRoute>
            }
          />
        </Routes>
      </AuthProvider>
    </MemoryRouter>
  )
}

describe('ProtectedRoute', () => {
  it('redirects to /login when the API knows no session', async () => {
    authService.getMe.mockRejectedValue({ response: { status: 401 } })
    renderAt('/')
    expect(await screen.findByText('login screen')).toBeInTheDocument()
    expect(screen.queryByText('dashboard')).not.toBeInTheDocument()
  })

  it('renders the protected content once the API confirms the session', async () => {
    authService.getMe.mockResolvedValue({ data: { username: 'admin', role: 'admin' } })
    renderAt('/')
    expect(await screen.findByText('dashboard')).toBeInTheDocument()
  })

  it('does not trust anything left in localStorage', async () => {
    // Regression: the route used to open on the mere presence of a token.
    localStorage.setItem('access_token', 'a-stale-token')
    authService.getMe.mockRejectedValue({ response: { status: 401 } })
    renderAt('/')
    expect(await screen.findByText('login screen')).toBeInTheDocument()
    expect(localStorage.getItem('access_token')).toBeNull()
  })
})
