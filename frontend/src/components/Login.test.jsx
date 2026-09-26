import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import Login from './Login'
import { AuthProvider } from '../auth/AuthContext'
import { authService } from '../services'

vi.mock('../services', () => ({
  authService: { login: vi.fn(), getMe: vi.fn(), logout: vi.fn() },
}))

const navigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

function renderLogin() {
  // Nobody is signed in when the login page opens.
  authService.getMe.mockRejectedValue({ response: { status: 401 } })
  return render(
    <MemoryRouter>
      <AuthProvider>
        <Login />
      </AuthProvider>
    </MemoryRouter>
  )
}

async function submitCredentials(user, username = 'admin', password = 'adminpass123456') {
  await user.type(screen.getByLabelText(/username/i), username)
  await user.type(screen.getByLabelText(/password/i), password)
  await user.click(screen.getByRole('button', { name: /sign in/i }))
}

describe('Login', () => {
  beforeEach(() => navigate.mockClear())

  it('signs in without writing any token to the browser storage', async () => {
    // The API answers with HttpOnly cookies; the body carries no token.
    authService.login.mockResolvedValue({ data: { role: 'admin', username: 'admin' } })

    const user = userEvent.setup()
    renderLogin()
    await submitCredentials(user)

    await waitFor(() => {
      expect(navigate).toHaveBeenCalledWith('/', { replace: true })
    })
    expect(authService.login).toHaveBeenCalledWith('admin', 'adminpass123456')
    expect(localStorage.length).toBe(0)
  })

  it('shows the API error and keeps the user on the page', async () => {
    authService.login.mockRejectedValue({
      response: { data: { detail: 'Incorrect username or password' } },
    })

    const user = userEvent.setup()
    renderLogin()
    await submitCredentials(user, 'admin', 'wrongpass')

    expect(await screen.findByText(/incorrect username or password/i)).toBeInTheDocument()
    expect(navigate).not.toHaveBeenCalledWith('/', { replace: true })
  })

  it('surfaces a lockout message from the throttle', async () => {
    authService.login.mockRejectedValue({
      response: { data: { detail: 'Too many failed login attempts. Try again later.' } },
    })

    const user = userEvent.setup()
    renderLogin()
    await submitCredentials(user, 'admin', 'wrongpass')

    expect(await screen.findByText(/too many failed login attempts/i)).toBeInTheDocument()
  })
})
