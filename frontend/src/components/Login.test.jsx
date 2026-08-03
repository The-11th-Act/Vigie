import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'

import Login from './Login'
import { authService } from '../services'

vi.mock('../services', () => ({
  authService: { login: vi.fn() },
}))

const navigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return { ...actual, useNavigate: () => navigate }
})

function renderLogin() {
  return render(
    <MemoryRouter>
      <Login />
    </MemoryRouter>
  )
}

async function submitCredentials(user, username = 'admin', password = 'adminpass123456') {
  await user.type(screen.getByLabelText(/username/i), username)
  await user.type(screen.getByLabelText(/password/i), password)
  await user.click(screen.getByRole('button', { name: /sign in/i }))
}

describe('Login', () => {
  it('stores both tokens and the identity on success', async () => {
    authService.login.mockResolvedValue({
      data: {
        access_token: 'access-1',
        refresh_token: 'refresh-1',
        role: 'admin',
        username: 'admin',
      },
    })

    const user = userEvent.setup()
    renderLogin()
    await submitCredentials(user)

    await waitFor(() => {
      expect(localStorage.getItem('access_token')).toBe('access-1')
    })
    // Without the refresh token the session could not survive expiry.
    expect(localStorage.getItem('refresh_token')).toBe('refresh-1')
    expect(localStorage.getItem('role')).toBe('admin')
    expect(navigate).toHaveBeenCalledWith('/', { replace: true })
  })

  it('shows the API error and keeps the user on the page', async () => {
    authService.login.mockRejectedValue({
      response: { data: { detail: 'Incorrect username or password' } },
    })

    const user = userEvent.setup()
    renderLogin()
    await submitCredentials(user, 'admin', 'wrongpass')

    expect(await screen.findByText(/incorrect username or password/i)).toBeInTheDocument()
    expect(localStorage.getItem('access_token')).toBeNull()
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
