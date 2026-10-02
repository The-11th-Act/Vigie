import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import ChangePassword from './ChangePassword'
import { AuthContext } from '../auth/AuthContext'
import { meService } from '../services'

vi.mock('../services', () => ({
  meService: { changePassword: vi.fn() },
}))

function setup() {
  const logout = vi.fn().mockResolvedValue()
  render(
    <AuthContext.Provider value={{ user: { username: 'alice', role: 'analyst' }, logout }}>
      <ChangePassword />
    </AuthContext.Provider>
  )
  return logout
}

async function fill(user, { current = 'old-passw0rd-123', next = 'brand-new-passw0rd', again = next } = {}) {
  await user.type(screen.getByLabelText('Current password'), current)
  await user.type(screen.getByLabelText('New password'), next)
  await user.type(screen.getByLabelText('New password, again'), again)
}

describe('ChangePassword', () => {
  beforeEach(() => vi.clearAllMocks())

  it('changes it, then signs out: every session has ended', async () => {
    meService.changePassword.mockResolvedValue({})
    const user = userEvent.setup()
    const logout = setup()

    await fill(user)
    await user.click(screen.getByRole('button', { name: 'Change password' }))

    await waitFor(() =>
      expect(meService.changePassword).toHaveBeenCalledWith('old-passw0rd-123', 'brand-new-passw0rd')
    )
    await waitFor(() => expect(logout).toHaveBeenCalled())
  })

  it('wants the new password twice, the same', async () => {
    const user = userEvent.setup()
    setup()

    await fill(user, { again: 'something-else-1' })

    expect(screen.getByText('The two new passwords differ.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Change password' })).toBeDisabled()
  })

  it('stays signed in when the current password is wrong', async () => {
    meService.changePassword.mockRejectedValue({
      response: { status: 403, data: { detail: 'The current password is not right' } },
    })
    const user = userEvent.setup()
    const logout = setup()

    await fill(user)
    await user.click(screen.getByRole('button', { name: 'Change password' }))

    expect(await screen.findByText('The current password is not right')).toBeInTheDocument()
    expect(logout).not.toHaveBeenCalled()
  })
})
