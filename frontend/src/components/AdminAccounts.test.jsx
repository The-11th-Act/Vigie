import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import { AccountActions, NewAccountForm, errorText } from './AdminAccounts'
import { userService } from '../services'

vi.mock('../services', () => ({
  userService: {
    create: vi.fn(),
    setActive: vi.fn(),
    resetPassword: vi.fn(),
    remove: vi.fn(),
  },
}))

const ROLES = { admin: 'Administrator', analyst: 'Analyst', remediator: 'Remediator' }
const ALICE = { id: 7, username: 'alice', email: 'alice@test.com', role: 'analyst', teams: [], is_active: true }

describe('NewAccountForm', () => {
  beforeEach(() => vi.clearAllMocks())

  it('opens an account with its role and initial password', async () => {
    userService.create.mockResolvedValue({ data: {} })
    const onCreated = vi.fn()
    const user = userEvent.setup()
    render(<NewAccountForm roleLabels={ROLES} onCreated={onCreated} />)

    await user.click(screen.getByRole('button', { name: 'New account' }))
    const create = screen.getByRole('button', { name: 'Create account' })
    expect(create).toBeDisabled()
    await user.type(screen.getByLabelText('Username'), ' newbie ')
    await user.type(screen.getByLabelText('Email'), 'newbie@test.com')
    await user.selectOptions(screen.getByLabelText('Role'), 'remediator')
    await user.type(screen.getByLabelText('Initial password'), 'initial-passw0rd')
    await user.click(create)

    await waitFor(() =>
      expect(userService.create).toHaveBeenCalledWith({
        username: 'newbie',
        email: 'newbie@test.com',
        password: 'initial-passw0rd',
        role: 'remediator',
      })
    )
    expect(onCreated).toHaveBeenCalled()
    expect(screen.queryByRole('form', { name: 'New account' })).not.toBeInTheDocument()
  })

  it('shows what the API refused, as sentences', async () => {
    userService.create.mockRejectedValue({
      response: { data: { detail: [{ msg: 'Value error, password must contain at least one digit' }] } },
    })
    const user = userEvent.setup()
    render(<NewAccountForm roleLabels={ROLES} onCreated={vi.fn()} />)

    await user.click(screen.getByRole('button', { name: 'New account' }))
    await user.type(screen.getByLabelText('Username'), 'newbie')
    await user.type(screen.getByLabelText('Email'), 'newbie@test.com')
    await user.type(screen.getByLabelText('Initial password'), 'nodigitsatall')
    await user.click(screen.getByRole('button', { name: 'Create account' }))

    expect(await screen.findByText('password must contain at least one digit')).toBeInTheDocument()
  })
})

describe('AccountActions', () => {
  beforeEach(() => vi.clearAllMocks())

  it('disables an account, and enables a disabled one', async () => {
    userService.setActive.mockResolvedValue({ data: {} })
    const onChanged = vi.fn()
    const user = userEvent.setup()
    const { rerender } = render(<AccountActions user={ALICE} isSelf={false} onChanged={onChanged} />)

    await user.click(screen.getByRole('button', { name: 'Disable alice' }))
    await waitFor(() => expect(userService.setActive).toHaveBeenCalledWith(7, false))
    expect(onChanged).toHaveBeenCalled()

    rerender(<AccountActions user={{ ...ALICE, is_active: false }} isSelf={false} onChanged={onChanged} />)
    expect(screen.getByText('Disabled')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Enable alice' }))
    await waitFor(() => expect(userService.setActive).toHaveBeenCalledWith(7, true))
  })

  it('sets a new password', async () => {
    userService.resetPassword.mockResolvedValue({})
    const user = userEvent.setup()
    render(<AccountActions user={ALICE} isSelf={false} onChanged={vi.fn()} />)

    await user.click(screen.getByRole('button', { name: 'Reset the password of alice' }))
    await user.type(screen.getByLabelText('New password for alice'), 'brand-new-passw0rd')
    await user.click(screen.getByRole('button', { name: 'Set' }))

    await waitFor(() => expect(userService.resetPassword).toHaveBeenCalledWith(7, 'brand-new-passw0rd'))
    expect(await screen.findByText(/their sessions are closed/)).toBeInTheDocument()
  })

  it('deletes only once confirmed', async () => {
    userService.remove.mockResolvedValue({})
    const user = userEvent.setup()
    render(<AccountActions user={ALICE} isSelf={false} onChanged={vi.fn()} />)

    await user.click(screen.getByRole('button', { name: 'Delete alice' }))
    expect(userService.remove).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Confirm the deletion of alice' }))

    await waitFor(() => expect(userService.remove).toHaveBeenCalledWith(7))
  })

  it("offers nothing on one's own account", () => {
    render(<AccountActions user={ALICE} isSelf onChanged={vi.fn()} />)

    expect(screen.getByText('you')).toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  it('shows why a change was refused', async () => {
    userService.setActive.mockRejectedValue({
      response: { data: { detail: 'The last active administrator cannot be disabled' } },
    })
    const user = userEvent.setup()
    render(<AccountActions user={ALICE} isSelf={false} onChanged={vi.fn()} />)

    await user.click(screen.getByRole('button', { name: 'Disable alice' }))

    expect(await screen.findByText(/last active administrator/)).toBeInTheDocument()
  })
})

describe('errorText', () => {
  it('reads a sentence or a list of problems', () => {
    expect(errorText({ response: { data: { detail: 'Nope' } } })).toBe('Nope')
    expect(errorText({ response: { data: { detail: [{ msg: 'a' }, { msg: 'b' }] } } })).toBe('a; b')
    expect(errorText({ message: 'Network Error' })).toBe('Network Error')
  })
})
