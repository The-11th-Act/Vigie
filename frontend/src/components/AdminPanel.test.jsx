import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '../test/render'
import userEvent from '@testing-library/user-event'

import AdminPanel from './AdminPanel'
import { adminService, userService } from '../services'

vi.mock('../services', () => ({
  adminService: {
    getModules: vi.fn(),
    toggleModule: vi.fn(),
    setRoleProfile: vi.fn(),
    resetRoleProfile: vi.fn(),
  },
  userService: { list: vi.fn(), updateRole: vi.fn() },
}))

const OVERVIEW = {
  modules: [
    { key: 'dashboard', label: 'Dashboard', enabled: true, admin_only: false },
    { key: 'scans', label: 'Scans', enabled: true, admin_only: false },
    { key: 'admin', label: 'Administration', enabled: true, admin_only: true },
  ],
  profiles: {
    admin: ['dashboard', 'scans', 'admin'],
    analyst: ['dashboard', 'scans'],
    remediator: ['dashboard'],
  },
  defaults: {},
  customized: ['remediator'],
}

const USERS = [
  { id: 1, username: 'admin', email: 'admin@test.com', role: 'admin' },
  { id: 2, username: 'bob', email: 'bob@test.com', role: 'analyst' },
]

function renderPanel() {
  adminService.getModules.mockResolvedValue({ data: OVERVIEW })
  userService.list.mockResolvedValue({ data: USERS })
  return render(<AdminPanel />)
}

describe('AdminPanel', () => {
  beforeEach(() => vi.clearAllMocks())

  it('grants a module to a role by appending it to its profile', async () => {
    adminService.setRoleProfile.mockResolvedValue({ data: OVERVIEW })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByLabelText('Scans for Remediator'))

    expect(adminService.setRoleProfile).toHaveBeenCalledWith('remediator', ['dashboard', 'scans'])
  })

  it('switches a module off for everybody', async () => {
    adminService.toggleModule.mockResolvedValue({ data: OVERVIEW })
    const user = userEvent.setup()
    renderPanel()

    await user.click(await screen.findByLabelText('Scans enabled'))

    expect(adminService.toggleModule).toHaveBeenCalledWith('scans', false)
  })

  it('never lets the administration module be taken away', async () => {
    renderPanel()

    expect(await screen.findByLabelText('Administration enabled')).toBeDisabled()
    expect(screen.getByLabelText('Administration for Administrator')).toBeChecked()
    expect(screen.getByLabelText('Administration for Analyst')).toBeDisabled()
  })

  it('resets only a customized role', async () => {
    adminService.resetRoleProfile.mockResolvedValue({ data: { ...OVERVIEW, customized: [] } })
    const user = userEvent.setup()
    renderPanel()

    expect(screen.queryByLabelText('Reset the Analyst profile')).not.toBeInTheDocument()
    await user.click(await screen.findByLabelText('Reset the Remediator profile'))

    expect(adminService.resetRoleProfile).toHaveBeenCalledWith('remediator')
    expect(screen.queryByLabelText('Reset the Remediator profile')).not.toBeInTheDocument()
  })

  it('shows why a role change was refused', async () => {
    userService.updateRole.mockRejectedValue({
      response: { data: { detail: 'The last administrator cannot be demoted' } },
    })
    const user = userEvent.setup()
    renderPanel()

    await user.selectOptions(await screen.findByLabelText('Role of admin'), 'analyst')

    expect(await screen.findByText('The last administrator cannot be demoted')).toBeInTheDocument()
  })
})
