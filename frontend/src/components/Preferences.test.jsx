import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import Preferences from './Preferences'
import { ModulesProvider } from '../auth/ModulesContext'
import { meService } from '../services'

vi.mock('../services', () => ({
  meService: { getModules: vi.fn(), updatePreferences: vi.fn() },
}))

const MODULES = [
  { key: 'dashboard', label: 'Dashboard', hidden: false },
  { key: 'backlog', label: 'Risk Backlog', hidden: false },
  { key: 'assets', label: 'Assets', hidden: false },
]

function renderPreferences() {
  meService.getModules.mockResolvedValue({ data: { role: 'analyst', modules: MODULES } })
  return render(
    <ModulesProvider>
      <Preferences />
    </ModulesProvider>
  )
}

describe('Preferences', () => {
  beforeEach(() => vi.clearAllMocks())

  it('saves the new order and the hidden modules', async () => {
    meService.updatePreferences.mockResolvedValue({
      data: { role: 'analyst', modules: [MODULES[1], MODULES[0], { ...MODULES[2], hidden: true }] },
    })
    const user = userEvent.setup()
    renderPreferences()

    await user.click(await screen.findByLabelText('Move Risk Backlog up'))
    await user.click(screen.getByLabelText('Show Assets in the sidebar'))
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(meService.updatePreferences).toHaveBeenCalledWith(
      ['backlog', 'dashboard', 'assets'],
      ['assets']
    )
    expect(await screen.findByText('Saved.')).toBeInTheDocument()
  })

  it('has nothing to save until something changes', async () => {
    renderPreferences()

    expect(await screen.findByRole('button', { name: 'Save' })).toBeDisabled()
    expect(screen.getByLabelText('Move Dashboard up')).toBeDisabled()
    expect(screen.getByLabelText('Move Assets down')).toBeDisabled()
  })

  it('reports a refused save and keeps the draft', async () => {
    meService.updatePreferences.mockRejectedValue({
      response: { data: { detail: 'unknown module(s): nope' } },
    })
    const user = userEvent.setup()
    renderPreferences()

    await user.click(await screen.findByLabelText('Show Assets in the sidebar'))
    await user.click(screen.getByRole('button', { name: 'Save' }))

    expect(await screen.findByText('unknown module(s): nope')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled())
  })
})
