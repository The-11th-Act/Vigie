import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import AdminTicketing from './AdminTicketing'
import { ticketingService } from '../services'

vi.mock('../services', () => ({
  ticketingService: {
    status: vi.fn(),
    syncNow: vi.fn(),
  },
}))

const STATUS = {
  connector: 'glpi',
  label: 'GLPI',
  enabled: true,
  configured: true,
  url: 'https://glpi.example.com/apirest.php',
  interval_minutes: 5,
  team_groups: { Servers: 12 },
  export_unmapped_teams: true,
  linked: 12,
  foreign: 0,
  gone: 1,
  errors: 2,
  pending_export: 3,
  last_run_at: '2026-10-02T10:00:00Z',
  last_success_at: '2026-10-02T10:00:00Z',
  last_error: null,
  last_result: { exported: 3, pulled: 1, solved: 0, reopened: 0, replaced: 0, gone: 0, foreign: 0, errors: 0 },
}

describe('AdminTicketing', () => {
  beforeEach(() => vi.clearAllMocks())

  it('says how to set it up when GLPI is not configured', async () => {
    ticketingService.status.mockResolvedValue({ data: { ...STATUS, configured: false } })
    render(<AdminTicketing />)

    expect(await screen.findByText(/Not configured/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /sync now/i })).toBeNull()
  })

  it('shows where the sync stands', async () => {
    ticketingService.status.mockResolvedValue({ data: STATUS })
    render(<AdminTicketing />)

    expect(await screen.findByText('Sync every 5 min')).toBeInTheDocument()
    expect(screen.getByText('https://glpi.example.com/apirest.php')).toBeInTheDocument()
    expect(screen.getByText('linked').previousSibling).toHaveTextContent('12')
    expect(screen.getByText('to export').previousSibling).toHaveTextContent('3')
    expect(screen.getByText(/3 exported, 1 moved by the teams/)).toBeInTheDocument()
    // Only when there are some: a production never has any.
    expect(screen.queryByText('other instance')).toBeNull()
  })

  it('reports a failed run and links from another instance', async () => {
    ticketingService.status.mockResolvedValue({
      data: { ...STATUS, foreign: 4, last_error: 'GLPI refused the session (HTTP 401)' },
    })
    render(<AdminTicketing />)

    expect(await screen.findByText(/Last run failed: GLPI refused the session/)).toBeInTheDocument()
    expect(screen.getByText('other instance').previousSibling).toHaveTextContent('4')
  })

  it('queues a sync on demand', async () => {
    ticketingService.status.mockResolvedValue({ data: STATUS })
    ticketingService.syncNow.mockResolvedValue({ data: { task_id: 't1' } })
    const user = userEvent.setup()
    render(<AdminTicketing />)

    await user.click(await screen.findByRole('button', { name: /sync now/i }))

    await waitFor(() => expect(ticketingService.syncNow).toHaveBeenCalledTimes(1))
    expect(await screen.findByText(/Sync queued/)).toBeInTheDocument()
    await waitFor(() => expect(ticketingService.status).toHaveBeenCalledTimes(2))
  })

  it('cannot sync while the sync is disabled', async () => {
    ticketingService.status.mockResolvedValue({ data: { ...STATUS, enabled: false } })
    render(<AdminTicketing />)

    expect(await screen.findByText('Sync disabled')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sync now/i })).toBeDisabled()
  })
})
