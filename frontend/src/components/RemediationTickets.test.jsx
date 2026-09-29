import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import RemediationPlan from './RemediationPlan'
import RemediationTickets from './RemediationTickets'
import { AuthContext } from '../auth/AuthContext'
import { remediationService } from '../services'

vi.mock('../services', () => ({
  remediationService: {
    listActions: vi.fn(),
    getAction: vi.fn(),
    exportHosts: vi.fn(),
    createTickets: vi.fn(),
    listTickets: vi.fn(),
    getTicket: vi.fn(),
    updateTicket: vi.fn(),
    exportTicketHosts: vi.fn(),
    listTeams: vi.fn(),
  },
}))

const ACTION = { id: 1, reference: 'KB5034127', kind: 'kb', title: 'January rollup', url: null, family: null }

const METRICS = {
  findings_total: 3,
  findings_open: 2,
  hosts_open: 2,
  hosts_total: 2,
  open_risk: 16,
  max_risk: 8,
  next_deadline: null,
  kev: 0,
  overdue: 1,
}

const TICKET = {
  id: 10,
  action_id: 1,
  owner_team: 'Servers',
  title: 'Deploy KB5034127 — Servers',
  status: 'open',
  note: null,
  external_system: null,
  external_ref: 'SEC-1',
  external_url: 'https://jira.example.com/browse/SEC-1',
  created_by_username: 'admin',
  action: ACTION,
  metrics: METRICS,
}

function withRole(role, ui) {
  return (
    <AuthContext.Provider value={{ user: { username: 'u', role } }}>{ui}</AuthContext.Provider>
  )
}

function ticketsListed(items = [TICKET]) {
  remediationService.listTeams.mockResolvedValue({ data: { teams: ['Servers', 'Workplace'] } })
  remediationService.listTickets.mockResolvedValue({ data: { total: items.length, items } })
  remediationService.getTicket.mockResolvedValue({
    data: {
      ticket: TICKET,
      action: { ...ACTION, solution: 'Apply it' },
      hosts: [],
      history: [{ username: 'admin', old_status: null, new_status: 'open', note: null, created_at: null }],
    },
  })
}

describe('Creating tickets from a fix', () => {
  beforeEach(() => vi.clearAllMocks())

  it('tickets the untracked findings and says for which teams', async () => {
    remediationService.listActions.mockResolvedValue({
      data: {
        total: 1,
        items: [
          { action: ACTION, findings: 5, assets: 3, cves: 2, kev: 0, overdue: 0, total_risk: 40, max_risk: 8, next_deadline: null, tracked: 0 },
        ],
        unremediated: { findings: 0, assets: 0, total_risk: 0 },
      },
    })
    remediationService.createTickets.mockResolvedValue({
      data: { created: [{ ...TICKET }, { ...TICKET, id: 11, owner_team: null }], added: 0 },
    })
    const user = userEvent.setup()
    render(<RemediationPlan />)

    await user.click(await screen.findByRole('button', { name: 'Create tickets for KB5034127' }))

    expect(remediationService.createTickets).toHaveBeenCalledWith(1)
    expect(await screen.findByText(/2 tickets created \(Servers, Unassigned\)/)).toBeInTheDocument()
  })

  it('offers nothing when every finding is ticketed', async () => {
    remediationService.listActions.mockResolvedValue({
      data: {
        total: 1,
        items: [
          { action: ACTION, findings: 5, assets: 3, cves: 2, kev: 0, overdue: 0, total_risk: 40, max_risk: 8, next_deadline: null, tracked: 5 },
        ],
        unremediated: { findings: 0, assets: 0, total_risk: 0 },
      },
    })
    render(<RemediationPlan />)

    expect(await screen.findByText('All ticketed')).toBeInTheDocument()
  })
})

describe('RemediationTickets', () => {
  beforeEach(() => vi.clearAllMocks())

  it('lists what is left in each ticket', async () => {
    ticketsListed()
    render(withRole('analyst', <RemediationTickets />))

    expect(await screen.findByRole('cell', { name: 'Servers' })).toBeInTheDocument()
    expect(screen.getByText('2 / 3')).toBeInTheDocument()
    expect(screen.getByText('1 overdue')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /SEC-1/ })).toHaveAttribute(
      'href',
      'https://jira.example.com/browse/SEC-1'
    )
  })

  it('filters by team', async () => {
    ticketsListed()
    const user = userEvent.setup()
    render(withRole('analyst', <RemediationTickets />))

    await user.selectOptions(await screen.findByLabelText('Team filter'), 'Workplace')

    expect(remediationService.listTickets).toHaveBeenLastCalledWith(
      expect.objectContaining({ owner_team: 'Workplace' })
    )
  })

  it('moves a ticket along', async () => {
    ticketsListed()
    remediationService.updateTicket.mockResolvedValue({ data: TICKET })
    const user = userEvent.setup()
    render(withRole('remediator', <RemediationTickets />))

    await user.click(await screen.findByRole('button', { name: /open ticket/i }))
    await user.selectOptions(await screen.findByLabelText('Ticket status'), 'deployed')
    await user.type(screen.getByLabelText('Ticket note'), 'Wave 1 pushed.')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(remediationService.updateTicket).toHaveBeenCalledWith(
        10,
        expect.objectContaining({ status: 'deployed', note: 'Wave 1 pushed.' })
      )
    )
  })

  it('does not offer a remediator to cancel', async () => {
    ticketsListed()
    const user = userEvent.setup()
    render(withRole('remediator', <RemediationTickets />))

    await user.click(await screen.findByRole('button', { name: /open ticket/i }))
    const options = [...(await screen.findByLabelText('Ticket status')).options].map((o) => o.value)

    expect(options).toEqual(['open', 'in_progress', 'deployed'])
  })

  it('wants a reason to cancel', async () => {
    ticketsListed()
    const user = userEvent.setup()
    render(withRole('analyst', <RemediationTickets />))

    await user.click(await screen.findByRole('button', { name: /open ticket/i }))
    await user.selectOptions(await screen.findByLabelText('Ticket status'), 'cancelled')

    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    await user.type(screen.getByLabelText('Ticket note'), 'Hosts decommissioned.')
    expect(screen.getByRole('button', { name: 'Save' })).toBeEnabled()
  })
})
