import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import RemediationPlan from './RemediationPlan'
import { remediationService } from '../services'

vi.mock('../services', () => ({
  remediationService: { listActions: vi.fn(), getAction: vi.fn(), exportHosts: vi.fn() },
}))

const ROLLUP = {
  action: { id: 1, reference: 'KB5034127', kind: 'kb', title: 'January rollup', url: null, family: null },
  findings: 6,
  assets: 2,
  cves: 3,
  kev: 1,
  overdue: 2,
  total_risk: 48,
  max_risk: 8,
  next_deadline: '2026-10-10T00:00:00Z',
}

const APACHE = {
  action: { id: 2, reference: 'nessus:183391', kind: 'vendor_fix', title: 'Apache < 2.4.58', url: null, family: null },
  findings: 1,
  assets: 1,
  cves: 1,
  kev: 0,
  overdue: 0,
  total_risk: 5,
  max_risk: 5,
  next_deadline: null,
}

function listing(items = [ROLLUP, APACHE], unremediated = { findings: 0, assets: 0, total_risk: 0 }) {
  remediationService.listActions.mockResolvedValue({
    data: { total: items.length, items, unremediated },
  })
}

describe('RemediationPlan', () => {
  beforeEach(() => vi.clearAllMocks())

  it('lists fixes by what they close, KB first as a badge', async () => {
    listing()
    render(<RemediationPlan />)

    expect(await screen.findByText('KB5034127')).toBeInTheDocument()
    expect(screen.getByText('48.0')).toBeInTheDocument()
    expect(screen.getByText('Apache < 2.4.58')).toBeInTheDocument()
    expect(screen.getByText('Vendor fix · nessus:183391')).toBeInTheDocument()
  })

  it('opens the hosts still waiting for a fix', async () => {
    listing()
    remediationService.getAction.mockResolvedValue({
      data: {
        action: { ...ROLLUP.action, solution: 'Apply Security Update 5034127' },
        hosts: [
          {
            asset_id: 7,
            hostname: 'srv-a',
            ip_address: '10.0.0.1',
            operating_system: 'Windows Server 2019',
            business_criticality: 'High',
            internet_facing: true,
            installed_versions: [],
            fixed_versions: [],
            cves: ['CVE-2024-0001', 'CVE-2024-0002'],
            max_risk: 8,
            next_deadline: null,
            in_kev: true,
            overdue: true,
          },
        ],
      },
    })
    const user = userEvent.setup()
    render(<RemediationPlan />)

    await user.click(await screen.findByRole('button', { name: 'Show hosts for KB5034127' }))

    expect(remediationService.getAction).toHaveBeenCalledWith(1)
    expect(await screen.findByText('srv-a')).toBeInTheDocument()
    expect(screen.getByText('Apply Security Update 5034127')).toBeInTheDocument()
    const hostRow = screen.getByText('srv-a').closest('tr')
    expect(within(hostRow).getByText('Overdue')).toBeInTheDocument()
    expect(within(hostRow).getByText('KEV')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /export hosts/i })).toBeInTheDocument()
  })

  it('filters by kind of fix', async () => {
    listing()
    const user = userEvent.setup()
    render(<RemediationPlan />)

    await user.selectOptions(await screen.findByLabelText('Kind of fix'), 'kb')

    expect(remediationService.listActions).toHaveBeenLastCalledWith(
      expect.objectContaining({ kind: 'kb', skip: 0 })
    )
  })

  it('counts the findings nobody can plan yet', async () => {
    listing([ROLLUP], { findings: 3, assets: 2, total_risk: 12 })
    render(<RemediationPlan />)

    expect(await screen.findByText(/no identified fix/i)).toBeInTheDocument()
    expect(screen.getByText(/3 open findings on 2 hosts/)).toBeInTheDocument()
  })

  it('says when there is nothing to deploy', async () => {
    listing([])
    render(<RemediationPlan />)

    expect(await screen.findByText(/no open fix matches/i)).toBeInTheDocument()
  })
})
