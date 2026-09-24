import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import FindingsBacklog from './FindingsBacklog'
import { vulnerabilityService } from '../services'

vi.mock('../services', () => ({
  vulnerabilityService: { getFindings: vi.fn(), updateFinding: vi.fn() },
}))

const FINDING = {
  id: 1,
  asset_id: 7,
  status: 'Open',
  risk_score: 9.9,
  risk_level: 'Critical',
  is_overdue: true,
  remediation_deadline: '2026-07-24T00:00:00Z',
  asset: { hostname: 'web-prod-01', ip_address: '10.0.0.5' },
  vulnerability: { cve_id: 'CVE-2024-1234', title: 'RCE in OpenSSL' },
}

function mockOneFinding() {
  vulnerabilityService.getFindings.mockResolvedValue({
    data: { total: 1, items: [FINDING] },
  })
}

async function selectStatus(user, label) {
  const select = await screen.findByDisplayValue('Open')
  await user.selectOptions(select, label)
}

describe('FindingsBacklog', () => {
  it('renders a risk-ranked finding with its asset and CVE', async () => {
    mockOneFinding()
    render(<FindingsBacklog />)

    expect(await screen.findByText('web-prod-01')).toBeInTheDocument()
    expect(screen.getByText('CVE-2024-1234')).toBeInTheDocument()
    expect(screen.getByText('9.90')).toBeInTheDocument()
    expect(screen.getByText('Overdue')).toBeInTheDocument()
  })

  it('requires a justification before accepting a risk', async () => {
    mockOneFinding()
    const user = userEvent.setup()
    render(<FindingsBacklog />)

    await selectStatus(user, 'Risk Accepted')

    // The note is what makes the decision auditable, so Save stays disabled
    // until one is written.
    const save = screen.getByRole('button', { name: /save/i })
    expect(save).toBeDisabled()

    await user.type(screen.getByPlaceholderText(/justification/i), 'Segmented network.')
    expect(save).toBeEnabled()
  })

  it('sends the triage decision with its note', async () => {
    mockOneFinding()
    vulnerabilityService.updateFinding.mockResolvedValue({ data: {} })

    const user = userEvent.setup()
    render(<FindingsBacklog />)

    await selectStatus(user, 'Risk Accepted')
    await user.type(screen.getByPlaceholderText(/justification/i), 'Segmented network.')
    await user.click(screen.getByRole('button', { name: /save/i }))

    await waitFor(() => {
      expect(vulnerabilityService.updateFinding).toHaveBeenCalledWith(1, {
        status: 'Risk Accepted',
        status_note: 'Segmented network.',
      })
    })
  })

  it('does not demand a note to mark something remediated', async () => {
    mockOneFinding()
    const user = userEvent.setup()
    render(<FindingsBacklog />)

    await selectStatus(user, 'Remediated')

    expect(screen.queryByPlaceholderText(/justification/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /save/i })).toBeEnabled()
  })

  it('surfaces a rejected update instead of silently dropping it', async () => {
    mockOneFinding()
    vulnerabilityService.updateFinding.mockRejectedValue({
      response: { data: { detail: 'A status_note is required' } },
    })

    const user = userEvent.setup()
    render(<FindingsBacklog />)

    await selectStatus(user, 'Remediated')
    await user.click(screen.getByRole('button', { name: /save/i }))

    expect(await screen.findByText(/a status_note is required/i)).toBeInTheDocument()
  })
})
