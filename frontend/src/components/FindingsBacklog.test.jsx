import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import FindingsBacklog from './FindingsBacklog'
import { vulnerabilityService } from '../services'

vi.mock('../services', () => ({
  vulnerabilityService: { getFindings: vi.fn(), updateFinding: vi.fn(), exportFindings: vi.fn() },
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

describe('FindingsBacklog — threat context', () => {
  const THREAT_FINDING = {
    ...FINDING,
    asset: { ...FINDING.asset, internet_facing: true },
    vulnerability: {
      ...FINDING.vulnerability,
      in_kev: true,
      kev_date_added: '2024-04-12',
      kev_ransomware: true,
      epss_score: 0.9432,
    },
    risk_factors: [
      { code: 'kev', label: 'Known exploited (CISA KEV)', multiplier: 1.3, points: null },
      { code: 'overdue', label: 'Past its remediation deadline', multiplier: null, points: 1.5 },
    ],
  }

  it('flags known exploitation, the EPSS probability and exposure', async () => {
    vulnerabilityService.getFindings.mockResolvedValue({
      data: { total: 1, items: [THREAT_FINDING] },
    })
    render(<FindingsBacklog />)

    const kev = await screen.findByText('KEV')
    expect(kev).toHaveAttribute('title', expect.stringContaining('ransomware'))
    expect(screen.getByText('EPSS 94%')).toBeInTheDocument()
    expect(screen.getByText('Exposed')).toBeInTheDocument()
    expect(screen.getByText('9.90')).toHaveAttribute(
      'title',
      'Known exploited (CISA KEV) (×1.3)\nPast its remediation deadline (+1.50)',
    )
  })

  it('shows nothing extra for a finding without threat context', async () => {
    mockOneFinding()
    render(<FindingsBacklog />)

    await screen.findByText('web-prod-01')
    expect(screen.queryByText('KEV')).not.toBeInTheDocument()
    // The EPSS filter options ("EPSS ≥ 10%") are not badges: a badge has a number.
    expect(screen.queryByText(/^EPSS \d/)).not.toBeInTheDocument()
  })

  it('filters on KEV and on the EPSS band', async () => {
    mockOneFinding()
    const user = userEvent.setup()
    render(<FindingsBacklog />)
    await screen.findByText('web-prod-01')

    await user.click(screen.getByLabelText(/known exploited/i))
    await user.selectOptions(screen.getByLabelText(/exploitation likelihood/i), '0.1')

    await waitFor(() => {
      expect(vulnerabilityService.getFindings).toHaveBeenLastCalledWith(
        expect.objectContaining({ kev_only: true, min_epss: '0.1' }),
      )
    })
  })
})

describe('FindingsBacklog — risk acceptance', () => {
  it('sends the chosen end date with the acceptance', async () => {
    mockOneFinding()
    vulnerabilityService.updateFinding.mockResolvedValue({ data: {} })
    const user = userEvent.setup()
    render(<FindingsBacklog />)

    await selectStatus(user, 'Risk Accepted')
    await user.type(screen.getByPlaceholderText(/justification/i), 'Isolated host.')
    const until = screen.getByLabelText(/accepted until/i)
    await user.clear(until)
    await user.type(until, '2027-01-15')
    await user.click(screen.getByRole('button', { name: /save/i }))

    await waitFor(() => {
      expect(vulnerabilityService.updateFinding).toHaveBeenCalledWith(1, {
        status: 'Risk Accepted',
        status_note: 'Isolated host.',
        accepted_until: new Date('2027-01-15T23:59:00').toISOString(),
      })
    })
  })

  it('lets the API pick the default duration when no date is given', async () => {
    mockOneFinding()
    vulnerabilityService.updateFinding.mockResolvedValue({ data: {} })
    const user = userEvent.setup()
    render(<FindingsBacklog />)

    await selectStatus(user, 'Risk Accepted')
    await user.type(screen.getByPlaceholderText(/justification/i), 'Isolated host.')
    await user.click(screen.getByRole('button', { name: /save/i }))

    await waitFor(() => {
      expect(vulnerabilityService.updateFinding).toHaveBeenCalledWith(1, {
        status: 'Risk Accepted',
        status_note: 'Isolated host.',
        accepted_until: undefined,
      })
    })
  })

  it('shows until when an accepted finding stays accepted', async () => {
    vulnerabilityService.getFindings.mockResolvedValue({
      data: {
        total: 1,
        items: [{ ...FINDING, status: 'Risk Accepted', accepted_until: '2027-01-15T12:00:00Z' }],
      },
    })
    render(<FindingsBacklog />)

    expect(await screen.findByText(/^until /)).toBeInTheDocument()
  })
})

describe('FindingsBacklog — export', () => {
  it('exports with the filters on screen', async () => {
    mockOneFinding()
    vulnerabilityService.exportFindings.mockResolvedValue({ data: new Blob(['a,b']) })
    URL.createObjectURL = vi.fn(() => 'blob:x')
    URL.revokeObjectURL = vi.fn()
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    const user = userEvent.setup()
    render(<FindingsBacklog />)
    await screen.findByText('web-prod-01')

    await user.click(screen.getByLabelText(/known exploited/i))
    await user.click(screen.getByRole('button', { name: /export csv/i }))

    await waitFor(() => expect(click).toHaveBeenCalled())
    expect(vulnerabilityService.exportFindings).toHaveBeenCalledWith(
      expect.objectContaining({ kev_only: true }),
    )
  })
})

describe('FindingsBacklog — sources', () => {
  it('lists every scanner that reports the finding', async () => {
    vulnerabilityService.getFindings.mockResolvedValue({
      data: {
        total: 1,
        items: [{ ...FINDING, sources: [{ source: 'nessus' }, { source: 'openvas' }] }],
      },
    })
    render(<FindingsBacklog />)

    expect(await screen.findByText('nessus · openvas')).toBeInTheDocument()
  })
})
