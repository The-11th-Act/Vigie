import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '../test/render'
import userEvent from '@testing-library/user-event'

import Categorization from './Categorization'
import { categorizationService } from '../services'

vi.mock('../services', () => ({
  categorizationService: { matrix: vi.fn(), cellFindings: vi.fn() },
}))

const MATRIX = {
  dimension: { key: 'asset_type', label: 'Asset type' },
  dimensions: [
    { key: 'asset_type', label: 'Asset type' },
    { key: 'environment', label: 'Environment' },
  ],
  rows: [
    { key: 'operating_system', label: 'Operating system' },
    { key: 'browser', label: 'Browser' },
  ],
  columns: [
    { key: 'server', label: 'Server' },
    { key: 'workstation', label: 'Workstation' },
  ],
  cells: [
    { row: 'operating_system', col: 'server', findings: 3, assets: 1, total_risk: 27, max_risk: 9, kev: 1, overdue: 0 },
    { row: 'browser', col: 'workstation', findings: 2, assets: 2, total_risk: 16, max_risk: 8, kev: 0, overdue: 1 },
  ],
}

const FINDING = {
  id: 5,
  risk_score: 8,
  risk_level: 'High',
  is_overdue: true,
  remediation_deadline: null,
  asset: { hostname: 'pc-01', ip_address: '10.0.1.1', owner_team: 'Workplace' },
  vulnerability: { cve_id: 'CVE-2024-0001', title: 'Google Chrome < 120', in_kev: false },
  remediations: [{ action: { reference: 'nessus:1', kind: 'vendor_fix', title: 'Update Chrome' } }],
}

describe('Categorization', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    categorizationService.matrix.mockResolvedValue({ data: MATRIX })
  })

  it('draws the matrix, by open risk by default', async () => {
    render(<Categorization />)

    expect(await screen.findByText('Operating system')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Operating system on Server: 3 findings' })).toHaveTextContent('27.0')
    expect(screen.getByText('1 KEV')).toBeInTheDocument()
  })

  it('switches the measure', async () => {
    const user = userEvent.setup()
    render(<Categorization />)

    await user.selectOptions(await screen.findByLabelText('Measure'), 'findings')

    expect(screen.getByRole('button', { name: 'Browser on Workstation: 2 findings' })).toHaveTextContent('2')
  })

  it('asks for another host dimension', async () => {
    const user = userEvent.setup()
    render(<Categorization />)

    // The dimensions come with the matrix: wait for the option, as a user would.
    await screen.findByRole('option', { name: 'Environment' })
    await user.selectOptions(screen.getByLabelText('Host dimension'), 'environment')

    expect(categorizationService.matrix).toHaveBeenLastCalledWith(
      expect.objectContaining({ columns: 'environment' })
    )
  })

  it('opens the findings of a cell, once', async () => {
    categorizationService.cellFindings.mockResolvedValue({ data: { total: 1, items: [FINDING] } })
    const user = userEvent.setup()
    render(<Categorization />)

    await user.click(await screen.findByRole('button', { name: 'Browser on Workstation: 2 findings' }))

    expect(await screen.findByText('pc-01')).toBeInTheDocument()
    expect(screen.getByText('Update Chrome')).toBeInTheDocument()
    expect(categorizationService.cellFindings).toHaveBeenCalledWith(
      expect.objectContaining({ category: 'browser', value: 'workstation', columns: 'asset_type' })
    )
    // Regression guard: an unstable dependency would refetch on every render.
    expect(categorizationService.cellFindings).toHaveBeenCalledTimes(1)
  })
})
