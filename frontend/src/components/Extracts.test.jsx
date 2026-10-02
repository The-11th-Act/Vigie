import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import Extracts, { extractParams } from './Extracts'
import { extractService } from '../services'

vi.mock('../services', () => ({
  extractService: {
    datasets: vi.fn(),
    preview: vi.fn(),
    download: vi.fn(),
    listSaved: vi.fn(),
    save: vi.fn(),
    deleteSaved: vi.fn(),
    runSaved: vi.fn(),
    listTokens: vi.fn(),
    createToken: vi.fn(),
    revokeToken: vi.fn(),
  },
}))

const FINDINGS = {
  key: 'findings',
  label: 'Findings (risk backlog)',
  columns: [
    { key: 'cve_id', label: 'CVE' },
    { key: 'asset', label: 'Asset' },
    { key: 'risk_score', label: 'Risk score' },
  ],
  filters: [
    { key: 'kev_only', label: 'Known exploited (KEV) only', type: 'bool', options: [] },
    { key: 'status', label: 'Status', type: 'enum', options: ['Open', 'Remediated'] },
  ],
}

const ASSETS = {
  key: 'assets',
  label: 'Assets',
  columns: [{ key: 'ip_address', label: 'IP address' }],
  filters: [],
}

function setup({ saved = [], tokens = [] } = {}) {
  extractService.datasets.mockResolvedValue({ data: [FINDINGS, ASSETS] })
  extractService.listSaved.mockResolvedValue({ data: saved })
  extractService.listTokens.mockResolvedValue({ data: tokens })
  return render(<Extracts />)
}

describe('extractParams', () => {
  it('only sends what differs from the defaults', () => {
    expect(extractParams(FINDINGS, ['cve_id', 'asset', 'risk_score'], { kev_only: false, status: '' }, 'csv')).toEqual({
      format: 'csv',
    })
    expect(extractParams(FINDINGS, ['cve_id'], { kev_only: true, status: 'Open' }, 'json')).toEqual({
      format: 'json',
      columns: 'cve_id',
      kev_only: 'true',
      status: 'Open',
    })
  })
})

describe('Extracts', () => {
  beforeEach(() => vi.clearAllMocks())

  it('previews the extract as built, and shows the same call for a script', async () => {
    extractService.preview.mockResolvedValue({ data: [{ cve_id: 'CVE-2024-0001', risk_score: 9 }] })
    const user = userEvent.setup()
    setup()

    await user.click(await screen.findByLabelText('Asset'))
    await user.click(screen.getByLabelText('Known exploited (KEV) only'))
    await user.click(screen.getByRole('button', { name: /preview/i }))

    expect(extractService.preview).toHaveBeenCalledWith('findings', {
      format: 'csv',
      columns: 'cve_id,risk_score',
      kev_only: 'true',
    })
    expect(await screen.findByText('CVE-2024-0001')).toBeInTheDocument()
    expect(screen.getByTestId('curl-command').textContent).toContain(
      '/api/v1/extracts/findings?format=csv&columns=cve_id%2Crisk_score&kev_only=true'
    )
  })

  it('switching dataset resets columns and filters', async () => {
    const user = userEvent.setup()
    setup()

    await user.selectOptions(await screen.findByLabelText('Dataset'), 'assets')

    expect(screen.getByLabelText('IP address')).toBeChecked()
    expect(screen.queryByLabelText('Known exploited (KEV) only')).not.toBeInTheDocument()
  })

  it('saves a named extract', async () => {
    extractService.save.mockResolvedValue({ data: {} })
    const user = userEvent.setup()
    setup()

    await user.type(await screen.findByLabelText('Extract name'), 'Weekly KEV')
    await user.click(screen.getByLabelText('Known exploited (KEV) only'))
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    await waitFor(() =>
      expect(extractService.save).toHaveBeenCalledWith({
        name: 'Weekly KEV',
        dataset: 'findings',
        columns: ['cve_id', 'asset', 'risk_score'],
        filters: { kev_only: true },
        format: 'csv',
      })
    )
  })

  it('offers Excel, for the download and a saved extract alike', async () => {
    extractService.save.mockResolvedValue({ data: {} })
    const user = userEvent.setup()
    setup()

    await user.selectOptions(await screen.findByLabelText('Format'), 'xlsx')
    await user.type(screen.getByLabelText('Extract name'), 'For Excel')
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    expect(screen.getByTestId('curl-command').textContent).toContain('format=xlsx')
    await waitFor(() =>
      expect(extractService.save).toHaveBeenCalledWith(expect.objectContaining({ format: 'xlsx' }))
    )
  })

  it('lists saved extracts with the URL to pull', async () => {
    setup({
      saved: [
        {
          id: 4,
          name: 'Weekly KEV',
          dataset: 'findings',
          columns: [],
          filters: {},
          format: 'csv',
          run_path: '/api/v1/extracts/saved/4/run',
        },
      ],
    })

    expect(await screen.findByText('Weekly KEV')).toBeInTheDocument()
    expect(screen.getByText(`${window.location.origin}/api/v1/extracts/saved/4/run`)).toBeInTheDocument()
  })

  it('shows a new token once, and lists tokens without their secret', async () => {
    extractService.createToken.mockResolvedValue({
      data: { id: 1, name: 'Power BI', prefix: 'vigie_pat_abcd', token: 'vigie_pat_abcdSECRET', active: true },
    })
    const user = userEvent.setup()
    setup({
      tokens: [
        { id: 2, name: 'Old cron', prefix: 'vigie_pat_zzzz', expires_at: '2026-01-01T00:00:00Z', revoked_at: null, active: false },
      ],
    })

    expect(await screen.findByText('Expired')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Revoke Old cron' })).not.toBeInTheDocument()

    await user.type(screen.getByLabelText('Token name'), 'Power BI')
    await user.click(screen.getByRole('button', { name: 'Create token' }))

    expect(extractService.createToken).toHaveBeenCalledWith('Power BI', 90)
    expect(await screen.findByTestId('new-token')).toHaveTextContent('vigie_pat_abcdSECRET')
    expect(screen.getByText(/will not be shown again/i)).toBeInTheDocument()
  })
})
