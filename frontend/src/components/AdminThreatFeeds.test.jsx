import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import AdminThreatFeeds from './AdminThreatFeeds'
import { threatIntelService } from '../services'

vi.mock('../services', () => ({
  threatIntelService: { status: vi.fn(), refresh: vi.fn(), importFeed: vi.fn() },
}))

const STATUS = {
  enabled: true,
  stale_after_hours: 72,
  feeds: [
    {
      feed: 'kev',
      last_success_at: '2026-10-02T06:15:00Z',
      last_error: null,
      source_version: '2026.10.01',
      source_date: '2026-10-01',
      records: 1725,
      stale: false,
    },
    {
      feed: 'epss',
      last_success_at: null,
      last_error: 'HTTP 503 from the EPSS mirror',
      source_version: null,
      source_date: null,
      records: 0,
      stale: true,
    },
  ],
}

describe('AdminThreatFeeds', () => {
  beforeEach(() => vi.clearAllMocks())

  it('shows how fresh each feed is, and why one failed', async () => {
    threatIntelService.status.mockResolvedValue({ data: STATUS })
    render(<AdminThreatFeeds />)

    expect(await screen.findByText('CISA KEV')).toBeInTheDocument()
    expect(screen.getByText('Fresh')).toBeInTheDocument()
    expect(screen.getByText('Stale')).toBeInTheDocument()
    // Formatted in the machine's locale: any thousands separator.
    expect(screen.getByText(/^1[\s.,]?725$/)).toBeInTheDocument()
    expect(screen.getByText(/Last attempt failed: HTTP 503/)).toBeInTheDocument()
  })

  it('queues a refresh when the daily one is on', async () => {
    threatIntelService.status.mockResolvedValue({ data: STATUS })
    threatIntelService.refresh.mockResolvedValue({ data: { task_id: 't1' } })
    const user = userEvent.setup()
    render(<AdminThreatFeeds />)

    await user.click(await screen.findByRole('button', { name: /refresh now/i }))

    await waitFor(() => expect(threatIntelService.refresh).toHaveBeenCalled())
    expect(await screen.findByText(/Refresh queued/)).toBeInTheDocument()
  })

  it('offers the import, not the refresh, without Internet access', async () => {
    threatIntelService.status.mockResolvedValue({ data: { ...STATUS, enabled: false } })
    render(<AdminThreatFeeds />)

    expect(await screen.findByRole('button', { name: /refresh now/i })).toBeDisabled()
    expect(screen.getByText(/import the files below/)).toBeInTheDocument()
  })

  it('imports a file and says what it changed', async () => {
    threatIntelService.status.mockResolvedValue({ data: STATUS })
    threatIntelService.importFeed.mockResolvedValue({
      data: { feed: 'epss', status: 'applied', records: 379145, changed: 120, rescored: 48 },
    })
    const user = userEvent.setup()
    render(<AdminThreatFeeds />)
    const file = new File(['cve,epss,percentile'], 'epss.csv.gz')

    await user.selectOptions(await screen.findByLabelText('Feed to import'), 'epss')
    await user.upload(screen.getByLabelText('Feed file'), file)
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: /import/i }))

    await waitFor(() => expect(threatIntelService.importFeed).toHaveBeenCalledWith('epss', file, true))
    expect(
      await screen.findByText(
        /FIRST EPSS applied: 379[\s.,]?145 records, 120 CVE\(s\) changed, 48 finding\(s\) rescored/
      )
    ).toBeInTheDocument()
  })

  it('imports an MSRC document and says how many links moved', async () => {
    threatIntelService.status.mockResolvedValue({
      data: {
        ...STATUS,
        feeds: [
          ...STATUS.feeds,
          {
            feed: 'msrc',
            last_success_at: null,
            last_error: null,
            source_version: null,
            source_date: null,
            records: 0,
            stale: true,
            stale_after_hours: 840,
          },
        ],
      },
    })
    threatIntelService.importFeed.mockResolvedValue({
      data: { feed: 'msrc', status: 'applied', records: 152, changed: 12, rescored: 0 },
    })
    const user = userEvent.setup()
    render(<AdminThreatFeeds />)
    const file = new File(['{}'], '2026-Sep.json')

    expect(await screen.findByText('MSRC (KB supersedence)')).toBeInTheDocument()
    expect(screen.getByText(/MSRC \(KB supersedence\): 35 days/)).toBeInTheDocument()
    await user.selectOptions(screen.getByLabelText('Feed to import'), 'msrc')
    await user.upload(screen.getByLabelText('Feed file'), file)
    await user.click(screen.getByRole('button', { name: /import/i }))

    await waitFor(() => expect(threatIntelService.importFeed).toHaveBeenCalledWith('msrc', file, false))
    expect(
      await screen.findByText(
        'MSRC (KB supersedence) applied: 152 superseded KB(s) known, 12 remediation link(s) moved to a later KB.'
      )
    ).toBeInTheDocument()
  })

  it('shows why a file was refused', async () => {
    threatIntelService.status.mockResolvedValue({ data: STATUS })
    threatIntelService.importFeed.mockRejectedValue({
      response: { status: 400, data: { detail: 'Older than the catalogue already applied' } },
    })
    const user = userEvent.setup()
    render(<AdminThreatFeeds />)

    await user.upload(await screen.findByLabelText('Feed file'), new File(['{}'], 'kev.json'))
    await user.click(screen.getByRole('button', { name: /import/i }))

    expect(await screen.findByText('Older than the catalogue already applied')).toBeInTheDocument()
  })
})
