import { describe, it, expect, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'

import ScanHistory from './ScanHistory'
import { scanService } from '../services'

vi.mock('../services', () => ({
  scanService: { list: vi.fn() },
}))

describe('ScanHistory', () => {
  it('lists recent scans with what each one closed', async () => {
    scanService.list.mockResolvedValue({
      data: {
        total: 1,
        items: [
          {
            id: 1,
            filename: 'dmz.nessus',
            scan_type: 'nessus',
            status: 'Success',
            processed_records: 40,
            new_associations: 6,
            reopened: 2,
            auto_remediated: 9,
            created_at: '2026-09-25T08:00:00Z',
          },
        ],
      },
    })
    render(<ScanHistory />)

    const row = (await screen.findByText('dmz.nessus')).closest('tr')
    expect(within(row).getByText('Success')).toBeInTheDocument()
    expect(within(row).getByText('9')).toBeInTheDocument()
    expect(scanService.list).toHaveBeenCalledWith({ limit: 10 })
  })

  it('says so when nothing was uploaded yet', async () => {
    scanService.list.mockResolvedValue({ data: { total: 0, items: [] } })
    render(<ScanHistory />)

    expect(await screen.findByText('No scan uploaded yet.')).toBeInTheDocument()
  })
})
