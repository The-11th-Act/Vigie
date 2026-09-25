import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, act } from '@testing-library/react'

import ScanUpload from './ScanUpload'
import { scanService } from '../services'

vi.mock('../services', () => ({
  scanService: { upload: vi.fn(), getStatus: vi.fn(), list: vi.fn() },
}))

const FINISHED_JOB = {
  id: 4,
  task_id: 'abcdef123456',
  scan_type: 'nessus',
  filename: 'weekly.nessus',
  status: 'Success',
  processed_records: 12,
  new_assets: 1,
  new_vulnerabilities: 2,
  new_associations: 3,
  reopened: 1,
  auto_remediated: 5,
  message: null,
  created_at: '2026-09-25T08:00:00Z',
}

async function uploadAFile() {
  const input = document.getElementById('file-input')
  const file = new File(['<NessusClientData_v2/>'], 'weekly.nessus')
  fireEvent.change(input, { target: { files: [file] } })
  fireEvent.click(screen.getByRole('button', { name: /upload & process/i }))
  // Let the upload resolve, then run one polling tick.
  await act(async () => {
    await vi.advanceTimersByTimeAsync(2000)
  })
}

describe('ScanUpload', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    scanService.upload.mockResolvedValue({ data: { task_id: 'abcdef123456' } })
    scanService.list.mockResolvedValue({ data: { total: 0, items: [] } })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it('reads the stored scan job, not a raw Celery state', async () => {
    // Regression: the page waited for `state === "SUCCESS"`, which the status
    // endpoint never returns since it serves the ScanJob record.
    scanService.getStatus.mockResolvedValue({ data: FINISHED_JOB })
    render(<ScanUpload />)

    await uploadAFile()

    expect(screen.getByText('Scan processed successfully!')).toBeInTheDocument()
    expect(screen.getByText('Records processed: 12')).toBeInTheDocument()
    expect(screen.getByText('Reopened: 1')).toBeInTheDocument()
    expect(screen.getByText('Closed automatically (no longer detected): 5')).toBeInTheDocument()
  })

  it('reports a failed scan with its message', async () => {
    scanService.getStatus.mockResolvedValue({
      data: { ...FINISHED_JOB, status: 'Failed', message: 'Unsupported scan type' },
    })
    render(<ScanUpload />)

    await uploadAFile()

    expect(screen.getByText('Processing failed: Unsupported scan type')).toBeInTheDocument()
  })

  it('refreshes the history once the scan is done', async () => {
    scanService.getStatus.mockResolvedValue({ data: FINISHED_JOB })
    render(<ScanUpload />)

    await uploadAFile()

    expect(scanService.list).toHaveBeenCalledTimes(2)
  })
})
