import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'

import InstanceBanner from './InstanceBanner'
import { instanceService } from '../services'

vi.mock('../services', () => ({
  instanceService: { get: vi.fn() },
}))

const BASE_TITLE = document.title

describe('InstanceBanner', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    document.title = BASE_TITLE
  })

  it('names a staging deployment on screen and in the tab title', async () => {
    instanceService.get.mockResolvedValue({ data: { banner: 'Préproduction' } })

    render(<InstanceBanner />)

    expect(await screen.findByRole('status')).toHaveTextContent('Préproduction')
    const expected = ['Préproduction', BASE_TITLE].filter(Boolean).join(' · ')
    await waitFor(() => expect(document.title).toBe(expected))
  })

  it('shows nothing in production', async () => {
    instanceService.get.mockResolvedValue({ data: { banner: null } })

    render(<InstanceBanner />)

    await waitFor(() => expect(instanceService.get).toHaveBeenCalled())
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
    expect(document.title).toBe(BASE_TITLE)
  })

  it('never blocks the app when the API cannot say', async () => {
    instanceService.get.mockRejectedValue(new Error('Network Error'))

    render(<InstanceBanner />)

    await waitFor(() => expect(instanceService.get).toHaveBeenCalled())
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })
})
