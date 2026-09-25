import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import AssetsList from './AssetsList'
import { assetService } from '../services'

vi.mock('../services', () => ({
  assetService: { list: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn() },
}))

const ASSET = {
  id: 3,
  ip_address: '203.0.113.7',
  hostname: 'edge-01',
  operating_system: 'Debian 12',
  business_criticality: 'High',
  internet_facing: false,
}

function mockAssets(...items) {
  assetService.list.mockResolvedValue({ data: { total: items.length, items } })
}

describe('AssetsList — Internet exposure', () => {
  it('sends the exposure when creating an asset', async () => {
    mockAssets()
    assetService.create.mockResolvedValue({ data: {} })
    const user = userEvent.setup()
    render(<AssetsList />)

    await user.click(await screen.findByRole('button', { name: /new asset/i }))
    await user.type(screen.getByLabelText(/ip address/i), '203.0.113.9')
    await user.click(screen.getByLabelText(/exposed to the internet/i))
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    await waitFor(() => {
      expect(assetService.create).toHaveBeenCalledWith(
        expect.objectContaining({ ip_address: '203.0.113.9', internet_facing: true }),
      )
    })
  })

  it('sends the exposure when editing an asset', async () => {
    // The update payload is built field by field: a field left out of it is
    // silently never saved, which is exactly what this guards against.
    localStorage.setItem('role', 'admin')
    mockAssets(ASSET)
    assetService.update.mockResolvedValue({ data: {} })
    const user = userEvent.setup()
    render(<AssetsList />)

    await user.click(await screen.findByTitle('Edit'))
    await user.click(screen.getByLabelText(/exposed to the internet/i))
    await user.click(screen.getByRole('button', { name: /^save$/i }))

    await waitFor(() => {
      expect(assetService.update).toHaveBeenCalledWith(
        3,
        expect.objectContaining({ internet_facing: true, business_criticality: 'High' }),
      )
    })
  })

  it('flags an exposed asset in the list', async () => {
    mockAssets({ ...ASSET, internet_facing: true })
    render(<AssetsList />)

    expect(await screen.findByText('Exposed')).toBeInTheDocument()
  })
})
