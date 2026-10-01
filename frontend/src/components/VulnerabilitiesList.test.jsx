import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import VulnerabilitiesList from './VulnerabilitiesList'
import { vulnerabilityService } from '../services'

vi.mock('../services', () => ({
  vulnerabilityService: { list: vi.fn() },
}))

const CVE = { id: 1, cve_id: 'CVE-2024-3094', title: 'xz backdoor', cvss_score: 10, severity: 'Critical' }

function lastCall() {
  return vulnerabilityService.list.mock.calls.at(-1)[0]
}

describe('VulnerabilitiesList', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vulnerabilityService.list.mockResolvedValue({ data: { total: 45, items: [CVE] } })
  })

  it('lists the catalogue with its total', async () => {
    render(<VulnerabilitiesList />)

    expect(await screen.findByText('CVE-2024-3094')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Vulnerability Database (45)' })).toBeInTheDocument()
    expect(lastCall()).toMatchObject({ skip: 0, limit: 20 })
  })

  it('pages through the catalogue', async () => {
    render(<VulnerabilitiesList />)

    await userEvent.click(await screen.findByRole('button', { name: 'Next page' }))

    await waitFor(() => expect(lastCall()).toMatchObject({ skip: 20 }))
    expect(await screen.findByText('Page 2 of 3')).toBeInTheDocument()
  })

  it('searches once typing stops, from the first page', async () => {
    render(<VulnerabilitiesList />)
    await userEvent.click(await screen.findByRole('button', { name: 'Next page' }))
    await waitFor(() => expect(lastCall()).toMatchObject({ skip: 20 }))

    await userEvent.type(screen.getByRole('searchbox', { name: /search by cve/i }), 'xz')

    await waitFor(() => expect(lastCall()).toMatchObject({ search: 'xz', skip: 0 }))
    // One search request for the whole word, not one per keystroke.
    const searches = vulnerabilityService.list.mock.calls.filter(([params]) => params.search)
    expect(searches.map(([params]) => params.search)).toEqual(['xz'])
  })

  it('filters by severity from the first page', async () => {
    render(<VulnerabilitiesList />)
    await userEvent.click(await screen.findByRole('button', { name: 'Next page' }))

    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Severity' }), 'High')

    await waitFor(() => expect(lastCall()).toMatchObject({ severity: 'High', skip: 0 }))
  })
})
