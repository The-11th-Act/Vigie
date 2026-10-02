import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import VulnerabilitiesList from './VulnerabilitiesList'
import { vulnerabilityService } from '../services'
import { AuthContext } from '../auth/AuthContext'
import { ModulesContext } from '../auth/ModulesContext'

vi.mock('../services', () => ({
  vulnerabilityService: { list: vi.fn(), update: vi.fn(), remove: vi.fn() },
}))

function renderAs(role, teams = null) {
  return render(
    <AuthContext.Provider value={{ user: { username: 'u', role } }}>
      <ModulesContext.Provider value={{ modules: [], teams, loading: false, error: null }}>
        <VulnerabilitiesList />
      </ModulesContext.Provider>
    </AuthContext.Provider>
  )
}

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

  it('lets an analyst correct a score, not delete the CVE', async () => {
    vulnerabilityService.update.mockResolvedValue({ data: { ...CVE, cvss_score: 7.5 } })
    const user = userEvent.setup()
    renderAs('analyst')

    await user.click(await screen.findByRole('button', { name: 'Edit CVE-2024-3094' }))
    expect(screen.queryByRole('button', { name: 'Delete CVE-2024-3094' })).not.toBeInTheDocument()
    const score = screen.getByLabelText('CVSS score of CVE-2024-3094')
    await user.clear(score)
    await user.type(score, '7.5')
    await user.selectOptions(screen.getByLabelText('Severity of CVE-2024-3094'), 'High')
    await user.click(screen.getByRole('button', { name: 'Save' }))

    // Only what changed is sent.
    await waitFor(() =>
      expect(vulnerabilityService.update).toHaveBeenCalledWith(1, { cvss_score: 7.5, severity: 'High' })
    )
  })

  it('refuses a score outside 0 to 10 before sending it', async () => {
    const user = userEvent.setup()
    renderAs('admin')

    await user.click(await screen.findByRole('button', { name: 'Edit CVE-2024-3094' }))
    const score = screen.getByLabelText('CVSS score of CVE-2024-3094')
    await user.clear(score)
    await user.type(score, '11')

    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('lets an administrator delete a CVE once confirmed', async () => {
    vulnerabilityService.remove.mockResolvedValue({})
    const user = userEvent.setup()
    renderAs('admin')

    await user.click(await screen.findByRole('button', { name: 'Delete CVE-2024-3094' }))
    expect(vulnerabilityService.remove).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Confirm the deletion of CVE-2024-3094' }))

    await waitFor(() => expect(vulnerabilityService.remove).toHaveBeenCalledWith(1))
  })

  it('offers no edit to a remediator nor to a scoped account', async () => {
    const { unmount } = renderAs('remediator')
    expect(await screen.findByText('CVE-2024-3094')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit CVE-2024-3094' })).not.toBeInTheDocument()
    unmount()

    renderAs('analyst', ['Servers'])
    expect(await screen.findByText('CVE-2024-3094')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Edit CVE-2024-3094' })).not.toBeInTheDocument()
  })
})
