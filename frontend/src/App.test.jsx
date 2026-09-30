import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import App from './App'
import { authService, dashboardService, meService } from './services'

// Screens only need to mount: their data never arrives.
const pending = () => new Promise(() => {})

vi.mock('./services', () => ({
  instanceService: { get: vi.fn(() => Promise.resolve({ data: { banner: null } })) },
  authService: { getMe: vi.fn(), login: vi.fn(), logout: vi.fn() },
  meService: { getModules: vi.fn(), updatePreferences: vi.fn() },
  dashboardService: { getStats: vi.fn(() => pending()), getTopRisks: vi.fn(() => pending()) },
  vulnerabilityService: {
    getFindings: vi.fn(() => pending()),
    list: vi.fn(() => pending()),
    updateFinding: vi.fn(),
    exportFindings: vi.fn(),
  },
  assetService: { list: vi.fn(() => pending()) },
  scanService: { list: vi.fn(() => pending()), upload: vi.fn(), getStatus: vi.fn() },
  adminService: { getModules: vi.fn(() => pending()) },
  userService: { list: vi.fn(() => pending()) },
}))

// Charts need a layout jsdom does not have (ResizeObserver): drawn as nothing.
vi.mock('recharts', () => {
  const Empty = () => null
  return Object.fromEntries(
    [
      'Bar',
      'BarChart',
      'CartesianGrid',
      'Cell',
      'Legend',
      'Line',
      'LineChart',
      'ResponsiveContainer',
      'Tooltip',
      'XAxis',
      'YAxis',
    ].map((name) => [name, Empty])
  )
})

function signedInWith(modules) {
  authService.getMe.mockResolvedValue({ data: { username: 'alice', role: 'remediator' } })
  meService.getModules.mockResolvedValue({ data: { role: 'remediator', modules } })
}

function renderAt(path) {
  window.history.pushState({}, '', path)
  return render(<App />)
}

async function sidebarLinks() {
  const nav = await screen.findByRole('navigation')
  return within(nav)
    .getAllByRole('link')
    .map((link) => link.textContent)
}

describe('App shell', () => {
  beforeEach(() => vi.clearAllMocks())

  it('builds the sidebar from the granted modules, in their order', async () => {
    signedInWith([
      { key: 'backlog', label: 'Risk Backlog', hidden: false },
      { key: 'dashboard', label: 'Dashboard', hidden: false },
      { key: 'assets', label: 'Assets', hidden: true },
      // A module this build does not know yet is ignored.
      { key: 'future', label: 'Future', hidden: false },
    ])
    renderAt('/')

    expect(await sidebarLinks()).toEqual(['Risk Backlog', 'Dashboard'])
  })

  it('opens on the first module of the sidebar', async () => {
    signedInWith([
      { key: 'backlog', label: 'Risk Backlog', hidden: false },
      { key: 'dashboard', label: 'Dashboard', hidden: false },
    ])
    renderAt('/')

    await sidebarLinks()
    // Navigate redirects in an effect, after the first render: wait for it.
    await waitFor(() => expect(window.location.pathname).toBe('/findings'))
  })

  it('sends a module the role lacks back home', async () => {
    signedInWith([{ key: 'dashboard', label: 'Dashboard', hidden: false }])
    renderAt('/scans')

    await sidebarLinks()
    // Navigate redirects in an effect, after the first render: wait for it.
    await waitFor(() => expect(window.location.pathname).toBe('/dashboard'))
  })

  it('keeps a hidden module reachable by its address', async () => {
    signedInWith([
      { key: 'dashboard', label: 'Dashboard', hidden: false },
      { key: 'backlog', label: 'Risk Backlog', hidden: true },
    ])
    renderAt('/findings')

    await sidebarLinks()
    // Navigate redirects in an effect, after the first render: wait for it.
    await waitFor(() => expect(window.location.pathname).toBe('/findings'))
  })

  it('lands on the preferences without any module', async () => {
    signedInWith([])
    renderAt('/')

    expect(await screen.findByText(/no module is available/i)).toBeInTheDocument()
    // Navigate redirects in an effect, after the first render: wait for it.
    await waitFor(() => expect(window.location.pathname).toBe('/preferences'))
  })

  it('still signs out from the sidebar', async () => {
    signedInWith([{ key: 'dashboard', label: 'Dashboard', hidden: false }])
    authService.logout.mockResolvedValue({})
    const user = userEvent.setup()
    renderAt('/')

    await sidebarLinks()
    await user.click(screen.getByRole('button', { name: /log out/i }))

    expect(authService.logout).toHaveBeenCalled()
    await waitFor(() => expect(window.location.pathname).toBe('/login'))
  })

  it('forgets what the previous session loaded when signing out', async () => {
    // Alice's dashboard, cached by TanStack Query while she is signed in. An
    // analyst: the dashboard opens on the posture figures.
    authService.getMe.mockResolvedValue({ data: { username: 'alice', role: 'analyst' } })
    meService.getModules.mockResolvedValue({
      data: { role: 'analyst', modules: [{ key: 'dashboard', label: 'Dashboard', hidden: false }] },
    })
    dashboardService.getStats.mockResolvedValueOnce({
      data: {
        total_assets: 777,
        total_open_vulnerabilities: 0,
        severity_breakdown: { Critical: 0, High: 0, Medium: 0, Low: 0 },
        overdue_count: 0,
        average_cvss: 0,
        kev_open_count: 0,
        kev_overdue_count: 0,
        threat_intel: { enabled: false, feeds: [] },
      },
    })
    authService.logout.mockResolvedValue({})
    const user = userEvent.setup()
    renderAt('/dashboard')
    expect(await screen.findByText('777')).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: /log out/i }))
    await waitFor(() => expect(window.location.pathname).toBe('/login'))

    // Bob signs in on the same browser; his figures are still on their way.
    authService.login.mockResolvedValue({ data: { username: 'bob', role: 'analyst' } })
    await user.type(screen.getByLabelText('Username'), 'bob')
    await user.type(screen.getByLabelText('Password'), 'secret')
    await user.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByText(/loading dashboard/i)).toBeInTheDocument()
    expect(screen.queryByText('777')).not.toBeInTheDocument()
  })

  it('says so when the modules cannot be loaded', async () => {
    authService.getMe.mockResolvedValue({ data: { username: 'alice', role: 'analyst' } })
    meService.getModules.mockRejectedValue({ message: 'Network Error' })
    renderAt('/')

    expect(await screen.findByText(/could not load your modules/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })
})
