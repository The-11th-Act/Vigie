import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import Dashboard from './Dashboard'
import DashboardTrends, { weekly } from './DashboardTrends'
import { AuthContext } from '../auth/AuthContext'
import { dashboardService } from '../services'

vi.mock('../services', () => ({
  dashboardService: {
    getStats: vi.fn(() => new Promise(() => {})),
    getTopRisks: vi.fn(() => new Promise(() => {})),
    getPerformance: vi.fn(),
    getTrends: vi.fn(),
    rebuildSnapshots: vi.fn(),
  },
}))

// Recharts measures its container, which jsdom cannot do; the charts are not
// what these tests are about.
vi.mock('recharts', () => {
  const Empty = () => null
  return Object.fromEntries(
    ['ResponsiveContainer', 'BarChart', 'Bar', 'LineChart', 'Line', 'XAxis', 'YAxis', 'Tooltip', 'Legend', 'Cell', 'CartesianGrid']
      .map((name) => [name, Empty])
  )
})

const PERFORMANCE = {
  days: 30,
  fixed: 12,
  sla_percent: 75,
  mttr_days: 9.5,
  mttr_by_criticality: { Critical: 4, High: 8, Medium: null, Low: null },
  risk_removed: 88.5,
  new_findings: 20,
  open_now: 40,
  open_at_start: 50,
  open_risk_now: 300,
  open_risk_at_start: 320,
  team_names: ['Servers', 'Workplace'],
  teams: [
    {
      team: 'Servers', key: 'Servers', open: 30, overdue: 4, open_risk: 250, kev: 2,
      fixed: 10, sla_percent: 80, mttr_days: 8, active_tickets: 3, resolved_tickets: 5,
    },
  ],
}

function asRole(role, ui) {
  return <AuthContext.Provider value={{ user: { username: 'u', role } }}>{ui}</AuthContext.Provider>
}

describe('weekly', () => {
  it('groups days by the Monday of their week', () => {
    const points = [
      { day: '2026-09-21', new_findings: 1, fixed: 0 }, // Monday
      { day: '2026-09-27', new_findings: 2, fixed: 3 }, // Sunday, same week
      { day: '2026-09-28', new_findings: 0, fixed: 1 }, // next Monday
    ]
    expect(weekly(points)).toEqual([
      { week: '2026-09-21', new_findings: 3, fixed: 3 },
      { week: '2026-09-28', new_findings: 0, fixed: 1 },
    ])
  })
})

describe('DashboardTrends', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    dashboardService.getPerformance.mockResolvedValue({ data: PERFORMANCE })
    dashboardService.getTrends.mockResolvedValue({
      data: { days: 90, points: [{ day: '2026-09-28', estimated: true, open_findings: 40, open_risk: 300, overdue: 4, new_findings: 1, fixed: 2 }] },
    })
  })

  it('shows the performance of the period', async () => {
    render(asRole('analyst', <DashboardTrends />))

    expect(await screen.findByText('75 %')).toBeInTheDocument()
    expect(screen.getByText('9.5 d')).toBeInTheDocument()
    expect(screen.getByText('-10 since the start of the period')).toBeInTheDocument()
    expect(screen.getByText('3 / 5')).toBeInTheDocument()
    expect(await screen.findByText(/rebuilt from detection and fix dates/)).toBeInTheDocument()
  })

  it('narrows to a team', async () => {
    const user = userEvent.setup()
    render(asRole('analyst', <DashboardTrends />))

    await user.selectOptions(await screen.findByLabelText('Team'), 'Workplace')

    expect(dashboardService.getPerformance).toHaveBeenLastCalledWith({ days: 30, owner_team: 'Workplace' })
    expect(dashboardService.getTrends).toHaveBeenLastCalledWith({ days: 90, owner_team: 'Workplace' })
  })

  it('lets an administrator build the missing history', async () => {
    dashboardService.getTrends.mockResolvedValue({ data: { days: 90, points: [] } })
    dashboardService.rebuildSnapshots.mockResolvedValue({ data: { rebuilt: 89 } })
    const user = userEvent.setup()
    render(asRole('admin', <DashboardTrends />))

    await user.click(await screen.findByRole('button', { name: /build the history now/i }))

    expect(dashboardService.rebuildSnapshots).toHaveBeenCalled()
  })

  it('offers nobody else to', async () => {
    dashboardService.getTrends.mockResolvedValue({ data: { days: 90, points: [] } })
    render(asRole('analyst', <DashboardTrends />))

    expect(await screen.findByText(/no history yet/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /build the history/i })).not.toBeInTheDocument()
  })

  it('is where a remediation team lands', async () => {
    render(asRole('remediator', <Dashboard />))

    expect(await screen.findByRole('tab', { name: 'Trends & remediation' })).toHaveAttribute('aria-selected', 'true')
    expect(dashboardService.getPerformance).toHaveBeenCalled()
    expect(dashboardService.getStats).not.toHaveBeenCalled()
  })
})
