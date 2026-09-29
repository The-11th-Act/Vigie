import { describe, it, expect, vi, beforeAll } from 'vitest'
import { render, screen } from '@testing-library/react'

import DashboardTrends from './DashboardTrends'
import { dashboardService } from '../services'

// The other dashboard tests replace Recharts; this one mounts the real charts,
// so that a Recharts release no longer compatible with our React version
// fails here rather than in a browser.
vi.mock('../services', () => ({
  dashboardService: { getPerformance: vi.fn(), getTrends: vi.fn(), rebuildSnapshots: vi.fn() },
}))

beforeAll(() => {
  // jsdom measures nothing; Recharts only needs the observer to exist.
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
})

describe('charts', () => {
  it('mount with the real Recharts', async () => {
    dashboardService.getPerformance.mockResolvedValue({
      data: {
        days: 30, fixed: 1, sla_percent: 100, mttr_days: 2, risk_removed: 8,
        mttr_by_criticality: { Critical: 2, High: null, Medium: null, Low: null },
        new_findings: 1, open_now: 1, open_at_start: 1, open_risk_now: 8, open_risk_at_start: 8,
        team_names: [], teams: [],
      },
    })
    dashboardService.getTrends.mockResolvedValue({
      data: {
        days: 90,
        points: [
          { day: '2026-09-27', estimated: false, open_findings: 2, open_risk: 16, overdue: 0, new_findings: 1, fixed: 0 },
          { day: '2026-09-28', estimated: false, open_findings: 1, open_risk: 8, overdue: 0, new_findings: 0, fixed: 1 },
        ],
      },
    })
    const errors = vi.spyOn(console, 'error').mockImplementation(() => {})

    render(<DashboardTrends />)

    expect(await screen.findByText('Open backlog, day by day')).toBeInTheDocument()
    expect(await screen.findByText('New findings and fixes, per week')).toBeInTheDocument()
    // React reports render failures of child components through console.error.
    const failures = errors.mock.calls.filter(([message]) =>
      /error|invalid|not a function|cannot read/i.test(String(message))
        && !/width\(0\) and height\(0\)/.test(String(message))
    )
    expect(failures).toEqual([])
  })
})
