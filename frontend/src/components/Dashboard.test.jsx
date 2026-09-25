import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'

import Dashboard from './Dashboard'
import { dashboardService } from '../services'

vi.mock('../services', () => ({
  dashboardService: { getStats: vi.fn(), getTopRisks: vi.fn() },
}))

// Recharts measures its container, which jsdom cannot do; the chart is not
// what these tests are about.
vi.mock('recharts', () => {
  const Empty = () => null
  return {
    ResponsiveContainer: Empty,
    BarChart: Empty,
    Bar: Empty,
    XAxis: Empty,
    YAxis: Empty,
    Tooltip: Empty,
    Cell: Empty,
    CartesianGrid: Empty,
  }
})

const STATS = {
  total_assets: 12,
  total_open_vulnerabilities: 30,
  severity_breakdown: { Critical: 4, High: 6, Medium: 10, Low: 10 },
  overdue_count: 5,
  average_cvss: 6.4,
  kev_open_count: 3,
  kev_overdue_count: 2,
  threat_intel: {
    enabled: true,
    feeds: [
      { feed: 'kev', last_success_at: '2026-09-25T06:15:00Z', stale: false },
      { feed: 'epss', last_success_at: null, stale: true },
    ],
  },
}

describe('Dashboard — threat context', () => {
  it('shows the known-exploited findings and how many are late', async () => {
    dashboardService.getStats.mockResolvedValue({ data: STATS })
    dashboardService.getTopRisks.mockResolvedValue({ data: [] })
    render(<Dashboard />)

    expect(await screen.findByText('Known Exploited (KEV)')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('2 overdue')).toBeInTheDocument()
  })

  it('says when a feed was never loaded', async () => {
    dashboardService.getStats.mockResolvedValue({ data: STATS })
    dashboardService.getTopRisks.mockResolvedValue({ data: [] })
    render(<Dashboard />)

    expect(await screen.findByText(/FIRST EPSS: never loaded/)).toBeInTheDocument()
  })

  it('marks KEV entries among the top risks', async () => {
    dashboardService.getStats.mockResolvedValue({ data: STATS })
    dashboardService.getTopRisks.mockResolvedValue({
      data: [
        {
          finding_id: 1,
          asset_id: 1,
          hostname: 'edge-01',
          cve_id: 'CVE-2024-3400',
          title: 'PAN-OS',
          risk_score: 10,
          risk_level: 'Critical',
          in_kev: true,
        },
      ],
    })
    render(<Dashboard />)

    expect(await screen.findByText('KEV')).toBeInTheDocument()
  })
})
