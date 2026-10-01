import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '../test/render'
import userEvent from '@testing-library/user-event'

import AdminWebhooks from './AdminWebhooks'
import { webhookService } from '../services'

vi.mock('../services', () => ({
  webhookService: {
    list: vi.fn(),
    events: vi.fn(),
    create: vi.fn(),
    update: vi.fn(),
    remove: vi.fn(),
    rotateSecret: vi.fn(),
    ping: vi.fn(),
    deliveries: vi.fn(),
    retryDelivery: vi.fn(),
  },
}))

const EVENTS = [
  { name: 'scan.completed', description: 'A scan was ingested' },
  { name: 'ticket.status_changed', description: 'A ticket changed status' },
]

const WEBHOOK = {
  id: 4,
  name: 'SOC',
  url: 'https://hooks.example.com/vigie',
  events: ['ticket.status_changed'],
  enabled: true,
  usable: true,
  last_success_at: null,
  last_failure_at: null,
  last_error: null,
  pending: 0,
  failed: 1,
}

function listed(webhooks = [WEBHOOK]) {
  webhookService.list.mockResolvedValue({ data: webhooks })
  webhookService.events.mockResolvedValue({ data: EVENTS })
}

describe('AdminWebhooks', () => {
  beforeEach(() => vi.clearAllMocks())

  it('registers a webhook and shows its secret once', async () => {
    listed([])
    webhookService.create.mockResolvedValue({ data: { ...WEBHOOK, secret: 'whsec_abc' } })
    const user = userEvent.setup()
    render(<AdminWebhooks />)

    const add = await screen.findByRole('button', { name: 'Add webhook' })
    expect(add).toBeDisabled()
    await user.type(screen.getByLabelText('Webhook name'), 'SOC')
    await user.type(screen.getByLabelText('Webhook URL'), 'https://hooks.example.com/vigie')
    await user.click(screen.getByRole('checkbox', { name: /ticket\.status_changed/ }))
    await user.click(add)

    expect(webhookService.create).toHaveBeenCalledWith({
      name: 'SOC',
      url: 'https://hooks.example.com/vigie',
      events: ['ticket.status_changed'],
    })
    expect(await screen.findByTestId('webhook-secret')).toHaveTextContent('whsec_abc')
    await user.click(screen.getByRole('button', { name: 'Done' }))
    expect(screen.queryByTestId('webhook-secret')).not.toBeInTheDocument()
  })

  it('says why the API refused it', async () => {
    listed([])
    webhookService.create.mockRejectedValue({
      response: { data: { detail: [{ msg: 'Value error, The URL must use https' }] } },
    })
    const user = userEvent.setup()
    render(<AdminWebhooks />)

    await user.type(await screen.findByLabelText('Webhook name'), 'SOC')
    await user.type(screen.getByLabelText('Webhook URL'), 'http://hooks.example.com')
    await user.click(screen.getByRole('checkbox', { name: /scan\.completed/ }))
    await user.click(screen.getByRole('button', { name: 'Add webhook' }))

    expect(await screen.findByText(/must use https/)).toBeInTheDocument()
  })

  it('keeps a webhook of another instance inert until adopted', async () => {
    listed([{ ...WEBHOOK, usable: false }])
    webhookService.rotateSecret.mockResolvedValue({ data: { ...WEBHOOK, secret: 'whsec_new' } })
    const user = userEvent.setup()
    render(<AdminWebhooks />)

    expect(await screen.findByText('Other instance')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Send a test event to SOC' })).toBeDisabled()
    expect(screen.queryByRole('button', { name: 'Disable' })).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Use here (new secret)' }))

    expect(webhookService.rotateSecret).toHaveBeenCalledWith(4)
    expect(await screen.findByTestId('webhook-secret')).toHaveTextContent('whsec_new')
  })

  it('sends an abandoned delivery again', async () => {
    listed()
    webhookService.deliveries.mockResolvedValue({
      data: [
        {
          id: 9,
          event: 'ticket.status_changed',
          status: 'failed',
          attempts: 7,
          response_status: 503,
          last_error: 'HTTP 503',
          created_at: '2026-10-01T08:00:00Z',
          next_attempt_at: null,
        },
      ],
    })
    webhookService.retryDelivery.mockResolvedValue({ data: {} })
    const user = userEvent.setup()
    render(<AdminWebhooks />)

    await user.click(await screen.findByRole('button', { name: 'Deliveries of SOC' }))
    await user.click(await screen.findByRole('button', { name: 'Send again' }))

    expect(webhookService.retryDelivery).toHaveBeenCalledWith(4, 9)
  })

  it('asks twice before deleting', async () => {
    listed()
    webhookService.remove.mockResolvedValue({})
    const user = userEvent.setup()
    render(<AdminWebhooks />)

    await user.click(await screen.findByRole('button', { name: 'Delete SOC' }))
    expect(webhookService.remove).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Confirm delete' }))

    await waitFor(() => expect(webhookService.remove).toHaveBeenCalledWith(4))
  })
})
