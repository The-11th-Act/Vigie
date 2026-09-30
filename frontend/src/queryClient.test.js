import { describe, it, expect } from 'vitest'
import { createQueryClient } from './queryClient'

const retry = createQueryClient().getDefaultOptions().queries.retry
const failure = (status) => (status ? { response: { status } } : { message: 'Network Error' })

describe('createQueryClient', () => {
  it('retries a network blip or a server error once', () => {
    expect(retry(0, failure())).toBe(true)
    expect(retry(0, failure(503))).toBe(true)
    expect(retry(1, failure(503))).toBe(false)
  })

  it('takes a 4xx as an answer', () => {
    for (const status of [400, 401, 403, 404, 422]) {
      expect(retry(0, failure(status))).toBe(false)
    }
  })
})
