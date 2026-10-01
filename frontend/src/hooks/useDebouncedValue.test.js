import { describe, it, expect, vi, afterEach } from 'vitest'
import { act, renderHook } from '@testing-library/react'

import { useDebouncedValue } from './useDebouncedValue'

describe('useDebouncedValue', () => {
  afterEach(() => vi.useRealTimers())

  it('follows the value only once it has stopped changing', () => {
    vi.useFakeTimers()
    const { result, rerender } = renderHook(({ value }) => useDebouncedValue(value, 300), {
      initialProps: { value: '' },
    })

    rerender({ value: 'op' })
    act(() => vi.advanceTimersByTime(200))
    rerender({ value: 'openssl' })
    act(() => vi.advanceTimersByTime(200))
    // 400 ms since the first keystroke, but only 200 since the last one.
    expect(result.current).toBe('')

    act(() => vi.advanceTimersByTime(100))
    expect(result.current).toBe('openssl')
  })

  it('drops its pending timer on unmount', () => {
    vi.useFakeTimers()
    const { rerender, unmount } = renderHook(({ value }) => useDebouncedValue(value), {
      initialProps: { value: '' },
    })

    rerender({ value: 'kb' })
    unmount()
    expect(vi.getTimerCount()).toBe(0)
  })
})
