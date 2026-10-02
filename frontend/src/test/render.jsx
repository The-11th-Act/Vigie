/*
 * Testing Library with a fresh query client per render: screens read their
 * data through TanStack Query, and no cache may leak from one test to the
 * next. Import from here instead of '@testing-library/react'.
 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render as baseRender } from '@testing-library/react'

export * from '@testing-library/react'

export function createTestQueryClient() {
  return new QueryClient({
    // No retry: a mocked failure must show at once, not after a backoff.
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
}

export function render(ui, { queryClient, ...options } = {}) {
  const client = queryClient ?? createTestQueryClient()
  const Wrapper = ({ children }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  )
  return { queryClient: client, ...baseRender(ui, { wrapper: Wrapper, ...options }) }
}
