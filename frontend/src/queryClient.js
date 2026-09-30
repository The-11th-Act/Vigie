import { QueryClient } from '@tanstack/react-query'

/**
 * Server data, cached per query key.
 *
 * staleTime stays at 0: a screen opened again shows what it last loaded at
 * once and refreshes it in the background, so it is never older than before
 * the cache existed. Keys start with their domain (["findings", ...],
 * ["dashboard", ...]) so that a change can invalidate every screen it makes
 * wrong in one call.
 */
export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        // Predictable load: data refreshes when a screen mounts or after a
        // change, not each time the browser tab regains focus.
        refetchOnWindowFocus: false,
        // One retry for a network blip or a 5xx; a 4xx is an answer (the
        // api client already handles 401), retrying it changes nothing.
        retry: (failures, error) => failures < 1 && !(error?.response?.status < 500),
      },
    },
  })
}
