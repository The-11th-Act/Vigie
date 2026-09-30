import { useQuery } from '@tanstack/react-query'

export function errorMessage(err) {
  return err?.response?.data?.detail || err?.message || 'An error occurred'
}

/**
 * A TanStack query in the shape the screens use: ``data`` (null until
 * loaded), ``loading`` (nothing to show yet), ``error`` (a message) and
 * ``refetch``.
 *
 * ``queryKey`` starts with the data's domain ("findings", "remediation"...):
 * invalidating that prefix refreshes every screen showing it. Everything the
 * request depends on (page, filters) belongs in the key.
 */
export function useApiQuery(queryKey, queryFn, options = {}) {
  const query = useQuery({ queryKey, queryFn, ...options })
  return {
    data: query.data ?? null,
    loading: query.isPending,
    error: query.error ? errorMessage(query.error) : null,
    refetch: query.refetch,
  }
}
