/*
 * `set-state-in-effect` guards against cascading renders from incidental state
 * writes. Marking a request as in flight the moment it starts is the one case
 * the rule cannot express: the loading flag *is* the effect's purpose, and the
 * alternative (an external store or a data-fetching library) is a far larger
 * change than this hook warrants.
 */
/* eslint-disable react-hooks/set-state-in-effect */
import { useState, useEffect, useCallback, useRef } from 'react'

/**
 * Run `fetchFn` on mount and whenever `deps` change.
 *
 * The function itself is kept in a ref rather than made a dependency: callers
 * pass an inline arrow, which is a new value on every render and would
 * otherwise refetch in a loop.
 */
export function useFetch(fetchFn, deps = []) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [reloadToken, setReloadToken] = useState(0)

  const fetchRef = useRef(fetchFn)

  // Kept in sync from an effect rather than assigned during render. Declared
  // before the fetching effect so the ref is already current when it runs.
  useEffect(() => {
    fetchRef.current = fetchFn
  })

  useEffect(() => {
    // Guards against a slow response from a superseded request landing after a
    // newer one and overwriting it — or against setting state after unmount.
    let cancelled = false

    setLoading(true)
    setError(null)

    fetchRef
      .current()
      .then((result) => {
        if (!cancelled) setData(result)
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err.response?.data?.detail || err.message || 'An error occurred')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
    // `deps` comes from the caller and is spread into a literal so the rule can
    // see an array; its contents cannot be verified statically from in here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, reloadToken])

  const refetch = useCallback(() => setReloadToken((token) => token + 1), [])

  return { data, loading, error, refetch }
}
