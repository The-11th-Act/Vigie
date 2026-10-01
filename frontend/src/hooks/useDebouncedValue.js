import { useEffect, useState } from 'react';

// `value`, once it has stopped changing for `delayMs`. Every search box used
// to keep its own timer (at first on `window`, shared by every list, then a
// copy of the same ref-and-effect in each screen); the timer now lives here,
// per component, and is cleared on unmount.
export function useDebouncedValue(value, delayMs = 300) {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);

  return debounced;
}
