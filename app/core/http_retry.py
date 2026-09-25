"""Retry pacing shared by the outbound HTTP clients.

Each client keeps its own request loop (CrowdStrike re-authenticates on a 401,
the threat feeds stream their body), but how long to wait before trying again
is the same question everywhere: honour the server when it says, back off
exponentially when it does not.
"""

import time

BACKOFF_BASE_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 30.0


def backoff_seconds(attempt: int) -> float:
    """Exponential delay before retry ``attempt`` (1-based), capped."""
    return min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))


def retry_after_seconds(response, attempt: int) -> float:
    """Honour the server's own pacing whenever it states one."""
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return min(BACKOFF_MAX_SECONDS, max(0.0, float(retry_after)))
        except ValueError:
            pass

    # Falcon's own variant carries an absolute epoch rather than a delay.
    epoch = response.headers.get("X-RateLimit-RetryAfter")
    if epoch:
        try:
            return min(BACKOFF_MAX_SECONDS, max(0.0, float(epoch) - time.time()))
        except ValueError:
            pass

    return backoff_seconds(attempt)
