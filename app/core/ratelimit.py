"""Login throttling.

The login endpoint is unauthenticated by definition, so without a limit it is a
free brute-force oracle — the constant-time password check in
``app.core.security`` closes the timing side channel but does nothing about
volume. Failures are counted per source IP *and* per account: the first stops
one host hammering many accounts, the second stops a distributed attempt
against a single account.
"""

import logging
from dataclasses import dataclass

from app.core.config import settings
from app.core.keyvalue import get_store

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ThrottleState:
    locked: bool
    retry_after: int = 0


def _key(scope: str, identifier: str) -> str:
    return f"login:fail:{scope}:{identifier.lower()}"


def is_locked(scope: str, identifier: str) -> ThrottleState:
    """Whether this scope is currently locked out, without counting a hit."""
    if not settings.RATE_LIMIT_ENABLED:
        return ThrottleState(locked=False)

    key = _key(scope, identifier)
    store = get_store()
    if store.get_int(key) < settings.LOGIN_MAX_ATTEMPTS:
        return ThrottleState(locked=False)

    return ThrottleState(locked=True, retry_after=max(1, store.ttl(key)))


def register_failure(scope: str, identifier: str) -> ThrottleState:
    """Count a failed attempt and lock the scope once the threshold is hit."""
    if not settings.RATE_LIMIT_ENABLED:
        return ThrottleState(locked=False)

    key = _key(scope, identifier)
    store = get_store()
    count, ttl = store.incr(key, settings.LOGIN_WINDOW_SECONDS)

    if count < settings.LOGIN_MAX_ATTEMPTS:
        return ThrottleState(locked=False)

    # Threshold reached: hold the lock for the (longer) lockout period rather
    # than letting it lapse at the end of the counting window.
    if count == settings.LOGIN_MAX_ATTEMPTS:
        store.expire(key, settings.LOGIN_LOCKOUT_SECONDS)
        ttl = settings.LOGIN_LOCKOUT_SECONDS
        logger.warning(
            "Login lockout triggered for %s '%s' after %d failed attempts",
            scope,
            identifier,
            count,
        )

    return ThrottleState(locked=True, retry_after=max(1, ttl))


def reset(scope: str, identifier: str) -> None:
    """Clear the counter — called after a successful authentication."""
    if not settings.RATE_LIMIT_ENABLED:
        return
    get_store().delete(_key(scope, identifier))
