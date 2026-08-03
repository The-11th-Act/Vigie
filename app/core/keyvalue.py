"""Small key-value store used for login throttling and token revocation.

Backed by Redis, which is already a hard dependency of the platform. When Redis
is unreachable the store degrades to a process-local dictionary so the API keeps
serving instead of failing closed — and so the test suite runs without a broker.

That fallback is deliberately limited: it is not shared between processes, so a
multi-worker deployment with Redis down enforces limits per worker rather than
globally. Redis is the supported production path; the fallback exists to avoid
turning a cache outage into an outright outage.
"""
import logging
import threading
import time
from abc import ABC, abstractmethod
from typing import Optional, Tuple

import redis

from app.core.config import settings

logger = logging.getLogger(__name__)


class KeyValueStore(ABC):
    @abstractmethod
    def incr(self, key: str, window_seconds: int) -> Tuple[int, int]:
        """Increment a counter, creating it with ``window_seconds`` TTL.

        Returns ``(count, ttl_seconds)`` after the increment.
        """

    @abstractmethod
    def expire(self, key: str, seconds: int) -> None:
        """Reset a key's TTL."""

    @abstractmethod
    def ttl(self, key: str) -> int:
        """Remaining TTL in seconds, or 0 when the key is absent/expired."""

    @abstractmethod
    def get_int(self, key: str) -> int:
        """Current counter value, 0 when absent."""

    @abstractmethod
    def setex(self, key: str, seconds: int, value: str = "1") -> None:
        """Store a value with an expiry."""

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def delete(self, key: str) -> None: ...


class InMemoryStore(KeyValueStore):
    """Process-local fallback. Thread-safe, not shared across workers."""

    def __init__(self) -> None:
        self._entries: dict[str, Tuple[str, float]] = {}
        self._lock = threading.Lock()

    def _live(self, key: str) -> Optional[Tuple[str, float]]:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry[1] <= time.monotonic():
            self._entries.pop(key, None)
            return None
        return entry

    def incr(self, key: str, window_seconds: int) -> Tuple[int, int]:
        with self._lock:
            entry = self._live(key)
            if entry is None:
                expires_at = time.monotonic() + window_seconds
                self._entries[key] = ("1", expires_at)
                return 1, window_seconds
            count = int(entry[0]) + 1
            self._entries[key] = (str(count), entry[1])
            return count, max(0, int(entry[1] - time.monotonic()))

    def expire(self, key: str, seconds: int) -> None:
        with self._lock:
            entry = self._live(key)
            if entry is not None:
                self._entries[key] = (entry[0], time.monotonic() + seconds)

    def ttl(self, key: str) -> int:
        with self._lock:
            entry = self._live(key)
            return 0 if entry is None else max(0, int(entry[1] - time.monotonic()))

    def get_int(self, key: str) -> int:
        with self._lock:
            entry = self._live(key)
            return 0 if entry is None else int(entry[0])

    def setex(self, key: str, seconds: int, value: str = "1") -> None:
        with self._lock:
            self._entries[key] = (value, time.monotonic() + seconds)

    def exists(self, key: str) -> bool:
        with self._lock:
            return self._live(key) is not None

    def delete(self, key: str) -> None:
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


class RedisStore(KeyValueStore):
    def __init__(self, client: "redis.Redis") -> None:
        self._client = client

    def incr(self, key: str, window_seconds: int) -> Tuple[int, int]:
        pipe = self._client.pipeline()
        pipe.incr(key)
        pipe.ttl(key)
        count, ttl = pipe.execute()
        if ttl is None or ttl < 0:
            # First hit (or a key left without expiry): start the window now.
            self._client.expire(key, window_seconds)
            ttl = window_seconds
        return int(count), int(ttl)

    def expire(self, key: str, seconds: int) -> None:
        self._client.expire(key, seconds)

    def ttl(self, key: str) -> int:
        ttl = self._client.ttl(key)
        return int(ttl) if ttl and ttl > 0 else 0

    def get_int(self, key: str) -> int:
        raw = self._client.get(key)
        try:
            return int(raw) if raw is not None else 0
        except (TypeError, ValueError):
            return 0

    def setex(self, key: str, seconds: int, value: str = "1") -> None:
        self._client.setex(key, seconds, value)

    def exists(self, key: str) -> bool:
        return bool(self._client.exists(key))

    def delete(self, key: str) -> None:
        self._client.delete(key)


_store: Optional[KeyValueStore] = None
_store_lock = threading.Lock()


def get_store() -> KeyValueStore:
    """Return the shared store, preferring Redis and falling back to memory."""
    global _store
    if _store is not None:
        return _store

    with _store_lock:
        if _store is not None:
            return _store
        try:
            client = redis.Redis.from_url(
                settings.REDIS_URL,
                socket_connect_timeout=1,
                socket_timeout=1,
                decode_responses=True,
            )
            client.ping()
            _store = RedisStore(client)
            logger.info("Key-value store: Redis at %s", settings.REDIS_URL)
        except Exception as exc:
            logger.warning(
                "Redis unavailable (%s); falling back to a process-local store. "
                "Rate limits and token revocation will not be shared between workers.",
                exc,
            )
            _store = InMemoryStore()
        return _store


def reset_store(store: Optional[KeyValueStore] = None) -> None:
    """Replace the shared store. Intended for tests."""
    global _store
    with _store_lock:
        _store = store
