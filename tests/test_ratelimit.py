import pytest

from app.core import ratelimit
from app.core.config import settings
from app.core.keyvalue import InMemoryStore, reset_store


@pytest.fixture(autouse=True)
def throttle_enabled(monkeypatch):
    """The suite disables throttling globally; turn it back on here."""
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    monkeypatch.setattr(settings, "LOGIN_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(settings, "LOGIN_WINDOW_SECONDS", 60)
    monkeypatch.setattr(settings, "LOGIN_LOCKOUT_SECONDS", 300)


class TestLoginThrottle:
    def test_below_threshold_stays_open(self):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            assert ratelimit.register_failure("ip", "10.0.0.1").locked is False
        assert ratelimit.is_locked("ip", "10.0.0.1").locked is False

    def test_locks_at_threshold(self):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            state = ratelimit.register_failure("ip", "10.0.0.2")
        assert state.locked is True
        assert ratelimit.is_locked("ip", "10.0.0.2").locked is True

    def test_lock_reports_the_lockout_delay(self):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            ratelimit.register_failure("user", "victim")

        state = ratelimit.is_locked("user", "victim")
        # The lock must outlast the counting window, not expire with it.
        assert state.retry_after > settings.LOGIN_WINDOW_SECONDS

    def test_success_clears_the_counter(self):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS - 1):
            ratelimit.register_failure("ip", "10.0.0.3")

        ratelimit.reset("ip", "10.0.0.3")

        assert ratelimit.register_failure("ip", "10.0.0.3").locked is False

    def test_scopes_are_independent(self):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            ratelimit.register_failure("ip", "10.0.0.4")

        assert ratelimit.is_locked("ip", "10.0.0.4").locked is True
        assert ratelimit.is_locked("user", "10.0.0.4").locked is False

    def test_identifiers_are_case_insensitive(self):
        for _ in range(settings.LOGIN_MAX_ATTEMPTS):
            ratelimit.register_failure("user", "Alice")

        assert ratelimit.is_locked("user", "alice").locked is True

    def test_disabled_throttle_never_locks(self, monkeypatch):
        monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
        for _ in range(settings.LOGIN_MAX_ATTEMPTS * 3):
            assert ratelimit.register_failure("ip", "10.0.0.5").locked is False
        assert ratelimit.is_locked("ip", "10.0.0.5").locked is False


class TestInMemoryStore:
    def test_counter_expires(self):
        store = InMemoryStore()
        reset_store(store)
        try:
            count, ttl = store.incr("k", 60)
            assert (count, ttl) == (1, 60)
            assert store.incr("k", 60)[0] == 2

            # Expire it by hand rather than sleeping.
            store.expire("k", 0)
            assert store.get_int("k") == 0
            assert store.incr("k", 60)[0] == 1
        finally:
            reset_store(None)

    def test_setex_and_exists(self):
        store = InMemoryStore()
        store.setex("token", 60)
        assert store.exists("token") is True

        store.delete("token")
        assert store.exists("token") is False
