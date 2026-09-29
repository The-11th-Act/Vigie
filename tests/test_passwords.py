"""Password hashing, with bcrypt used directly (passlib is gone)."""

import pytest

from app.core.security import (
    get_password_hash,
    verify_password,
    verify_password_constant_time,
)

# Written by passlib 1.7.4 with bcrypt 4.0.1, as stored before the switch.
PASSLIB_HASH = "$2b$12$9/fpO9FM.ePM83SHIC170u1H4VsaNKKVcibYNQnip6C2Fxii7fgtO"
PASSLIB_PASSWORD = "adminpass123456"


def test_a_hash_verifies():
    hashed = get_password_hash("Correct-horse-42")
    assert hashed.startswith("$2b$")
    assert verify_password("Correct-horse-42", hashed)
    assert not verify_password("correct-horse-42", hashed)


def test_hashes_written_by_passlib_still_verify():
    """Existing accounts must keep working after the switch."""
    assert verify_password(PASSLIB_PASSWORD, PASSLIB_HASH)
    assert not verify_password("wrong-password-1", PASSLIB_HASH)


def test_a_password_over_72_bytes_is_refused_not_an_error():
    """bcrypt 5 raises on it; at login it is simply a wrong password."""
    hashed = get_password_hash("a" * 72)
    assert not verify_password("a" * 73, hashed)
    assert not verify_password_constant_time("é" * 40, None)
    with pytest.raises(ValueError):
        get_password_hash("a" * 73)


def test_a_malformed_stored_hash_matches_nothing():
    assert not verify_password("anything-1", "not-a-bcrypt-hash")
