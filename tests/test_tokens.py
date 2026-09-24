import time

import jwt
import pytest
from fastapi import HTTPException

from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    decode_token,
)
from app.core.tokens import is_revoked, revoke


def claims_of(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


class TestTokenClaims:
    def test_access_token_carries_a_unique_jti(self):
        first = claims_of(create_access_token(subject=1))
        second = claims_of(create_access_token(subject=1))

        assert first["jti"] != second["jti"]
        assert first["type"] == "access"

    def test_refresh_token_is_typed_and_longer_lived(self):
        access = claims_of(create_access_token(subject=1))
        refresh = claims_of(create_refresh_token(subject=1))

        assert refresh["type"] == "refresh"
        assert refresh["exp"] > access["exp"]


class TestTokenTypeSeparation:
    def test_refresh_token_is_not_accepted_as_an_access_token(self):
        """A refresh token lives for days; accepting it here would silently
        extend session lifetime well past the access token's hour."""
        refresh = create_refresh_token(subject=1)

        with pytest.raises(HTTPException) as exc:
            decode_token(refresh)
        assert exc.value.status_code == 401

    def test_access_token_is_not_accepted_as_a_refresh_token(self):
        access = create_access_token(subject=1)

        with pytest.raises(HTTPException) as exc:
            decode_refresh_token(access)
        assert exc.value.status_code == 401


class TestRevocation:
    def test_revoked_access_token_is_rejected(self):
        token = create_access_token(subject=1)
        payload = claims_of(token)

        assert decode_token(token)["sub"] == "1"

        revoke(payload["jti"], payload["exp"])

        with pytest.raises(HTTPException) as exc:
            decode_token(token)
        assert exc.value.status_code == 401

    def test_revoking_one_token_leaves_others_valid(self):
        revoked = create_access_token(subject=1)
        kept = create_access_token(subject=1)

        payload = claims_of(revoked)
        revoke(payload["jti"], payload["exp"])

        assert is_revoked(payload["jti"]) is True
        assert decode_token(kept)["sub"] == "1"

    def test_already_expired_token_is_not_stored(self):
        """No point holding an entry for a token signature validation already
        rejects — it would just grow the store."""
        revoke("expired-jti", int(time.time()) - 10)
        assert is_revoked("expired-jti") is False

    def test_token_without_jti_is_not_treated_as_revoked(self):
        """Tokens minted before revocation existed stay usable until expiry."""
        assert is_revoked(None) is False
