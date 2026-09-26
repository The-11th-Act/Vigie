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


OLD_KEY = "old-signing-key-" + "o" * 40
NEW_KEY = "new-signing-key-" + "n" * 40


class TestKeyRotation:
    """Changing SECRET_KEY used to invalidate every token at once. Tokens now
    name their key ("kid"), and retired keys keep verifying their own tokens."""

    @pytest.fixture
    def rotated(self, monkeypatch):
        """Mint a token under the old key, then rotate to the new one."""
        monkeypatch.setattr(settings, "SECRET_KEY", OLD_KEY)
        monkeypatch.setattr(settings, "SECRET_KEY_ID", "k1")
        monkeypatch.setattr(settings, "PREVIOUS_SECRET_KEYS", {})
        old_token = create_access_token(subject=1)

        monkeypatch.setattr(settings, "SECRET_KEY", NEW_KEY)
        monkeypatch.setattr(settings, "SECRET_KEY_ID", "k2")
        monkeypatch.setattr(settings, "PREVIOUS_SECRET_KEYS", {"k1": OLD_KEY})
        return old_token

    def test_tokens_name_their_key(self):
        header = jwt.get_unverified_header(create_access_token(subject=1))
        assert header["kid"] == settings.SECRET_KEY_ID

    def test_new_tokens_use_the_new_key(self, rotated):
        token = create_access_token(subject=1)
        assert jwt.get_unverified_header(token)["kid"] == "k2"
        assert decode_token(token)["sub"] == "1"

    def test_a_token_from_the_retired_key_still_works(self, rotated):
        assert decode_token(rotated)["sub"] == "1"

    def test_retiring_the_key_ends_its_tokens(self, rotated, monkeypatch):
        monkeypatch.setattr(settings, "PREVIOUS_SECRET_KEYS", {})
        with pytest.raises(HTTPException) as exc:
            decode_token(rotated)
        assert exc.value.status_code == 401

    def test_an_unknown_kid_is_rejected(self, rotated):
        forged = jwt.encode(
            {"sub": "1", "exp": time.time() + 60, "type": "access"},
            NEW_KEY,
            algorithm=settings.ALGORITHM,
            headers={"kid": "k9"},
        )
        with pytest.raises(HTTPException):
            decode_token(forged)

    def test_a_kid_does_not_vouch_for_another_key(self, rotated):
        """The kid only picks the key: a token claiming the retired key but
        signed with something else still fails the signature check."""
        forged = jwt.encode(
            {"sub": "1", "exp": time.time() + 60, "type": "access"},
            "attacker-controlled-key-" + "a" * 40,
            algorithm=settings.ALGORITHM,
            headers={"kid": "k1"},
        )
        with pytest.raises(HTTPException):
            decode_token(forged)

    def test_a_malformed_kid_is_a_401_not_a_crash(self, rotated):
        """Forged by hand, as an attacker would: PyJWT refuses to mint it."""
        import base64
        import hashlib
        import hmac
        import json

        def b64(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

        header = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": ["k1"]}).encode())
        body = b64(json.dumps({"sub": "1", "exp": time.time() + 60}).encode())
        signature = hmac.new(
            NEW_KEY.encode(), f"{header}.{body}".encode(), hashlib.sha256
        )
        forged = f"{header}.{body}.{b64(signature.digest())}"

        with pytest.raises(HTTPException) as exc:
            decode_token(forged)
        assert exc.value.status_code == 401

    def test_a_token_minted_before_key_ids_is_still_accepted(self):
        legacy = jwt.encode(
            {"sub": "1", "exp": time.time() + 60, "type": "access"},
            settings.SECRET_KEY,
            algorithm=settings.ALGORITHM,
        )
        assert "kid" not in jwt.get_unverified_header(legacy)
        assert decode_token(legacy)["sub"] == "1"


class TestKeyConfiguration:
    def build(self, **overrides):
        from app.core.config import Settings

        values = {
            "SECRET_KEY": NEW_KEY,
            "SECRET_KEY_ID": "k2",
            "ENVIRONMENT": "production",
        }
        values.update(overrides)
        return Settings(_env_file=None, **values)

    def test_a_rotation_is_accepted(self):
        settings_ = self.build(PREVIOUS_SECRET_KEYS={"k1": OLD_KEY})
        assert settings_.PREVIOUS_SECRET_KEYS == {"k1": OLD_KEY}

    def test_the_new_id_must_differ_from_the_retired_ones(self):
        with pytest.raises(ValueError, match="new id"):
            self.build(PREVIOUS_SECRET_KEYS={"k2": OLD_KEY})

    def test_a_weak_retired_key_is_refused_in_production(self):
        """A retired key still verifies tokens: a weak one is as dangerous as a
        weak current key."""
        with pytest.raises(ValueError, match="weak"):
            self.build(PREVIOUS_SECRET_KEYS={"k1": "changeme"})
