"""Token revocation list.

JWTs are self-validating, so a stolen or logged-out token stays usable until it
expires unless something records that it was revoked. Each token carries a
``jti``; logging out (or rotating a refresh token) stores that id until the
token's own expiry, after which the entry is pointless and Redis drops it.
"""

import logging
import time
from typing import Optional

from app.core.keyvalue import get_store

logger = logging.getLogger(__name__)

_PREFIX = "token:revoked:"


def revoke(jti: str, expires_at: Optional[int]) -> None:
    """Revoke a token id until the moment the token would have expired anyway.

    ``expires_at`` is the JWT ``exp`` claim (epoch seconds). An already-expired
    token needs no entry: it is rejected by signature validation.
    """
    if not jti:
        return

    ttl = int(expires_at - time.time()) if expires_at else 0
    if ttl <= 0:
        return

    get_store().setex(f"{_PREFIX}{jti}", ttl)


def is_revoked(jti: Optional[str]) -> bool:
    if not jti:
        # Tokens issued before revocation existed carry no jti; they remain
        # valid until they expire rather than being rejected wholesale.
        return False
    return get_store().exists(f"{_PREFIX}{jti}")
