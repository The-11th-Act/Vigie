"""Personal access tokens: read-only API access for scripts and reporting tools.

A token is ``vigie_pat_`` followed by 43 random URL-safe characters. Only its
SHA-256 is stored; the secret is shown once. It authenticates as its owner, as
the database knows them at the time of the request (role, modules), and only
for reading: a leaked token can export data, never change it.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import HTTPException, Request, status
from sqlalchemy.orm import Session

from app.models.extract import ApiToken
from app.models.user import User

TOKEN_PREFIX = "vigie_pat_"  # noqa: S105 - a marker, not a credential
READ_SCOPE = "read"
# The module a token belongs to: switching it off, or taking it from a role,
# stops that role's tokens at once.
TOKENS_MODULE = "extracts"
MAX_TOKENS_PER_USER = 20
# Writing last_used_at on every request would turn each read into a write.
LAST_USED_RESOLUTION = timedelta(minutes=5)
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def is_api_token(bearer: str) -> bool:
    return bearer.startswith(TOKEN_PREFIX)


def hash_token(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def new_token(
    db: Session, user: User, name: str, lifetime: timedelta
) -> tuple[ApiToken, str]:
    """Create a token; the returned secret is never stored nor shown again."""
    secret = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token = ApiToken(
        user_id=user.id,
        name=name,
        prefix=secret[: len(TOKEN_PREFIX) + 4],
        token_hash=hash_token(secret),
        scope=READ_SCOPE,
        expires_at=datetime.now(UTC) + lifetime,
    )
    db.add(token)
    db.flush()
    return token, secret


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def authenticate(request: Request, secret: str, db: Session) -> dict:
    """The claims of a valid token, shaped like an access token's."""
    denied = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = db.query(ApiToken).filter(ApiToken.token_hash == hash_token(secret)).first()
    now = datetime.now(UTC)
    if token is None or token.revoked_at is not None or _aware(token.expires_at) <= now:
        raise denied
    user = db.get(User, token.user_id)
    if user is None:
        raise denied

    if request.method not in SAFE_METHODS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Personal API tokens are read-only",
        )

    # Imported here: modules builds on security, which calls this module.
    from app.core.modules import module_access

    if TOKENS_MODULE not in module_access(db, user).allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API tokens are not available to your role",
        )

    if (
        token.last_used_at is None
        or now - _aware(token.last_used_at) > LAST_USED_RESOLUTION
    ):
        token.last_used_at = now
        # Safe to commit: nothing else is pending on a read-only request yet.
        db.commit()

    return {
        "sub": str(user.id),
        "role": user.role,
        "username": user.username,
        "type": "api_token",
        "token_id": token.id,
    }
