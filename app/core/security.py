import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.tokens import is_revoked
from app.db.database import get_db
from app.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

# Values of the JWT "type" claim, not credentials.
ACCESS_TOKEN_TYPE = "access"  # noqa: S105
REFRESH_TOKEN_TYPE = "refresh"  # noqa: S105


def _encode(
    subject: str | Any,
    expires_delta: timedelta,
    token_type: str,
    extra_claims: dict | None = None,
) -> str:
    to_encode = {
        "exp": datetime.now(UTC) + expires_delta,
        "sub": str(subject),
        # A unique id per token is what makes revocation possible: without it,
        # a logged-out token stays usable until it expires.
        "jti": uuid.uuid4().hex,
        "type": token_type,
    }
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(
    subject: str | Any,
    expires_delta: timedelta | None = None,
    extra_claims: dict | None = None,
) -> str:
    return _encode(
        subject,
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        ACCESS_TOKEN_TYPE,
        extra_claims,
    )


def create_refresh_token(
    subject: str | Any,
    expires_delta: timedelta | None = None,
    extra_claims: dict | None = None,
) -> str:
    return _encode(
        subject,
        expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
        REFRESH_TOKEN_TYPE,
        extra_claims,
    )


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def _decode(token: str, expected_type: str) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
        # `from None`: never let the JWT library's reason (expired? bad
        # signature? wrong algorithm?) reach the caller — that is an oracle.
        raise credentials_exception from None

    if payload.get("sub") is None:
        raise credentials_exception

    # A refresh token must not pass as an access token: it lives far longer, so
    # accepting one here would silently extend session lifetime. Tokens minted
    # before typing existed carry no "type" and stay valid as access tokens
    # until they expire.
    if payload.get("type", ACCESS_TOKEN_TYPE) != expected_type:
        raise credentials_exception

    if is_revoked(payload.get("jti")):
        raise credentials_exception

    return payload


def decode_token(token: str = Depends(oauth2_scheme)) -> dict:
    return _decode(token, ACCESS_TOKEN_TYPE)


def decode_refresh_token(token: str) -> dict:
    return _decode(token, REFRESH_TOKEN_TYPE)


# Pre-computed hash of a throwaway password. Verifying against it costs the same
# as verifying a real one, so an unknown username and a wrong password take
# indistinguishable time — closing the user-enumeration side channel.
_DUMMY_HASH = pwd_context.hash("timing-attack-mitigation-placeholder")


def verify_password_constant_time(
    plain_password: str, hashed_password: str | None
) -> bool:
    """Verify a password, always doing the hashing work even for unknown users."""
    if hashed_password is None:
        pwd_context.verify(plain_password, _DUMMY_HASH)
        return False
    return pwd_context.verify(plain_password, hashed_password)


def require_admin(
    token_data: dict = Depends(decode_token), db: Session = Depends(get_db)
) -> dict:
    """Admit only a user who is an administrator *now*, according to the database.

    The role claim in the token is what the user was at login: trusting it
    meant a demoted or deleted administrator kept every admin right until the
    token expired. One primary-key lookup per admin request closes that window.
    """
    user_id = _user_id(token_data)
    user = db.get(User, user_id) if user_id is not None else None
    if user is None or user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return token_data


def _user_id(token_data: dict) -> int | None:
    try:
        return int(token_data["sub"])
    except (KeyError, TypeError, ValueError):
        return None
