from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")


def create_access_token(
    subject: str | Any,
    expires_delta: timedelta | None = None,
    extra_claims: dict | None = None,
) -> str:
    expire = datetime.now(UTC) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode = {"exp": expire, "sub": str(subject)}
    if extra_claims:
        to_encode.update(extra_claims)
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def decode_token(token: str = Depends(oauth2_scheme)) -> dict:
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
    return payload


# Pre-computed hash of a throwaway password. Verifying against it costs the same
# as verifying a real one, so an unknown username and a wrong password take
# indistinguishable time — closing the user-enumeration side channel.
_DUMMY_HASH = pwd_context.hash("timing-attack-mitigation-placeholder")


def verify_password_constant_time(plain_password: str, hashed_password: str | None) -> bool:
    """Verify a password, always doing the hashing work even for unknown users."""
    if hashed_password is None:
        pwd_context.verify(plain_password, _DUMMY_HASH)
        return False
    return pwd_context.verify(plain_password, hashed_password)


def require_admin(token_data: dict = Depends(decode_token)) -> dict:
    if token_data.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return token_data