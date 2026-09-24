import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    decode_token,
    get_password_hash,
    oauth2_scheme,
    verify_password_constant_time,
)
from app.core.tokens import revoke
from app.db.database import get_db
from app.models.user import User
from app.schemas.user import (
    RefreshRequest,
    Token,
    UserCreate,
    UserLogin,
    UserResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter()

INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Incorrect username or password",
    headers={"WWW-Authenticate": "Bearer"},
)


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = (
        db.query(User)
        .filter(or_(User.username == user_in.username, User.email == user_in.email))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered",
        )

    # The role is never taken from the request body: self-registration must not
    # be a path to admin. Elevating a user is an explicit admin operation.
    db_user = User(
        email=user_in.email,
        username=user_in.username,
        hashed_password=get_password_hash(user_in.password),
        role="analyst",
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@router.post("/login", response_model=Token)
def login(credentials: UserLogin, request: Request, db: Session = Depends(get_db)):
    client_ip = _client_ip(request)

    # Both scopes are checked: per-IP stops one host working through many
    # accounts, per-account stops a distributed attempt on a single one.
    for scope, identifier in (("ip", client_ip), ("user", credentials.username)):
        state = ratelimit.is_locked(scope, identifier)
        if state.locked:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Try again later.",
                headers={"Retry-After": str(state.retry_after)},
            )

    user = db.query(User).filter(User.username == credentials.username).first()

    # Always run the password verification, even when the user does not exist,
    # so response timing cannot be used to enumerate valid usernames.
    hashed = user.hashed_password if user else None
    if not verify_password_constant_time(credentials.password, hashed):
        ratelimit.register_failure("ip", client_ip)
        ratelimit.register_failure("user", credentials.username)
        logger.warning("Failed login for '%s' from %s", credentials.username, client_ip)
        raise INVALID_CREDENTIALS

    ratelimit.reset("ip", client_ip)
    ratelimit.reset("user", credentials.username)

    claims = {"role": user.role, "username": user.username}
    return Token(
        access_token=create_access_token(subject=user.id, extra_claims=claims),
        refresh_token=create_refresh_token(subject=user.id, extra_claims=claims),
        role=user.role,
        username=user.username,
    )


@router.post("/refresh", response_model=Token)
def refresh(body: RefreshRequest, db: Session = Depends(get_db)):
    """Exchange a refresh token for a new pair, rotating the refresh token.

    The presented token is revoked as part of the exchange, so a captured
    refresh token is single-use: replaying it once the legitimate client has
    refreshed will fail.
    """
    payload = decode_refresh_token(body.refresh_token)

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise INVALID_CREDENTIALS from exc

    user = db.get(User, user_id)
    if user is None:
        raise INVALID_CREDENTIALS

    revoke(payload.get("jti"), payload.get("exp"))

    claims = {"role": user.role, "username": user.username}
    return Token(
        access_token=create_access_token(subject=user.id, extra_claims=claims),
        refresh_token=create_refresh_token(subject=user.id, extra_claims=claims),
        role=user.role,
        username=user.username,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    body: RefreshRequest | None = None,
    token: str = Depends(oauth2_scheme),
    payload: dict = Depends(decode_token),
):
    """Revoke the current access token, and the refresh token when supplied.

    Without this there was no server-side logout at all: clearing the browser's
    storage left a token valid for its full remaining lifetime.
    """
    revoke(payload.get("jti"), payload.get("exp"))

    if body and body.refresh_token:
        try:
            refresh_payload = decode_refresh_token(body.refresh_token)
        except HTTPException:
            # An invalid or already-revoked refresh token is no reason to fail
            # a logout — the access token is revoked either way.
            pass
        else:
            revoke(refresh_payload.get("jti"), refresh_payload.get("exp"))


@router.get("/me", response_model=UserResponse)
def get_current_user_info(
    payload: dict = Depends(decode_token), db: Session = Depends(get_db)
):
    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError):
        # `from None` on purpose: the client must not learn how the subject was
        # malformed, and the traceback of a rejected token is noise.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token subject",
        ) from None

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
        )
    return user


def _client_ip(request: Request) -> str:
    """Best-effort client address.

    ``X-Forwarded-For`` is only meaningful behind a proxy that sets it. It is
    trusted here because the alternative — every request sharing the proxy's
    address — would let one attacker lock out every user at once.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
