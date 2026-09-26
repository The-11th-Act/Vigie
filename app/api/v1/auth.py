import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.config import settings
from app.core.security import (
    ACCESS_COOKIE,
    CSRF_COOKIE,
    REFRESH_COOKIE,
    SESSION_MODE_HEADER,
    create_access_token,
    create_refresh_token,
    decode_refresh_token,
    decode_token,
    get_password_hash,
    new_csrf_token,
    require_csrf,
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


@router.post("/login", response_model=Token, response_model_exclude_none=True)
def login(
    credentials: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
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

    return _issue_tokens(user, response, cookie_mode=_wants_cookies(request))


@router.post("/refresh", response_model=Token, response_model_exclude_none=True)
def refresh(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    db: Session = Depends(get_db),
):
    """Exchange a refresh token for a new pair, rotating the refresh token.

    The presented token is revoked as part of the exchange, so a captured
    refresh token is single-use: replaying it once the legitimate client has
    refreshed will fail. A browser session sends it as a cookie, and gets the
    new pair back as cookies.
    """
    from_cookie = body is None
    if from_cookie:
        presented = request.cookies.get(REFRESH_COOKIE)
        if not presented:
            raise INVALID_CREDENTIALS
        require_csrf(request)
    else:
        presented = body.refresh_token
    payload = decode_refresh_token(presented)

    try:
        user_id = int(payload["sub"])
    except (KeyError, TypeError, ValueError) as exc:
        raise INVALID_CREDENTIALS from exc

    user = db.get(User, user_id)
    if user is None:
        raise INVALID_CREDENTIALS

    revoke(payload.get("jti"), payload.get("exp"))

    return _issue_tokens(
        user, response, cookie_mode=from_cookie or _wants_cookies(request)
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    payload: dict = Depends(decode_token),
):
    """Revoke the current access token, and the refresh token when supplied.

    Without this there was no server-side logout at all: clearing the browser's
    storage left a token valid for its full remaining lifetime. A browser
    session's refresh token comes from its cookie, and the cookies are cleared.
    """
    revoke(payload.get("jti"), payload.get("exp"))

    refresh_token = body.refresh_token if body else request.cookies.get(REFRESH_COOKIE)
    if refresh_token:
        try:
            refresh_payload = decode_refresh_token(refresh_token)
        except HTTPException:
            # An invalid or already-revoked refresh token is no reason to fail
            # a logout — the access token is revoked either way.
            pass
        else:
            revoke(refresh_payload.get("jti"), refresh_payload.get("exp"))

    _clear_session_cookies(response)


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


def _wants_cookies(request: Request) -> bool:
    return request.headers.get(SESSION_MODE_HEADER, "").strip().lower() == "cookie"


def _issue_tokens(user: User, response: Response, *, cookie_mode: bool) -> Token:
    """A new token pair: in the body for API clients, in cookies for browsers.

    In cookie mode the tokens are left out of the body on purpose: a script
    injected into the page could read the body, never an HttpOnly cookie.
    """
    claims = {"role": user.role, "username": user.username}
    access = create_access_token(subject=user.id, extra_claims=claims)
    refresh = create_refresh_token(subject=user.id, extra_claims=claims)

    if not cookie_mode:
        return Token(
            access_token=access,
            refresh_token=refresh,
            role=user.role,
            username=user.username,
        )

    secure = settings.auth_cookie_secure
    access_age = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    refresh_age = settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400
    response.set_cookie(
        ACCESS_COOKIE,
        access,
        max_age=access_age,
        path=settings.API_V1_STR,
        httponly=True,
        secure=secure,
        samesite="strict",
    )
    # Scoped to the auth routes: the long-lived token is never sent with an
    # ordinary API call.
    response.set_cookie(
        REFRESH_COOKIE,
        refresh,
        max_age=refresh_age,
        path=f"{settings.API_V1_STR}/auth",
        httponly=True,
        secure=secure,
        samesite="strict",
    )
    # Readable by the page, which copies it into the X-CSRF-Token header.
    response.set_cookie(  # noqa: S604 - httponly=False is the point of this cookie
        CSRF_COOKIE,
        new_csrf_token(),
        max_age=refresh_age,
        path="/",
        httponly=False,
        secure=secure,
        samesite="strict",
    )
    return Token(role=user.role, username=user.username)


def _clear_session_cookies(response: Response) -> None:
    secure = settings.auth_cookie_secure
    response.delete_cookie(
        ACCESS_COOKIE,
        path=settings.API_V1_STR,
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        REFRESH_COOKIE,
        path=f"{settings.API_V1_STR}/auth",
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, samesite="strict")


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
