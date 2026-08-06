from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.security import (
    create_access_token,
    decode_token,
    get_password_hash,
    verify_password_constant_time,
)
from app.db.database import get_db
from app.models.user import User
from app.schemas.user import Token, UserCreate, UserLogin, UserResponse

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
def login(credentials: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username).first()

    # Always run the password verification, even when the user does not exist,
    # so response timing cannot be used to enumerate valid usernames.
    hashed = user.hashed_password if user else None
    if not verify_password_constant_time(credentials.password, hashed):
        raise INVALID_CREDENTIALS

    access_token = create_access_token(
        subject=user.id,
        extra_claims={"role": user.role, "username": user.username},
    )
    return Token(access_token=access_token, role=user.role, username=user.username)


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
