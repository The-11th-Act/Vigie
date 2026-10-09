"""Accounts, managed by administrators: self-registration is closed."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_or_404
from app.core import api_tokens
from app.core.modules import ROLE_ADMIN
from app.core.scope import team_value
from app.core.security import end_sessions, get_password_hash, require_admin
from app.db.database import get_db
from app.models.user import User, UserTeam
from app.schemas.user import (
    PasswordReset,
    UserActiveUpdate,
    UserAdminCreate,
    UserResponse,
    UserRoleUpdate,
    UserTeamsUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _admin_id(token_data: dict) -> int | None:
    try:
        return int(token_data["sub"])
    except (KeyError, TypeError, ValueError):
        return None


def _refuse_losing_the_last_admin(db: Session, user: User, what: str) -> None:
    """Nobody could administer Vigie again, short of the bootstrap script."""
    if user.role != ROLE_ADMIN or not user.is_active:
        return
    others = db.query(User).filter(
        User.role == ROLE_ADMIN, User.is_active.is_(True), User.id != user.id
    )
    if others.count() == 0:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The last active administrator cannot be {what}",
        )


def _refuse_self(admin: dict, user: User, what: str) -> None:
    if _admin_id(admin) == user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"An administrator cannot {what} their own account",
        )


def _set_teams(user: User, teams: list[str]) -> None:
    wanted = {team_value(team.strip()) for team in teams}
    # Changed in place: rows re-created with the same key would clash with
    # the ones being removed in the same flush.
    for row in list(user.team_rows):
        if row.owner_team not in wanted:
            user.team_rows.remove(row)
    kept = {row.owner_team for row in user.team_rows}
    user.team_rows.extend(UserTeam(owner_team=team) for team in sorted(wanted - kept))


@router.get("/", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    """Every account, its role and its scope, for the administration screen."""
    return (
        db.query(User).options(selectinload(User.team_rows)).order_by(User.username).all()
    )


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    user_in: UserAdminCreate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Open an account, with its role and scope, and an initial password the
    administrator hands over (the user can change it in Preferences)."""
    if user_in.role == ROLE_ADMIN and user_in.teams:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="An administrator sees the whole estate and cannot be scoped",
        )
    taken = (
        db.query(User)
        .filter(
            or_(
                User.username == user_in.username,
                func.lower(User.email) == user_in.email.lower(),
            )
        )
        .first()
    )
    if taken:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This username or email is already used",
        )
    user = User(
        email=user_in.email,
        username=user_in.username,
        hashed_password=get_password_hash(user_in.password),
        role=user_in.role,
    )
    _set_teams(user, user_in.teams)
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Account '%s' (%s) created by an administrator", user.username, user.role)
    return user


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_in: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    user = get_or_404(db, User, user_id)
    if role_in.role != ROLE_ADMIN:
        _refuse_losing_the_last_admin(db, user, "demoted")
    if role_in.role == ROLE_ADMIN:
        # An administrator is never scoped: teams kept here would silently come
        # back into force on a later demotion.
        user.team_rows.clear()
    user.role = role_in.role
    db.commit()
    db.refresh(user)
    return user


@router.put("/{user_id}/teams", response_model=UserResponse)
def update_user_teams(
    user_id: int,
    teams_in: UserTeamsUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Set the teams whose hosts the user sees, everywhere in Vigie.

    An empty list gives back the whole estate. "__none__" stands for hosts
    without a team. A team need not own a host yet: a scope can be prepared
    before the ownership rules assign it any.
    """
    user = get_or_404(db, User, user_id)
    if user.role == ROLE_ADMIN and teams_in.teams:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="An administrator sees the whole estate and cannot be scoped",
        )
    _set_teams(user, teams_in.teams)
    db.commit()
    db.refresh(user)
    return user


@router.patch("/{user_id}/active", response_model=UserResponse)
def set_user_active(
    user_id: int,
    active_in: UserActiveUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Disable an account (someone leaving), or enable it again.

    Disabled, it signs in nowhere and its open sessions and personal API
    tokens stop at their next request; its history stays.
    """
    user = get_or_404(db, User, user_id)
    if not active_in.active and user.is_active:
        _refuse_self(admin, user, "disable")
        _refuse_losing_the_last_admin(db, user, "disabled")
        end_sessions(user)
    user.is_active = active_in.active
    db.commit()
    db.refresh(user)
    logger.info(
        "Account '%s' %s", user.username, "enabled" if user.is_active else "disabled"
    )
    return user


@router.put("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
def reset_user_password(
    user_id: int,
    password_in: PasswordReset,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Set a new password for a user who lost theirs, or whose account was
    compromised: their sessions end and their personal API tokens are revoked."""
    user = get_or_404(db, User, user_id)
    user.hashed_password = get_password_hash(password_in.password)
    end_sessions(user)
    revoked = api_tokens.revoke_all(db, user)
    db.commit()
    logger.info(
        "Password of '%s' reset by an administrator; %d personal API token(s) revoked",
        user.username,
        revoked,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Remove an account for good. Its preferences, saved extracts and personal
    tokens go with it; the histories keep its name, the scans and tickets it
    created keep no link to it. Disabling keeps everything instead."""
    user = get_or_404(db, User, user_id)
    _refuse_self(admin, user, "delete")
    _refuse_losing_the_last_admin(db, user, "deleted")
    username = user.username
    db.delete(user)
    db.commit()
    logger.info("Account '%s' deleted by an administrator", username)
