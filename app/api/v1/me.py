import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.modules import MODULES_BY_KEY, current_user, module_access
from app.core.scope import api_team, scope_of
from app.core.security import (
    end_sessions,
    get_password_hash,
    verify_password_constant_time,
)
from app.db.database import get_db
from app.models.preferences import UserPreference
from app.models.user import User
from app.schemas.modules import ModuleEntry, MyModulesResponse, PreferencesUpdate
from app.schemas.user import PasswordChange

logger = logging.getLogger(__name__)

router = APIRouter()


def _my_modules(db: Session, user: User) -> MyModulesResponse:
    access = module_access(db, user)
    scope = scope_of(db, user)
    return MyModulesResponse(
        role=user.role,
        teams=(
            sorted(api_team(team) for team in scope.teams)
            if scope.teams is not None
            else None
        ),
        modules=[
            ModuleEntry(
                key=key, label=MODULES_BY_KEY[key].label, hidden=key in access.hidden
            )
            for key in access.allowed
        ],
    )


@router.get("/modules", response_model=MyModulesResponse)
def get_my_modules(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """What the sidebar shows: the modules this user may use, in their order."""
    return _my_modules(db, user)


@router.put("/preferences", response_model=MyModulesResponse)
def update_my_preferences(
    preferences_in: PreferencesUpdate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Arrange the sidebar. Naming a module the role does not grant is not an
    error, and grants nothing: it only takes effect if the role gets it later."""
    preference = db.get(UserPreference, user.id)
    if preference is None:
        preference = UserPreference(user_id=user.id)
        db.add(preference)
    preference.module_order = preferences_in.order
    preference.hidden_modules = preferences_in.hidden
    db.commit()
    return _my_modules(db, user)


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_my_password(
    change_in: PasswordChange,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Change one's own password, the current one as proof.

    Every session ends, this one included: whoever had the old password, or a
    stolen session, is out. Failures count against the account like failed
    sign-ins, so a stolen session cannot be used to guess the password.
    """
    state = ratelimit.is_locked("user", user.username)
    if state.locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(state.retry_after)},
        )
    if not verify_password_constant_time(
        change_in.current_password, user.hashed_password
    ):
        ratelimit.register_failure("user", user.username)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The current password is not right",
        )
    ratelimit.reset("user", user.username)
    user.hashed_password = get_password_hash(change_in.new_password)
    end_sessions(user)
    db.commit()
    logger.info("'%s' changed their password", user.username)
