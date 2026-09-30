from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.modules import MODULES_BY_KEY, current_user, module_access
from app.core.scope import api_team, scope_of
from app.db.database import get_db
from app.models.preferences import UserPreference
from app.models.user import User
from app.schemas.modules import ModuleEntry, MyModulesResponse, PreferencesUpdate

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
