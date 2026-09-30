from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, selectinload

from app.api.deps import get_or_404
from app.core.modules import ROLE_ADMIN
from app.core.scope import team_value
from app.core.security import require_admin
from app.db.database import get_db
from app.models.user import User, UserTeam
from app.schemas.user import UserResponse, UserRoleUpdate, UserTeamsUpdate

router = APIRouter()


@router.get("/", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    """Every account, its role and its scope, for the administration screen."""
    return (
        db.query(User).options(selectinload(User.team_rows)).order_by(User.username).all()
    )


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_in: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    user = get_or_404(db, User, user_id)
    if user.role == ROLE_ADMIN and role_in.role != ROLE_ADMIN:
        # Nobody could promote anyone again, short of the bootstrap script.
        remaining = db.query(User).filter(User.role == ROLE_ADMIN, User.id != user.id)
        if remaining.count() == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The last administrator cannot be demoted",
            )
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
    wanted = {team_value(team.strip()) for team in teams_in.teams}
    # Changed in place: rows re-created with the same key would clash with
    # the ones being removed in the same flush.
    for row in list(user.team_rows):
        if row.owner_team not in wanted:
            user.team_rows.remove(row)
    kept = {row.owner_team for row in user.team_rows}
    user.team_rows.extend(UserTeam(owner_team=team) for team in sorted(wanted - kept))
    db.commit()
    db.refresh(user)
    return user
