from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_or_404
from app.core.modules import ROLE_ADMIN
from app.core.security import require_admin
from app.db.database import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserRoleUpdate

router = APIRouter()


@router.get("/", response_model=list[UserResponse])
def list_users(db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    """Every account and its role, for the administration screen."""
    return db.query(User).order_by(User.username).all()


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
    user.role = role_in.role
    db.commit()
    db.refresh(user)
    return user
