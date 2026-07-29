from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_or_404
from app.core.security import require_admin
from app.db.database import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserRoleUpdate

router = APIRouter()


@router.patch("/{user_id}/role", response_model=UserResponse)
def update_user_role(
    user_id: int,
    role_in: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    user = get_or_404(db, User, user_id)
    user.role = role_in.role
    db.commit()
    db.refresh(user)
    return user
