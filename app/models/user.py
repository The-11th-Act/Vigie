from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.database import Base


class User(Base):
    __tablename__ = "users"

    # A primary key is already indexed; index=True would create a duplicate.
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String, nullable=False)
    role: Mapped[str] = mapped_column(
        String, default="analyst", nullable=False
    )  # admin, analyst
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    team_rows: Mapped[list["UserTeam"]] = relationship(
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="UserTeam.owner_team",
    )

    @property
    def teams(self) -> list[str]:
        """The user's scope as the API names it; empty: the whole estate."""
        from app.core.scope import api_team

        return [api_team(row.owner_team) for row in self.team_rows]


class UserTeam(Base):
    """A team whose hosts a user may see: the user's scope (app/core/scope.py).

    A user without any row sees the whole estate, as every account did before
    scopes existed; an administrator is never scoped. "" stands for hosts
    without a team, as in backlog_snapshots.
    """

    __tablename__ = "user_teams"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    owner_team: Mapped[str] = mapped_column(String(128), primary_key=True)
