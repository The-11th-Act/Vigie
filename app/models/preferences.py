from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func, true

from app.db.database import Base


class ModuleSetting(Base):
    """Whether a module is switched on for the whole instance.

    No row means enabled: a module added by a release is available at once,
    and only an administrator's explicit choice turns one off.
    """

    __tablename__ = "module_settings"

    module: Mapped[str] = mapped_column(String(32), primary_key=True)
    enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=true(), nullable=False
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RoleProfile(Base):
    """The modules a role sees, in order, as an administrator set them.

    No row means the default profile from ``app/core/modules.py``.
    """

    __tablename__ = "role_profiles"

    role: Mapped[str] = mapped_column(String(16), primary_key=True)
    modules: Mapped[list] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class UserPreference(Base):
    """How one user arranges the modules their role grants.

    Only arrangement: hiding a module takes it out of the sidebar, it does not
    take away the right to use it.
    """

    __tablename__ = "user_preferences"

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    module_order: Mapped[list | None] = mapped_column(JSON, nullable=True)
    hidden_modules: Mapped[list | None] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
