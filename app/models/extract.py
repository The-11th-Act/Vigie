from sqlalchemy import JSON, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.database import Base


class ApiToken(Base):
    """A personal access token, for scripts and reporting tools.

    The web app signs in with cookies, and a script used to need a password to
    get a Bearer token. A personal token is read-only, expires, can be revoked
    alone, and is stored hashed: the secret is shown once, at creation.
    """

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    # The first characters of the secret, to recognise a token in a list.
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    # SHA-256 of the secret: the secret is random, so no salt or slow hash is
    # needed, and the lookup stays a single indexed equality.
    token_hash: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    expires_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_used_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user = relationship("User")


class SavedExtract(Base):
    """A named extract: dataset, columns and filters, run again by its URL."""

    __tablename__ = "saved_extracts"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    dataset: Mapped[str] = mapped_column(String(32), nullable=False)
    columns: Mapped[list] = mapped_column(JSON, nullable=False)
    filters: Mapped[dict] = mapped_column(JSON, nullable=False)
    format: Mapped[str] = mapped_column(String(8), nullable=False)
    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
