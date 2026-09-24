from enum import Enum

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.database import Base


class ScanStatus(str, Enum):
    pending = "Pending"
    running = "Running"
    success = "Success"
    failed = "Failed"


def _enum_values(enum_cls) -> list[str]:
    """Persist the human-readable value rather than the member name, matching
    the convention used by the other models."""
    return [member.value for member in enum_cls]


class ScanJob(Base):
    """Durable record of an uploaded scan and what it produced.

    Celery's result backend expires and is not queryable, so without this table
    an upload leaves no trace: no author, no date, no outcome. This is also what
    lets a scan's status be scoped to the user who submitted it.
    """

    __tablename__ = "scan_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str | None] = mapped_column(
        String(155), unique=True, index=True, nullable=True
    )
    scan_type: Mapped[str] = mapped_column(String(32), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    uploaded_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    status: Mapped[ScanStatus] = mapped_column(
        SAEnum(ScanStatus, name="scan_status_enum", values_callable=_enum_values),
        default=ScanStatus.pending,
        server_default=ScanStatus.pending.value,
        nullable=False,
        index=True,
    )

    processed_records: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    new_assets: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    new_vulnerabilities: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    new_associations: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    reopened: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )

    message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    finished_at: Mapped[DateTime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    uploader = relationship("User")
