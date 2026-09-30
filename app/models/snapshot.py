from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import false, func

from app.db.database import Base


class BacklogSnapshot(Base):
    """The backlog of one team at the end of one day (UTC).

    The dashboard computed everything at the present moment, so nobody could
    say whether things were getting better. One row per day and team, taken by
    the daily pass; the whole estate is the sum of the teams.
    """

    __tablename__ = "backlog_snapshots"

    __table_args__ = (
        UniqueConstraint("day", "owner_team", name="uq_backlog_snapshot_day_team"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)
    # "" for hosts without a team: NULLs would not make the pair unique.
    owner_team: Mapped[str] = mapped_column(
        String(128), nullable=False, server_default="", default=""
    )
    # Rebuilt afterwards from detection and fix dates rather than taken that
    # day: a finding reopened since, or a score that moved, is not reflected.
    estimated: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default=false(), default=False
    )
    open_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_high: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_kev: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    overdue: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    open_risk: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    new_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Actually fixed that day (not accepted or dismissed).
    fixed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fixed_on_time: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Summed so that a mean time to remediate stays exact across days and teams.
    fixed_days_total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    fixed_risk: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
