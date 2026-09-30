from datetime import datetime
from enum import Enum

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.database import Base


class RemediationKind(str, Enum):
    """What a remediation team is asked to do.

    Stored as a plain string rather than an ENUM, like the threat feeds: a new
    kind needs no database type to alter.
    """

    kb = "kb"  # a Microsoft update, by KB number
    vendor_fix = "vendor_fix"  # upgrade or patch published by the vendor
    workaround = "workaround"
    mitigation = "mitigation"
    no_fix = "no_fix"  # the vendor has none, or will not fix


class RemediationAction(Base):
    """One thing to deploy or change, shared by every finding it fixes.

    Remediation teams work in patches, not CVEs: a single cumulative update
    closes dozens of CVEs on hundreds of hosts. ``reference`` is the unit they
    recognise: ``KB5034441`` for a Microsoft update, otherwise the scanner's
    check (``nessus:171234``), since that is what one upgrade instruction maps to.
    """

    __tablename__ = "remediation_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    reference: Mapped[str] = mapped_column(
        String(128), unique=True, index=True, nullable=False
    )
    kind: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    title: Mapped[str | None] = mapped_column(String(512), nullable=True)
    solution: Mapped[str | None] = mapped_column(Text, nullable=True)
    url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # Scanner family ("Windows : Microsoft Bulletins", "Web Servers"...).
    family: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    findings = relationship("FindingRemediation", back_populates="action")


class FindingRemediation(Base):
    """A remediation a source prescribes for one finding.

    Attached to the finding (asset × CVE), not to the CVE: the same CVE is fixed
    by a different KB on Windows 10 and on Server 2022. Each source's links are
    replaced whenever it reports the finding again, so a superseded cumulative
    update disappears once the scanner asks for the next one.
    """

    __tablename__ = "finding_remediations"

    __table_args__ = (
        UniqueConstraint(
            "finding_id", "action_id", "source", name="uq_finding_remediation"
        ),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("asset_vulnerabilities.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_actions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    # Per host: two hosts missing the same fix can run different versions.
    installed_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    finding = relationship("AssetVulnerability", back_populates="remediations")
    action = relationship("RemediationAction", back_populates="findings")
