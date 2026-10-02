from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.models.ticket import USER_TICKET_STATUSES


class RemediationActionResponse(BaseModel):
    id: int
    reference: str
    kind: str
    title: str | None = None
    url: str | None = None
    family: str | None = None

    model_config = {"from_attributes": True}


class RemediationActionDetail(RemediationActionResponse):
    solution: str | None = None


class ActionSummaryResponse(BaseModel):
    """One fix and everything deploying it would close."""

    action: RemediationActionResponse
    findings: int
    assets: int
    cves: int
    kev: int
    overdue: int
    # Sum of the open findings' risk: what deploying the fix removes.
    total_risk: float
    max_risk: float
    next_deadline: datetime | None = None
    # Open findings already held by an active ticket.
    tracked: int = 0


class UnremediatedResponse(BaseModel):
    findings: int
    assets: int
    total_risk: float


class PaginatedActionSummaryResponse(BaseModel):
    total: int
    items: list[ActionSummaryResponse]
    unremediated: UnremediatedResponse


class HostResponse(BaseModel):
    asset_id: int
    hostname: str | None = None
    ip_address: str
    operating_system: str | None = None
    business_criticality: str
    internet_facing: bool
    installed_versions: list[str]
    fixed_versions: list[str]
    cves: list[str]
    max_risk: float
    next_deadline: datetime | None = None
    in_kev: bool
    overdue: bool

    model_config = {"from_attributes": True}


class ActionHostsResponse(BaseModel):
    action: RemediationActionDetail
    hosts: list[HostResponse]


class TicketMetrics(BaseModel):
    findings_total: int = 0
    findings_open: int = 0
    hosts_open: int = 0
    hosts_total: int = 0
    open_risk: float = 0.0
    max_risk: float = 0.0
    next_deadline: datetime | None = None
    kev: int = 0
    overdue: int = 0


class TicketResponse(BaseModel):
    id: int
    action_id: int
    owner_team: str | None = None
    title: str
    status: str
    note: str | None = None
    external_system: str | None = None
    external_ref: str | None = None
    external_url: str | None = None
    # Set by a ticketing connector: the external ticket's state as last seen,
    # when, and why the last sync of this ticket failed.
    external_state: str | None = None
    external_synced_at: datetime | None = None
    external_error: str | None = None
    created_by_username: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    resolved_at: datetime | None = None
    action: RemediationActionResponse
    metrics: TicketMetrics = Field(default_factory=TicketMetrics)


class PaginatedTicketResponse(BaseModel):
    total: int
    items: list[TicketResponse]


class TicketAuditResponse(BaseModel):
    username: str | None = None
    old_status: str | None = None
    new_status: str
    note: str | None = None
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class TicketDetailResponse(BaseModel):
    ticket: TicketResponse
    action: RemediationActionDetail
    hosts: list[HostResponse]
    history: list[TicketAuditResponse]


class CreatedTicketsResponse(BaseModel):
    created: list[TicketResponse]
    # Findings added to tickets the teams already had open for this fix.
    added: int


class TicketUpdate(BaseModel):
    status: str | None = None
    note: str | None = Field(None, max_length=2000)
    external_system: str | None = Field(None, max_length=32)
    external_ref: str | None = Field(None, max_length=128)
    external_url: str | None = Field(None, max_length=1024)

    @field_validator("status")
    @classmethod
    def settable_status(cls, v: str | None) -> str | None:
        if v is not None and v not in USER_TICKET_STATUSES:
            raise ValueError(
                f"status must be one of {sorted(USER_TICKET_STATUSES)}; "
                "a ticket is resolved by the scans, once every finding is closed"
            )
        return v

    @field_validator("note", "external_system", "external_ref", "external_url")
    @classmethod
    def blank_is_none(cls, v: str | None) -> str | None:
        return (v or "").strip() or None

    @field_validator("external_url")
    @classmethod
    def http_only(cls, v: str | None) -> str | None:
        # Rendered as a link: no javascript: or data: URL.
        if v and not v.lower().startswith(("https://", "http://")):
            raise ValueError("must be an http(s) URL")
        return v


class TeamsResponse(BaseModel):
    teams: list[str]
