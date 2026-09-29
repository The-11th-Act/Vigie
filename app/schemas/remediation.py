from datetime import datetime

from pydantic import BaseModel


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
