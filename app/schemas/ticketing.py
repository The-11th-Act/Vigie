from datetime import datetime

from pydantic import BaseModel


class TicketingStatus(BaseModel):
    connector: str
    label: str
    # GLPI_SYNC_ENABLED: the worker runs the sync on schedule.
    enabled: bool
    # GLPI_URL is set. Whether the tokens are right only the worker knows:
    # last_error says when they are not.
    configured: bool
    url: str | None = None
    interval_minutes: int
    team_groups: dict[str, int] = {}
    export_unmapped_teams: bool = True
    linked: int = 0
    # Links another instance (a staging restored from production) or another
    # GLPI server wrote: shown, never synced.
    foreign: int = 0
    gone: int = 0
    errors: int = 0
    pending_export: int = 0
    last_run_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error: str | None = None
    last_result: dict[str, int] | None = None


class TicketingSyncQueued(BaseModel):
    task_id: str
