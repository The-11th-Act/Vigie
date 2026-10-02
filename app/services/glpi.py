"""GLPI connector: remediation tickets mirrored as GLPI tickets.

Talks to GLPI's REST API (``apirest.php``, GLPI 10 and 11) as the account
whose API token is GLPI_USER_TOKEN, plus the API client's App-Token when GLPI
requires one. A session is opened per run and closed at its end.

- A Vigie ticket becomes a GLPI ticket of GLPI_TICKET_TYPE, in GLPI_ENTITY_ID
  and GLPI_CATEGORY_ID when set, assigned to the owner team's group
  (GLPI_TEAM_GROUPS), its urgency from the ticket's highest risk, its
  description listing the fix and the hosts left to fix.
- GLPI statuses map to ExternalState: new -> open, processing and pending ->
  in_progress, solved -> solved, closed -> closed. A ticket in the trash or
  deleted is gone.
- Vigie solves a ticket with an ITILSolution, and reopens it by moving it back
  to "processing (assigned)" with a followup saying why. A closed GLPI ticket
  cannot be reopened: the sync replaces it.

Tested against a simulated GLPI (tests/test_glpi.py) and, in the production
stack test, against a stand-in server: check it against your own GLPI before
relying on it, the assignment field especially (``_groups_id_assign``).
"""

import html
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import requests

from app.core.config import settings
from app.core.http_retry import backoff_seconds, retry_after_seconds
from app.services.ticketing import (
    ConnectorUnavailable,
    ExternalState,
    ExternalTicket,
    ExternalTicketClosed,
    ExternalTicketError,
    TicketExport,
)
from app.services.tickets import UNASSIGNED

logger = logging.getLogger(__name__)

GLPI = "glpi"
LABEL = "GLPI"

# GLPI ticket statuses (CommonITILObject).
NEW, ASSIGNED, PLANNED, WAITING, SOLVED, CLOSED = 1, 2, 3, 4, 5, 6
STATE_OF_STATUS = {
    NEW: ExternalState.open,
    ASSIGNED: ExternalState.in_progress,
    PLANNED: ExternalState.in_progress,
    WAITING: ExternalState.in_progress,
    SOLVED: ExternalState.solved,
    CLOSED: ExternalState.closed,
}

REQUEST_TIMEOUT = 30
MAX_ATTEMPTS = 3
# Hosts listed in a ticket's description; the full list is in Vigie.
HOSTS_IN_DESCRIPTION = 50
MAX_TITLE_LENGTH = 255


def team_key(team: str | None) -> str:
    return team or UNASSIGNED


def _teams_exported() -> frozenset[str | None] | None:
    if settings.GLPI_EXPORT_UNMAPPED_TEAMS:
        return None
    return frozenset(
        None if team == UNASSIGNED else team for team in settings.GLPI_TEAM_GROUPS
    )


@dataclass(frozen=True)
class GlpiIdentity:
    """The connector as the seal and the administration screen see it."""

    target: str
    teams: frozenset[str | None] | None
    name: str = GLPI
    label: str = LABEL


def glpi_identity() -> GlpiIdentity | None:
    """None when no GLPI is configured."""
    if not settings.GLPI_URL:
        return None
    return GlpiIdentity(target=settings.GLPI_URL, teams=_teams_exported())


def front_url(api_url: str, ticket_id: int) -> str:
    """The ticket's page, next to the API: .../apirest.php -> .../front/..."""
    base = api_url.removesuffix("/apirest.php")
    return f"{base}/front/ticket.form.php?id={ticket_id}"


def _error_detail(response) -> str:
    """GLPI answers errors as ["ERROR_CODE", "message"]."""
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, list):
        return " ".join(str(part) for part in body if part)[:200]
    return ""


class GlpiClient:
    """The REST calls the connector needs, with GLPI's session handshake."""

    def __init__(
        self,
        url: str,
        user_token: str,
        app_token: str | None = None,
        session: requests.Session | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.url = url.rstrip("/")
        self._user_token = user_token
        self._app_token = app_token or None
        self._session = session or requests.Session()
        self._sleep = sleep
        self._session_token: str | None = None

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._app_token:
            headers["App-Token"] = self._app_token
        return headers

    def open(self) -> None:
        response = self._send(
            "GET",
            "initSession",
            None,
            {**self._headers(), "Authorization": f"user_token {self._user_token}"},
        )
        if response.status_code != 200:
            raise ConnectorUnavailable(
                f"GLPI refused the session (HTTP {response.status_code} "
                f"{_error_detail(response)}): check GLPI_USER_TOKEN, GLPI_APP_TOKEN "
                "and that the API is enabled"
            )
        token = (response.json() or {}).get("session_token")
        if not token:
            raise ConnectorUnavailable("GLPI opened no session")
        self._session_token = token

    def close(self) -> None:
        if not self._session_token:
            return
        try:
            self._session.request(
                "GET",
                f"{self.url}/killSession",
                headers={**self._headers(), "Session-Token": self._session_token},
                timeout=REQUEST_TIMEOUT,
            )
        except requests.RequestException:
            pass  # the session expires on its own
        self._session_token = None

    def _send(self, method: str, path: str, payload: Any, headers: dict[str, str]):
        """One request, retried on a network error, a 429 or a 5xx."""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self._session.request(
                    method,
                    f"{self.url}/{path}",
                    json=payload,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                )
            except requests.RequestException as exc:
                if attempt == MAX_ATTEMPTS:
                    raise ConnectorUnavailable(f"GLPI unreachable: {exc}") from None
                self._sleep(backoff_seconds(attempt))
                continue
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == MAX_ATTEMPTS:
                    raise ConnectorUnavailable(
                        f"GLPI answered HTTP {response.status_code} "
                        f"{_error_detail(response)}".strip()
                    )
                self._sleep(retry_after_seconds(response, attempt))
                continue
            return response
        raise ConnectorUnavailable("GLPI unreachable")  # pragma: no cover

    def call(
        self, method: str, path: str, payload: Any = None, missing_ok: bool = False
    ) -> Any:
        """A request in the session; reopens it once if it expired."""
        if not self._session_token:
            self.open()
        for reopened in (False, True):
            response = self._send(
                method,
                path,
                payload,
                {**self._headers(), "Session-Token": self._session_token or ""},
            )
            if response.status_code == 401 and not reopened:
                self.open()
                continue
            break
        status = response.status_code
        if status == 401:
            raise ConnectorUnavailable(
                f"GLPI refused the session (HTTP 401 {_error_detail(response)})".strip()
            )
        if status == 404 and missing_ok:
            return None
        if status >= 400:
            raise ExternalTicketError(
                f"GLPI {method} {path}: HTTP {status} {_error_detail(response)}".strip()
            )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            raise ExternalTicketError(
                f"GLPI {method} {path}: answer is not JSON"
            ) from None


def _urgency(max_risk: float) -> int:
    """GLPI urgency, 1 (very low) to 5 (very high), from the highest risk."""
    if max_risk >= 9:
        return 5
    if max_risk >= 7:
        return 4
    if max_risk >= 4:
        return 3
    return 2


def _host_line(host) -> str:
    name = host.hostname or host.ip_address
    where = f"{name} ({host.ip_address})" if host.hostname else name
    versions = []
    if host.installed_versions:
        versions.append("installed " + ", ".join(host.installed_versions))
    if host.fixed_versions:
        versions.append("fixed in " + ", ".join(host.fixed_versions))
    detail = f" — {'; '.join(versions)}" if versions else ""
    flags = " [KEV]" if host.in_kev else ""
    return f"{where}{detail}{flags}"


def describe(export: TicketExport) -> str:
    """The ticket's description, as the HTML GLPI's rich text stores."""
    action, metrics = export.action, export.metrics
    e = html.escape
    fix = action.reference if not action.title else f"{action.reference} — {action.title}"
    deadline = metrics.get("next_deadline")
    facts = [
        f"{metrics.get('findings_open', 0)} open finding(s) "
        f"on {metrics.get('hosts_open', 0)} host(s)",
        f"KEV: {metrics.get('kev', 0)}",
        f"overdue: {metrics.get('overdue', 0)}",
    ]
    if deadline is not None:
        facts.append(f"next deadline: {deadline:%Y-%m-%d}")
    parts = [
        f"<p>Vigie remediation ticket #{export.ticket_id} — team "
        f"{e(team_key(export.owner_team))}.</p>",
        f"<p><b>Fix:</b> {e(fix)}</p>",
        f"<p><b>Left to fix:</b> {e('; '.join(facts))}.</p>",
    ]
    if export.hosts:
        shown = export.hosts[:HOSTS_IN_DESCRIPTION]
        items = "".join(f"<li>{e(_host_line(host))}</li>" for host in shown)
        parts.append(f"<p><b>Hosts</b>, highest risk first:</p><ul>{items}</ul>")
        if len(export.hosts) > len(shown):
            parts.append(
                f"<p>… and {len(export.hosts) - len(shown)} more: the full list "
                "is exported from the ticket in Vigie.</p>"
            )
    parts.append(
        "<p>The team follows this ticket here. Vigie solves it once the scans "
        "confirm every finding is closed, and reopens it if one comes back.</p>"
    )
    return "".join(parts)


def _paragraphs(text: str) -> str:
    return "".join(f"<p>{html.escape(line)}</p>" for line in text.splitlines() if line)


class GlpiConnector:
    name = GLPI
    label = LABEL

    def __init__(self, client: GlpiClient, identity: GlpiIdentity) -> None:
        self._client = client
        self.target = identity.target
        self.teams = identity.teams

    def open(self) -> None:
        self._client.open()

    def close(self) -> None:
        self._client.close()

    def create(self, export: TicketExport) -> ExternalTicket:
        fields: dict[str, Any] = {
            "name": export.title[:MAX_TITLE_LENGTH],
            "content": describe(export),
            "type": settings.GLPI_TICKET_TYPE,
            "urgency": _urgency(float(export.metrics.get("max_risk") or 0.0)),
        }
        if settings.GLPI_ENTITY_ID is not None:
            fields["entities_id"] = settings.GLPI_ENTITY_ID
        if settings.GLPI_CATEGORY_ID is not None:
            fields["itilcategories_id"] = settings.GLPI_CATEGORY_ID
        group = settings.GLPI_TEAM_GROUPS.get(team_key(export.owner_team))
        if group is not None:
            fields["_groups_id_assign"] = group
        created = self._client.call("POST", "Ticket", {"input": fields})
        ticket_id = created.get("id") if isinstance(created, dict) else None
        if not isinstance(ticket_id, int):
            raise ExternalTicketError(f"GLPI created no ticket: {created!r}"[:200])
        return ExternalTicket(
            ref=str(ticket_id),
            url=front_url(self.target, ticket_id),
            state=ExternalState.open,
        )

    def _id(self, ref: str) -> int:
        try:
            return int(ref)
        except ValueError:
            raise ExternalTicketError(f"Not a GLPI ticket id: {ref!r}") from None

    def state(self, ref: str) -> ExternalState:
        ticket = self._client.call("GET", f"Ticket/{self._id(ref)}", missing_ok=True)
        if not isinstance(ticket, dict) or ticket.get("is_deleted"):
            return ExternalState.gone
        status: Any = ticket.get("status")
        try:
            return STATE_OF_STATUS[int(status)]
        except (KeyError, TypeError, ValueError):
            raise ExternalTicketError(
                f"GLPI ticket {ref} has an unknown status: {status!r}"
            ) from None

    def solve(self, ref: str, message: str) -> ExternalState:
        self._client.call(
            "POST",
            "ITILSolution",
            {
                "input": {
                    "itemtype": "Ticket",
                    "items_id": self._id(ref),
                    "content": _paragraphs(message),
                }
            },
        )
        return ExternalState.solved

    def reopen(self, ref: str, message: str) -> ExternalState:
        current = self.state(ref)
        if current in (ExternalState.closed, ExternalState.gone):
            raise ExternalTicketClosed(f"GLPI ticket {ref} is {current.value}")
        ticket_id = self._id(ref)
        self._client.call("PUT", f"Ticket/{ticket_id}", {"input": {"status": ASSIGNED}})
        self._client.call(
            "POST",
            "ITILFollowup",
            {
                "input": {
                    "itemtype": "Ticket",
                    "items_id": ticket_id,
                    "content": _paragraphs(message),
                }
            },
        )
        return ExternalState.in_progress


def glpi_connector() -> GlpiConnector | None:
    """The connector the worker runs; None when GLPI is not fully configured."""
    identity = glpi_identity()
    if identity is None or not settings.GLPI_USER_TOKEN:
        return None
    client = GlpiClient(
        identity.target, settings.GLPI_USER_TOKEN, settings.GLPI_APP_TOKEN
    )
    return GlpiConnector(client, identity)
