"""GLPI connector: the REST client against a simulated GLPI, then a whole
sync through it.

The simulation follows GLPI's documented REST API (apirest.php): a session
opened with the user token, errors as ["ERROR_CODE", "message"], tickets,
solutions and followups. It is not a real GLPI: see the module docstring of
app/services/glpi.py.
"""

import json

import pytest
import requests

from app.core.config import Settings, settings
from app.core.scope import EVERYTHING
from app.models.asset import Asset
from app.models.remediation import RemediationAction
from app.parsers.utils import remediation
from app.services import glpi
from app.services.glpi import (
    GlpiClient,
    GlpiConnector,
    GlpiIdentity,
    describe,
    front_url,
    glpi_connector,
    glpi_identity,
)
from app.services.ingestion import ingest_findings
from app.services.ticketing import (
    ConnectorUnavailable,
    ExternalState,
    ExternalTicketClosed,
    ExternalTicketError,
    TicketExport,
    sync_tickets_with,
)
from app.services.tickets import create_tickets
from app.worker import tasks
from app.worker.celery_app import build_beat_schedule

URL = "https://glpi.example.com/apirest.php"
USER_TOKEN = "user-token-0123456789"
APP_TOKEN = "app-token-abcdef"


class FakeResponse:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self._body = body
        self.headers = {}
        self.content = b"" if body is None else json.dumps(body).encode()

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class FakeGlpi:
    """A requests.Session stand-in that behaves like GLPI's REST API."""

    def __init__(self, app_token=None):
        self.app_token = app_token
        self.tickets: dict[int, dict] = {}
        self.solutions: list[dict] = []
        self.followups: list[dict] = []
        self.sessions: set[str] = set()
        self.requests: list[tuple] = []
        self.failures: list = []  # status codes or exceptions, served first
        self.next_id = 1
        self.opened = 0

    def request(self, method, url, json=None, headers=None, timeout=None):
        assert url.startswith(URL + "/"), url
        path = url[len(URL) + 1 :]
        headers = headers or {}
        self.requests.append((method, path, json))
        if self.failures:
            failure = self.failures.pop(0)
            if isinstance(failure, Exception):
                raise failure
            return FakeResponse(failure, ["ERROR", "simulated failure"])
        if self.app_token and headers.get("App-Token") != self.app_token:
            return FakeResponse(400, ["ERROR_WRONG_APP_TOKEN_PARAMETER", "bad App-Token"])
        if path == "initSession":
            if headers.get("Authorization") != f"user_token {USER_TOKEN}":
                return FakeResponse(
                    401, ["ERROR_GLPI_LOGIN_USER_TOKEN", "parameter user_token is wrong"]
                )
            self.opened += 1
            token = f"session-{self.opened}"
            self.sessions.add(token)
            return FakeResponse(200, {"session_token": token})
        if headers.get("Session-Token") not in self.sessions:
            return FakeResponse(401, ["ERROR_SESSION_TOKEN_INVALID", "session expired"])
        if path == "killSession":
            self.sessions.discard(headers["Session-Token"])
            return FakeResponse(200, None)
        return self._item(method, path, json)

    def _item(self, method, path, payload):
        if method == "POST" and path == "Ticket":
            fields = payload["input"]
            if not fields.get("name"):
                return FakeResponse(400, ["ERROR_GLPI_ADD", "name is required"])
            ticket_id = self.next_id
            self.next_id += 1
            self.tickets[ticket_id] = {
                **fields,
                "id": ticket_id,
                "status": 1,
                "is_deleted": 0,
            }
            return FakeResponse(201, {"id": ticket_id, "message": ""})
        if path.startswith("Ticket/"):
            ticket = self.tickets.get(int(path.split("/")[1]))
            if ticket is None:
                return FakeResponse(404, ["ERROR_ITEM_NOT_FOUND", "Item not found"])
            if method == "GET":
                return FakeResponse(200, ticket)
            if method == "PUT":
                ticket.update(payload["input"])
                return FakeResponse(200, [{str(ticket["id"]): True, "message": ""}])
        if method == "POST" and path in ("ITILSolution", "ITILFollowup"):
            fields = payload["input"]
            assert fields["itemtype"] == "Ticket"
            ticket = self.tickets[fields["items_id"]]
            if path == "ITILSolution":
                self.solutions.append(fields)
                ticket["status"] = 5
            else:
                self.followups.append(fields)
            return FakeResponse(201, {"id": len(self.solutions) + len(self.followups)})
        return FakeResponse(400, ["ERROR_RESOURCE_NOT_FOUND_NOR_COMMONDBTM", path])

    def calls(self, method, path):
        return [payload for m, p, payload in self.requests if (m, p) == (method, path)]


@pytest.fixture
def server():
    return FakeGlpi()


@pytest.fixture
def sleeps():
    return []


@pytest.fixture
def client(server, sleeps):
    return GlpiClient(URL, USER_TOKEN, session=server, sleep=sleeps.append)


@pytest.fixture
def connector(client):
    return GlpiConnector(client, GlpiIdentity(target=URL, teams=None))


@pytest.fixture
def glpi_settings(monkeypatch):
    monkeypatch.setattr(settings, "GLPI_URL", URL)
    monkeypatch.setattr(settings, "GLPI_USER_TOKEN", USER_TOKEN)
    monkeypatch.setattr(settings, "GLPI_TEAM_GROUPS", {"Servers": 12, "Unassigned": 3})


class FakeAction:
    reference = "KB5034127"
    kind = "kb"
    title = "January <rollup>"


class FakeHost:
    def __init__(self, ip, hostname=None, kev=False):
        self.ip_address = ip
        self.hostname = hostname
        self.installed_versions = ["10.0.17763.5206"]
        self.fixed_versions = ["10.0.17763.5329"]
        self.in_kev = kev


def export(team="Servers", hosts=2, max_risk=8.0):
    return TicketExport(
        ticket_id=7,
        title=f"Deploy KB5034127 — {team or 'Unassigned'}",
        owner_team=team,
        action=FakeAction(),
        metrics={
            "findings_open": 3,
            "hosts_open": hosts,
            "kev": 1,
            "overdue": 0,
            "max_risk": max_risk,
            "next_deadline": None,
        },
        hosts=[
            FakeHost(f"10.0.0.{i}", f"srv-{i}", kev=i == 1) for i in range(1, hosts + 1)
        ],
    )


class TestSession:
    def test_opened_with_the_user_token_and_closed(self, client, server):
        client.open()
        assert server.sessions == {"session-1"}

        client.close()

        assert server.sessions == set()

    def test_the_app_token_goes_with_every_request(self, sleeps):
        server = FakeGlpi(app_token=APP_TOKEN)
        client = GlpiClient(
            URL, USER_TOKEN, APP_TOKEN, session=server, sleep=sleeps.append
        )

        client.open()
        assert client.call("GET", "Ticket/1", missing_ok=True) is None

    def test_a_wrong_token_stops_the_run_with_a_hint(self, server, sleeps):
        client = GlpiClient(URL, "wrong", session=server, sleep=sleeps.append)

        with pytest.raises(ConnectorUnavailable, match="GLPI_USER_TOKEN") as error:
            client.open()
        assert "ERROR_GLPI_LOGIN_USER_TOKEN" in str(error.value)

    def test_an_expired_session_is_reopened_once(self, client, server):
        client.open()
        server.sessions.clear()  # GLPI dropped it

        assert client.call("GET", "Ticket/1", missing_ok=True) is None
        assert server.opened == 2


class TestRetries:
    def test_a_server_error_is_retried(self, client, server, sleeps):
        client.open()
        server.failures = [503]

        assert client.call("GET", "Ticket/1", missing_ok=True) is None
        assert len(sleeps) == 1

    def test_a_server_that_stays_down_stops_the_run(self, client, server):
        client.open()
        server.failures = [502, 502, 502]

        with pytest.raises(ConnectorUnavailable, match="HTTP 502"):
            client.call("GET", "Ticket/1")

    def test_an_unreachable_server_stops_the_run(self, client, server):
        server.failures = [requests.ConnectionError("refused")] * 3

        with pytest.raises(ConnectorUnavailable, match="unreachable"):
            client.open()

    def test_a_refused_request_is_this_ticket_s_problem(self, client, server):
        client.open()

        with pytest.raises(ExternalTicketError, match="HTTP 400 ERROR_GLPI_ADD"):
            client.call("POST", "Ticket", {"input": {"name": ""}})


class TestCreate:
    def test_the_ticket_describes_the_work(self, connector, server, glpi_settings):
        created = connector.create(export())

        ticket = server.tickets[int(created.ref)]
        assert ticket["name"] == "Deploy KB5034127 — Servers"
        assert ticket["type"] == 2
        assert ticket["urgency"] == 4
        assert ticket["_groups_id_assign"] == 12
        assert "entities_id" not in ticket and "itilcategories_id" not in ticket
        content = ticket["content"]
        assert "Vigie remediation ticket #7" in content
        assert "January &lt;rollup&gt;" in content  # escaped, not markup
        assert "<li>srv-1 (10.0.0.1) — installed 10.0.17763.5206; fixed in " in content
        assert "[KEV]" in content
        assert created.url == (
            f"https://glpi.example.com/front/ticket.form.php?id={created.ref}"
        )
        assert created.state == ExternalState.open

    def test_entity_category_and_type_come_from_the_settings(
        self, connector, server, glpi_settings, monkeypatch
    ):
        monkeypatch.setattr(settings, "GLPI_ENTITY_ID", 0)
        monkeypatch.setattr(settings, "GLPI_CATEGORY_ID", 42)
        monkeypatch.setattr(settings, "GLPI_TICKET_TYPE", 1)

        ticket = server.tickets[int(connector.create(export()).ref)]

        assert (ticket["entities_id"], ticket["itilcategories_id"], ticket["type"]) == (
            0,
            42,
            1,
        )

    def test_unowned_hosts_and_unmapped_teams(self, connector, server, glpi_settings):
        unassigned = server.tickets[int(connector.create(export(team=None)).ref)]
        workplace = server.tickets[int(connector.create(export(team="Workplace")).ref)]

        assert unassigned["_groups_id_assign"] == 3
        assert "_groups_id_assign" not in workplace

    @pytest.mark.parametrize(
        "risk, urgency", [(9.5, 5), (9.0, 5), (7.0, 4), (4.0, 3), (3.9, 2), (0.0, 2)]
    )
    def test_urgency_follows_the_highest_risk(
        self, connector, server, glpi_settings, risk, urgency
    ):
        created = connector.create(export(max_risk=risk))
        assert server.tickets[int(created.ref)]["urgency"] == urgency

    def test_a_long_host_list_is_cut(self):
        content = describe(export(hosts=60))
        assert content.count("<li>") == glpi.HOSTS_IN_DESCRIPTION
        assert "and 10 more" in content


class TestStates:
    @pytest.mark.parametrize(
        "status, state",
        [
            (1, ExternalState.open),
            (2, ExternalState.in_progress),
            (3, ExternalState.in_progress),
            (4, ExternalState.in_progress),
            (5, ExternalState.solved),
            (6, ExternalState.closed),
        ],
    )
    def test_glpi_statuses(self, connector, server, glpi_settings, status, state):
        ref = connector.create(export()).ref
        server.tickets[int(ref)]["status"] = status
        assert connector.state(ref) == state

    def test_deleted_or_in_the_trash_is_gone(self, connector, server, glpi_settings):
        ref = connector.create(export()).ref
        server.tickets[int(ref)]["is_deleted"] = 1
        assert connector.state(ref) == ExternalState.gone
        assert connector.state("999") == ExternalState.gone

    def test_an_unknown_status_is_an_error(self, connector, server, glpi_settings):
        ref = connector.create(export()).ref
        server.tickets[int(ref)]["status"] = 9
        with pytest.raises(ExternalTicketError, match="unknown status"):
            connector.state(ref)


class TestSolveAndReopen:
    def test_solved_with_a_solution(self, connector, server, glpi_settings):
        ref = connector.create(export()).ref

        assert (
            connector.solve(ref, "Resolved in Vigie: <confirmed>") == ExternalState.solved
        )
        (solution,) = server.solutions
        assert solution["items_id"] == int(ref)
        assert solution["content"] == "<p>Resolved in Vigie: &lt;confirmed&gt;</p>"
        assert server.tickets[int(ref)]["status"] == 5

    def test_reopened_with_a_followup(self, connector, server, glpi_settings):
        ref = connector.create(export()).ref
        connector.solve(ref, "done")

        assert connector.reopen(ref, "A finding came back") == ExternalState.in_progress
        assert server.tickets[int(ref)]["status"] == 2
        assert server.followups[-1]["content"] == "<p>A finding came back</p>"

    def test_retargeted_with_a_new_title_description_and_followup(
        self, connector, server, glpi_settings
    ):
        ref = connector.create(export(hosts=2)).ref
        server.tickets[int(ref)]["urgency"] = 5  # raised by the team
        later = export(hosts=3)
        later.title = "Deploy KB5034768 — Servers"

        connector.retarget(ref, later, "Now KB5034768 instead of KB5034127")

        ticket = server.tickets[int(ref)]
        assert ticket["name"] == "Deploy KB5034768 — Servers"
        assert "srv-3 (10.0.0.3)" in ticket["content"]
        assert ticket["urgency"] == 5 and ticket["status"] == 1
        (update,) = server.calls("PUT", f"Ticket/{ref}")
        assert set(update["input"]) == {"name", "content"}
        assert server.followups[-1] == {
            "itemtype": "Ticket",
            "items_id": int(ref),
            "content": "<p>Now KB5034768 instead of KB5034127</p>",
        }

    def test_a_closed_ticket_cannot_be_reopened(self, connector, server, glpi_settings):
        ref = connector.create(export()).ref
        server.tickets[int(ref)]["status"] = 6

        with pytest.raises(ExternalTicketClosed):
            connector.reopen(ref, "A finding came back")
        assert server.calls("PUT", f"Ticket/{ref}") == []


class TestSettings:
    def build(self, **values):
        return Settings(_env_file=None, SECRET_KEY="x" * 40, **values)

    def test_the_url_is_the_rest_api(self):
        assert self.build(GLPI_URL=URL + "/").GLPI_URL == URL
        with pytest.raises(ValueError, match="apirest.php"):
            self.build(GLPI_URL="https://glpi.example.com/")
        with pytest.raises(ValueError, match="http"):
            self.build(GLPI_URL="ftp://glpi.example.com/apirest.php")

    def test_enabling_needs_the_url(self):
        with pytest.raises(ValueError, match="GLPI_URL"):
            self.build(GLPI_SYNC_ENABLED=True)

    def test_the_ticket_type_is_incident_or_request(self):
        with pytest.raises(ValueError):
            self.build(GLPI_TICKET_TYPE=3)

    def test_front_url(self):
        assert front_url("https://h/glpi/apirest.php", 4) == (
            "https://h/glpi/front/ticket.form.php?id=4"
        )

    def test_identity_and_connector(self, monkeypatch):
        monkeypatch.setattr(settings, "GLPI_URL", None)
        assert glpi_identity() is None and glpi_connector() is None
        monkeypatch.setattr(settings, "GLPI_URL", URL)
        monkeypatch.setattr(settings, "GLPI_USER_TOKEN", None)
        assert glpi_identity().teams is None
        # The API knows the server, only the worker holds the token.
        assert glpi_connector() is None
        monkeypatch.setattr(settings, "GLPI_USER_TOKEN", USER_TOKEN)
        assert glpi_connector() is not None

    def test_only_mapped_teams(self, monkeypatch):
        monkeypatch.setattr(settings, "GLPI_URL", URL)
        monkeypatch.setattr(settings, "GLPI_EXPORT_UNMAPPED_TEAMS", False)
        monkeypatch.setattr(
            settings, "GLPI_TEAM_GROUPS", {"Servers": 12, "Unassigned": 3}
        )
        assert glpi_identity().teams == frozenset({"Servers", None})


class TestWorker:
    def test_scheduled_only_when_enabled(self, monkeypatch):
        assert "glpi-sync" not in build_beat_schedule()
        monkeypatch.setattr(settings, "GLPI_URL", URL)
        monkeypatch.setattr(settings, "GLPI_SYNC_ENABLED", True)
        monkeypatch.setattr(settings, "GLPI_SYNC_INTERVAL_MINUTES", 2)
        entry = build_beat_schedule()["glpi-sync"]
        assert entry["task"] == "app.worker.tasks.sync_glpi_task"
        assert entry["schedule"].total_seconds() == 120

    def test_the_task_skips_when_disabled_or_without_token(self, monkeypatch):
        assert tasks.sync_glpi_task()["status"] == "skipped"
        monkeypatch.setattr(settings, "GLPI_SYNC_ENABLED", True)
        monkeypatch.setattr(settings, "GLPI_URL", URL)
        monkeypatch.setattr(settings, "GLPI_USER_TOKEN", None)
        assert "GLPI_USER_TOKEN" in tasks.sync_glpi_task()["message"]


def finding(ip):
    return {
        "ip_address": ip,
        "hostname": f"host-{ip}",
        "operating_system": None,
        "cve_id": "CVE-2024-0001",
        "title": "Test",
        "description": None,
        "cvss_score": 9.8,
        "severity": "Critical",
        "remediations": [remediation("kb", "KB5034127", title="January rollup")],
    }


class TestThroughTheSync:
    """The generic sync, the connector and the client together."""

    def test_export_progress_and_resolution(
        self, db_session, admin_user, connector, server, glpi_settings
    ):
        db_session.add(Asset(ip_address="10.0.0.1", owner_team="Servers"))
        db_session.commit()
        ingest_findings(db_session, [finding("10.0.0.1")], "nessus")
        action = db_session.query(RemediationAction).one()
        (ticket,), _ = create_tickets(db_session, action, admin_user, EVERYTHING)
        db_session.commit()

        assert sync_tickets_with(db_session, connector).exported == 1
        glpi_ticket = server.tickets[int(ticket.external_ref)]
        assert glpi_ticket["_groups_id_assign"] == 12
        assert "host-10.0.0.1 (10.0.0.1)" in glpi_ticket["content"]

        glpi_ticket["status"] = 2  # a technician takes it
        sync_tickets_with(db_session, connector)
        assert ticket.status == "in_progress"

        ticket.status = "resolved"  # as the scans would
        db_session.commit()
        sync_tickets_with(db_session, connector)
        assert glpi_ticket["status"] == 5
        assert "scans confirm" in server.solutions[0]["content"]
        # One session per run, each closed.
        assert server.opened == 3 and server.sessions == set()
