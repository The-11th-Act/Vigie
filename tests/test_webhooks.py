"""Outgoing webhooks: what is queued, how it is sent, and where it may go.

No network beyond the loopback: DNS resolution and the connection are
replaced in every test, except TestPinnedConnection, which talks to real
local servers (HTTP, and HTTPS with a certificate authority made for it).
"""

import hashlib
import hmac
import json
import shutil
import socket
import ssl
import subprocess
import threading
from datetime import UTC, date, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import urllib3

from app.core.config import settings
from app.models.asset import Asset
from app.models.scan import ScanJob, ScanStatus
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.models.webhook import DeliveryStatus, Webhook, WebhookDelivery
from app.parsers.threat_feeds import KevCatalog, KevEntry
from app.services import webhooks
from app.services.threat_intel import apply_kev
from app.services.webhooks import (
    RETRY_DELAYS,
    TargetRefused,
    check_url,
    deliver_due,
    emit,
    purge_deliveries,
    reseal_webhooks,
    seal,
    seal_state,
)
from app.worker import tasks
from app.worker.celery_app import build_beat_schedule

PUBLIC_IP = "93.184.216.34"
OTHER_KEY = "another-instance-signing-key-0123456789abcdef"


@pytest.fixture
def resolve(monkeypatch):
    """Every host resolves to PUBLIC_IP, unless a test says otherwise."""
    addresses = {"default": PUBLIC_IP}

    def getaddrinfo(host, port, *args, **kwargs):
        address = addresses.get(host, addresses["default"])
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

    monkeypatch.setattr(webhooks.socket, "getaddrinfo", getaddrinfo)
    return addresses


@pytest.fixture
def receiver(monkeypatch, resolve):
    """Record each POST and answer with the next queued status (200 by default).

    Replaces the connection itself (``_post``), which TestPinnedConnection
    exercises against real local servers."""
    calls = []
    answers = []

    def post(url, addresses, body, headers):
        calls.append(
            {
                "url": url,
                "addresses": addresses,
                "body": body.decode(),
                "headers": headers,
            }
        )
        answer = answers.pop(0) if answers else 200
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(webhooks, "_post", post)
    return calls, answers


@pytest.fixture
def hook(db_session):
    def _hook(
        events=("scan.completed",), url="https://hooks.example.com/vigie", **fields
    ):
        webhook = Webhook(
            name="SOC", url=url, events=list(events), secret="whsec_test", **fields
        )
        seal(webhook)
        db_session.add(webhook)
        db_session.commit()
        return webhook

    return _hook


def deliveries(db_session, **filters):
    return db_session.query(WebhookDelivery).filter_by(**filters).all()


def scan_job(db_session):
    job = ScanJob(scan_type="nessus", filename="weekly.nessus", status=ScanStatus.running)
    db_session.add(job)
    db_session.commit()
    return job


class TestEmit:
    def test_queues_one_delivery_per_subscribed_webhook(self, db_session, hook):
        first = hook(events=["scan.completed", "ticket.created"])
        second = hook(events=["scan.completed"])
        hook(events=["ticket.created"])
        hook(events=["scan.completed"], enabled=False)

        queued = emit(db_session, "scan.completed", {"scan": {"id": 1}})
        db_session.commit()

        assert queued == 2
        rows = deliveries(db_session)
        assert {row.webhook_id for row in rows} == {first.id, second.id}
        # One event, one id: the receiver deduplicates on it across retries.
        assert len({row.event_id for row in rows}) == 1
        body = json.loads(rows[0].body)
        assert body["event"] == "scan.completed"
        assert body["id"] == rows[0].event_id
        assert body["data"] == {"scan": {"id": 1}}

    def test_an_unknown_event_is_a_bug(self, db_session):
        with pytest.raises(ValueError):
            emit(db_session, "scan.exploded", {})

    def test_nothing_is_queued_for_another_instance(self, db_session, hook, monkeypatch):
        """A staging restored from production has its own signing key."""
        hook()
        monkeypatch.setattr(settings, "SECRET_KEY", OTHER_KEY)

        assert emit(db_session, "scan.completed", {}) == 0


class TestSeal:
    def test_a_rotated_key_still_recognises_its_webhooks(
        self, db_session, hook, monkeypatch
    ):
        webhook = hook()
        old_key = settings.SECRET_KEY
        monkeypatch.setattr(settings, "SECRET_KEY", OTHER_KEY)
        monkeypatch.setattr(settings, "PREVIOUS_SECRET_KEYS", {"k1": old_key})
        assert seal_state(webhook) == "previous"

        assert reseal_webhooks(db_session) == 1

        assert seal_state(webhook) == "current"

    def test_a_url_changed_in_the_database_breaks_the_seal(self, db_session, hook):
        webhook = hook()
        webhook.url = "https://attacker.example.net/collect"

        assert seal_state(webhook) == "foreign"


class TestTargets:
    @pytest.mark.parametrize(
        "url",
        [
            "http://hooks.example.com/x",
            "ftp://hooks.example.com/x",
            "https:///no-host",
            "https://user:pass@hooks.example.com/x",
            "https://127.0.0.1/x",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/x",
            "https://10.1.2.3/x",
        ],
    )
    def test_refused_by_default(self, url):
        with pytest.raises(TargetRefused):
            check_url(url)

    def test_private_and_http_receivers_can_be_allowed(self, monkeypatch):
        monkeypatch.setattr(settings, "WEBHOOK_ALLOW_PRIVATE_TARGETS", True)
        monkeypatch.setattr(settings, "WEBHOOK_ALLOW_HTTP", True)

        assert check_url("http://10.1.2.3/hook") == "http://10.1.2.3/hook"
        # Never the instance itself nor the cloud metadata, even then.
        for url in ("http://127.0.0.1/x", "http://169.254.169.254/x"):
            with pytest.raises(TargetRefused):
                check_url(url)

    def test_a_name_resolving_to_a_private_address_is_not_called(
        self, db_session, hook, receiver, resolve
    ):
        calls, _ = receiver
        hook(url="https://internal.example.com/hook")
        resolve["internal.example.com"] = "10.0.0.5"
        emit(db_session, "scan.completed", {})
        db_session.commit()

        run = deliver_due(db_session)

        assert calls == []
        assert run.failed == 1
        assert "private" in deliveries(db_session)[0].last_error

    def test_a_rebinding_dns_cannot_redirect_the_request(
        self, db_session, hook, receiver, monkeypatch
    ):
        """A DNS that answers a public address to the check, then a private
        one to the connection. There is a single lookup per attempt, and the
        connection is given the addresses it returned."""
        calls, _ = receiver
        answers = iter([PUBLIC_IP, "10.0.0.5"])
        lookups = []

        def getaddrinfo(host, port, *args, **kwargs):
            lookups.append(address := next(answers))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))]

        monkeypatch.setattr(webhooks.socket, "getaddrinfo", getaddrinfo)
        hook()
        emit(db_session, "scan.completed", {})
        db_session.commit()

        assert deliver_due(db_session).delivered == 1
        assert lookups == [PUBLIC_IP]
        assert calls[0]["addresses"] == [PUBLIC_IP]


class TestDelivery:
    def test_signs_what_it_sends(self, db_session, hook, receiver):
        calls, _ = receiver
        webhook = hook()
        emit(db_session, "scan.completed", {"scan": {"id": 7}})
        db_session.commit()

        run = deliver_due(db_session)

        assert run.delivered == 1
        (call,) = calls
        headers = call["headers"]
        assert headers["X-Vigie-Event"] == "scan.completed"
        signed = f"{headers['X-Vigie-Timestamp']}.{call['body']}".encode()
        expected = hmac.new(b"whsec_test", signed, hashlib.sha256).hexdigest()
        assert headers["X-Vigie-Signature"] == f"sha256={expected}"
        assert headers["X-Vigie-Delivery"] == json.loads(call["body"])["id"]
        # Sent to the address checked, not to a second lookup.
        assert call["addresses"] == [PUBLIC_IP]
        delivery = deliveries(db_session)[0]
        assert delivery.status == DeliveryStatus.delivered.value
        assert webhook.last_success_at is not None

    def test_a_failure_is_retried_later_then_abandoned(self, db_session, hook, receiver):
        calls, answers = receiver
        hook()
        emit(db_session, "scan.completed", {})
        db_session.commit()
        delivery = deliveries(db_session)[0]

        answers.append(503)
        before = datetime.now(UTC)
        assert deliver_due(db_session).retrying == 1
        assert delivery.status == DeliveryStatus.pending.value
        assert delivery.last_error == "HTTP 503"
        wait = _aware(delivery.next_attempt_at) - before
        assert RETRY_DELAYS[0] <= wait < RETRY_DELAYS[0] + timedelta(seconds=5)
        # Not due yet: the next run leaves it alone.
        assert deliver_due(db_session).retrying == 0

        # Whatever breaks (connection, TLS, the OS), the run goes on.
        errors = [
            urllib3.exceptions.ProtocolError("Connection aborted."),
            urllib3.exceptions.SSLError("certificate verify failed"),
            ConnectionRefusedError("refused"),
        ]
        for attempt, _ in enumerate(RETRY_DELAYS):
            answers.append(errors[attempt % len(errors)])
            delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
            db_session.commit()
            deliver_due(db_session)

        assert delivery.status == DeliveryStatus.failed.value
        assert delivery.attempts == len(RETRY_DELAYS) + 1
        assert len(calls) == len(RETRY_DELAYS) + 1

    def test_a_key_rotation_does_not_strand_the_deliveries(
        self, db_session, hook, receiver, monkeypatch
    ):
        """The worker sends with the new key and the old one retired: it must
        know the retired key (PREVIOUS_SECRET_KEYS), or it gives up on every
        webhook as registered by another instance."""
        calls, _ = receiver
        webhook = hook()
        emit(db_session, "scan.completed", {})
        db_session.commit()
        old_key = settings.SECRET_KEY
        monkeypatch.setattr(settings, "SECRET_KEY", OTHER_KEY)
        monkeypatch.setattr(settings, "PREVIOUS_SECRET_KEYS", {"k1": old_key})

        assert deliver_due(db_session).delivered == 1
        assert len(calls) == 1
        # Resealed on the way: still sent once the old key is dropped.
        assert seal_state(webhook) == "current"

    def test_a_disabled_webhook_sends_nothing(self, db_session, hook, receiver):
        calls, _ = receiver
        webhook = hook()
        emit(db_session, "scan.completed", {})
        webhook.enabled = False
        db_session.commit()

        assert deliver_due(db_session).failed == 1
        assert calls == []

    def test_purge_keeps_what_is_still_owed(self, db_session, hook):
        hook()
        old = datetime.now(UTC) - timedelta(days=settings.WEBHOOK_RETENTION_DAYS + 1)
        for status in DeliveryStatus:
            emit(db_session, "scan.completed", {})
            db_session.flush()
            row = (
                db_session.query(WebhookDelivery)
                .order_by(WebhookDelivery.id.desc())
                .first()
            )
            row.status = status.value
            row.created_at = old
        db_session.commit()

        assert purge_deliveries(db_session) == 2
        assert [row.status for row in deliveries(db_session)] == ["pending"]


class TestEvents:
    def test_a_successful_scan_is_announced(self, db_session, hook):
        hook(events=["scan.completed"])
        job = scan_job(db_session)

        class Result:
            processed_records = 12
            new_assets = 1
            new_vulnerabilities = 2
            new_associations = 3
            reopened = 0
            auto_remediated = 4
            message = ""

        tasks._apply_result(db_session, job.id, Result())

        (delivery,) = deliveries(db_session, event="scan.completed")
        scan = json.loads(delivery.body)["data"]["scan"]
        assert (scan["filename"], scan["status"], scan["auto_remediated"]) == (
            "weekly.nessus",
            "Success",
            4,
        )

    def test_new_kev_entries_with_open_findings_are_announced_once(
        self, db_session, hook
    ):
        hook(events=["threat.kev_listed"])
        asset = Asset(ip_address="10.50.0.1")
        exposed = Vulnerability(
            cve_id="CVE-2024-0001", title="A", cvss_score=6.0, severity="Medium"
        )
        unexposed = Vulnerability(
            cve_id="CVE-2024-0002", title="B", cvss_score=6.0, severity="Medium"
        )
        db_session.add_all([asset, exposed, unexposed])
        db_session.flush()
        db_session.add(
            AssetVulnerability(
                asset_id=asset.id, vulnerability_id=exposed.id, status=Status.open
            )
        )
        db_session.add(
            AssetVulnerability(
                asset_id=asset.id, vulnerability_id=unexposed.id, status=Status.remediated
            )
        )
        db_session.commit()
        catalog = KevCatalog(
            version="1",
            released=date(2026, 9, 25),
            entries={
                cve: KevEntry(cve, date_added=date(2024, 1, 10))
                for cve in ("CVE-2024-0001", "CVE-2024-0002")
            },
        )

        apply_kev(db_session, catalog, source="network", now=datetime.now(UTC))

        (delivery,) = deliveries(db_session, event="threat.kev_listed")
        data = json.loads(delivery.body)["data"]
        assert data["total"] == 1
        assert [(c["cve_id"], c["reason"], c["open_findings"]) for c in data["cves"]] == [
            ("CVE-2024-0001", "listed", 1)
        ]


class TestSchedule:
    def test_delivery_runs_only_when_enabled(self, monkeypatch):
        assert "webhook-delivery" in build_beat_schedule()
        monkeypatch.setattr(settings, "WEBHOOKS_ENABLED", False)
        assert "webhook-delivery" not in build_beat_schedule()

    def test_the_task_does_nothing_when_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "WEBHOOKS_ENABLED", False)
        assert tasks.deliver_webhooks_task()["status"] == "skipped"


class _Recorder(BaseHTTPRequestHandler):
    def do_POST(self):
        self.server.requests.append(
            {
                "path": self.path,
                "host": self.headers["Host"],
                "body": self.rfile.read(int(self.headers["Content-Length"])),
            }
        )
        self.send_response(self.server.status)
        if self.server.status == 302:
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class _Server(HTTPServer):
    def __init__(self, context=None):
        super().__init__(("127.0.0.1", 0), _Recorder)
        self.requests, self.status, self.server_names = [], 204, []
        if context is not None:
            context.sni_callback = lambda sock, name, ctx: self.server_names.append(name)
            self.socket = context.wrap_socket(self.socket, server_side=True)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]

    def handle_error(self, request, client_address):
        pass  # a client refusing the certificate resets the connection

    def stop(self):
        self.shutdown()
        self.server_close()


@pytest.fixture
def http_server():
    server = _Server()
    yield server
    server.stop()


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    """A certificate authority and a certificate for hooks.example.test."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl is needed to make a test certificate authority")
    directory = tmp_path_factory.mktemp("tls")
    (directory / "ca.cnf").write_text(
        "[req]\ndistinguished_name = dn\n[dn]\n[ca]\n"
        "basicConstraints = critical, CA:TRUE\n"
        "keyUsage = critical, keyCertSign, cRLSign\n"
        "subjectKeyIdentifier = hash\n"
    )
    (directory / "leaf.ext").write_text(
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature, keyEncipherment\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = DNS:hooks.example.test\n"
        "subjectKeyIdentifier = hash\n"
        "authorityKeyIdentifier = keyid\n"
    )

    def openssl(*args):
        subprocess.run(  # noqa: S603 — fixed arguments, test only
            ["openssl", *args], cwd=directory, check=True, capture_output=True
        )

    openssl(
        "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Vigie test CA",
        "-config", "ca.cnf", "-extensions", "ca",
    )  # fmt: skip
    openssl(
        "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "leaf.key",
        "-out", "leaf.csr", "-subj", "/CN=hooks.example.test",
    )  # fmt: skip
    openssl(
        "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-days", "1", "-out", "leaf.pem", "-extfile", "leaf.ext",
    )  # fmt: skip
    return directory


@pytest.fixture
def tls_server(tls_files):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(tls_files / "leaf.pem", tls_files / "leaf.key")
    server = _Server(context)
    yield server
    server.stop()


class TestPinnedConnection:
    """The real connection, against local servers. The URLs name hosts under
    .test, which never resolve: a request that arrives went to the address
    given, not to a DNS lookup."""

    @pytest.fixture(autouse=True)
    def no_proxy_from_the_host(self, monkeypatch):
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
            monkeypatch.delenv(name, raising=False)
            monkeypatch.delenv(name.lower(), raising=False)
        for name in ("REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(name, raising=False)

    def test_goes_to_the_address_given_with_the_host_named(self, http_server):
        url = f"http://hooks.example.test:{http_server.port}/in?source=vigie"

        status = webhooks._post(url, ["127.0.0.1"], b'{"a":1}', {"X-Vigie-Event": "ping"})

        assert status == 204
        assert http_server.requests == [
            {
                "path": "/in?source=vigie",
                "host": f"hooks.example.test:{http_server.port}",
                "body": b'{"a":1}',
            }
        ]

    def test_a_redirect_is_not_followed(self, http_server):
        http_server.status = 302
        url = f"http://hooks.example.test:{http_server.port}/in"

        assert webhooks._post(url, ["127.0.0.1"], b"{}", {}) == 302
        assert len(http_server.requests) == 1

    def test_the_next_address_is_tried_when_one_refuses(self, http_server):
        # The server listens on IPv4 only: ::1 refuses (or is unreachable).
        url = f"http://hooks.example.test:{http_server.port}/in"

        assert webhooks._post(url, ["::1", "127.0.0.1"], b"{}", {}) == 204
        with pytest.raises(urllib3.exceptions.NewConnectionError):
            webhooks._post(url, ["::1"], b"{}", {})

    def test_https_names_the_host_and_checks_its_certificate(self, tls_server, tls_files):
        url = f"https://hooks.example.test:{tls_server.port}/in"

        status = webhooks._post(
            url, ["127.0.0.1"], b"{}", {}, ca_certs=str(tls_files / "ca.pem")
        )

        assert status == 204
        assert tls_server.server_names == ["hooks.example.test"]
        assert tls_server.requests[0]["host"] == f"hooks.example.test:{tls_server.port}"

    def test_https_refuses_a_certificate_for_another_name(self, tls_server, tls_files):
        url = f"https://other.example.test:{tls_server.port}/in"

        with pytest.raises(urllib3.exceptions.SSLError):
            webhooks._post(
                url, ["127.0.0.1"], b"{}", {}, ca_certs=str(tls_files / "ca.pem")
            )
        assert tls_server.requests == []

    def test_https_refuses_an_unknown_authority(self, tls_server):
        url = f"https://hooks.example.test:{tls_server.port}/in"

        with pytest.raises(urllib3.exceptions.SSLError):
            webhooks._post(url, ["127.0.0.1"], b"{}", {})
        assert tls_server.requests == []

    def test_an_internal_authority_comes_from_requests_ca_bundle(
        self, tls_server, tls_files, monkeypatch
    ):
        """As for the threat feeds: REQUESTS_CA_BUNDLE names the internal CA."""
        monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tls_files / "ca.pem"))
        url = f"https://hooks.example.test:{tls_server.port}/in"

        assert webhooks._post(url, ["127.0.0.1"], b"{}", {}) == 204

    def test_an_outbound_proxy_is_used_when_configured(self, http_server, monkeypatch):
        # The local server plays the proxy: it receives the absolute URL.
        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{http_server.port}")
        url = "http://hooks.example.test:8080/in"

        assert webhooks._post(url, ["192.0.2.1"], b"{}", {}) == 204
        assert http_server.requests[0]["path"] == url
        assert http_server.requests[0]["host"] == "hooks.example.test:8080"

    def test_no_proxy_keeps_the_connection_pinned(self, http_server, monkeypatch):
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")  # would refuse
        monkeypatch.setenv("NO_PROXY", "hooks.example.test")
        url = f"http://hooks.example.test:{http_server.port}/in"

        assert webhooks._post(url, ["127.0.0.1"], b"{}", {}) == 204
        assert http_server.requests[0]["path"] == "/in"


def _aware(moment):
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
