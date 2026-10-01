"""Outgoing webhooks: what is queued, how it is sent, and where it may go.

No network: requests.post and DNS resolution are replaced in every test.
"""

import hashlib
import hmac
import json
import socket
from datetime import UTC, date, datetime, timedelta

import pytest
import requests

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


class FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code

    def close(self):
        pass


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
    """Record each POST and answer with the next queued status (200 by default)."""
    calls = []
    answers = []

    def post(url, data, headers, timeout, allow_redirects):
        calls.append(
            {
                "url": url,
                "body": data.decode(),
                "headers": headers,
                "redirects": allow_redirects,
            }
        )
        answer = answers.pop(0) if answers else 200
        if isinstance(answer, Exception):
            raise answer
        return FakeResponse(answer)

    monkeypatch.setattr(webhooks.requests, "post", post)
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
        assert call["redirects"] is False
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

        for _ in RETRY_DELAYS:
            answers.append(requests.ConnectionError("refused"))
            delivery.next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
            db_session.commit()
            deliver_due(db_session)

        assert delivery.status == DeliveryStatus.failed.value
        assert delivery.attempts == len(RETRY_DELAYS) + 1
        assert len(calls) == len(RETRY_DELAYS) + 1

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


def _aware(moment):
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
