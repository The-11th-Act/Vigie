"""Applying the KEV and EPSS feeds: what changes, and what must not.

Replayed against the test database with a fake feed client: no network. The
invariants that matter are the guards — a failed or suspicious feed must never
erase good data — and that only findings whose score can move get rescored.
"""

import gzip
import json
import logging
from datetime import UTC, date, datetime, timedelta

import pytest
import requests

from app.core.config import settings
from app.models.asset import Asset, Criticality
from app.models.threat_intel import FEED_EPSS, FEED_KEV, ThreatFeedStatus
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.parsers.threat_feeds import (
    EpssScore,
    EpssSnapshot,
    KevCatalog,
    KevEntry,
    ThreatFeedError,
)
from app.services.threat_intel import (
    FeedRejected,
    apply_epss,
    apply_kev,
    import_feed,
    refresh_threat_intel,
)

NOW = datetime(2026, 9, 25, 6, 15, tzinfo=UTC)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("a test tried to reach the network")

    monkeypatch.setattr(requests.Session, "request", refuse)


@pytest.fixture
def track(db_session):
    """Create a tracked CVE with one open finding on a Medium asset."""
    counter = iter(range(1, 1000))

    def _track(cve, cvss=6.0, status=Status.open, risk_score=None, **vuln_fields):
        n = next(counter)
        asset = Asset(ip_address=f"10.40.0.{n}", business_criticality=Criticality.medium)
        vuln = Vulnerability(
            cve_id=cve, title=cve, cvss_score=cvss, severity="Medium", **vuln_fields
        )
        db_session.add_all([asset, vuln])
        db_session.flush()
        finding = AssetVulnerability(
            asset_id=asset.id,
            vulnerability_id=vuln.id,
            status=status,
            risk_score=cvss if risk_score is None else risk_score,
            detected_at=NOW - timedelta(days=1),
            remediation_deadline=NOW + timedelta(days=89),
        )
        db_session.add(finding)
        db_session.commit()
        return finding

    return _track


def catalog(*cves, version="2026.09.25", released=date(2026, 9, 25), ransomware=()):
    return KevCatalog(
        version=version,
        released=released,
        entries={
            cve: KevEntry(cve, date_added=date(2024, 1, 10), ransomware=cve in ransomware)
            for cve in cves
        },
    )


def snapshot(scores, score_date=date(2026, 9, 25)):
    return EpssSnapshot(
        model_version="v2026.06.15",
        score_date=score_date,
        scores={cve: EpssScore(score, 0.5) for cve, score in scores.items()},
        total_rows=len(scores),
    )


class TestApplyKev:
    def test_flags_the_listed_cves_we_track(self, db_session, track):
        finding = track("CVE-2024-0001")

        result = apply_kev(
            db_session,
            catalog("CVE-2024-0001", "CVE-2099-9999", ransomware={"CVE-2024-0001"}),
            source="network",
            now=NOW,
        )

        vuln = finding.vulnerability
        assert vuln.in_kev is True
        assert vuln.kev_date_added == date(2024, 1, 10)
        assert vuln.kev_ransomware is True
        assert vuln.threat_intel_updated_at is not None
        assert (result.records, result.changed) == (2, 1)
        # CVEs we do not track are not created.
        assert db_session.query(Vulnerability).count() == 1

    def test_rescores_and_tightens_newly_listed_findings(self, db_session, track):
        finding = track("CVE-2024-0001", cvss=5.0)

        result = apply_kev(
            db_session, catalog("CVE-2024-0001"), source="network", now=NOW
        )

        assert finding.risk_score == 7.0  # 5.0 x 1.3 = 6.5, raised to the floor
        assert result.rescored == 1
        deadline = finding.remediation_deadline
        deadline = deadline if deadline.tzinfo else deadline.replace(tzinfo=UTC)
        assert deadline <= NOW - timedelta(days=1) + timedelta(days=14)

    def test_leaves_unrelated_findings_alone(self, db_session, track):
        """A deliberately stale score on an unchanged CVE proves the rescoring
        is targeted, not a sweep of the whole backlog."""
        track("CVE-2024-0001")
        stale = track("CVE-2024-0002", cvss=6.0, risk_score=1.23)

        apply_kev(db_session, catalog("CVE-2024-0001"), source="network", now=NOW)

        assert stale.risk_score == 1.23

    def test_unflags_a_delisted_cve(self, db_session, track, caplog):
        finding = track("CVE-2024-0001", in_kev=True, risk_score=7.8)
        track("CVE-2024-0002")

        with caplog.at_level(logging.WARNING):
            apply_kev(db_session, catalog("CVE-2024-0002"), source="network", now=NOW)

        assert finding.vulnerability.in_kev is False
        assert finding.risk_score == 6.0
        assert "CVE-2024-0001" in caplog.text

    def test_an_unchanged_catalogue_rewrites_nothing(self, db_session, track):
        finding = track("CVE-2024-0001")
        apply_kev(db_session, catalog("CVE-2024-0001"), source="network", now=NOW)
        first_update = finding.vulnerability.threat_intel_updated_at

        result = apply_kev(
            db_session,
            catalog("CVE-2024-0001"),
            source="network",
            now=NOW + timedelta(days=1),
        )

        assert result.changed == 0
        assert finding.vulnerability.threat_intel_updated_at == first_update

    def test_records_the_feed_status(self, db_session, track):
        track("CVE-2024-0001")

        apply_kev(db_session, catalog("CVE-2024-0001"), source="import", now=NOW)

        status = db_session.get(ThreatFeedStatus, FEED_KEV)
        assert status.source == "import"
        assert status.source_version == "2026.09.25"
        assert status.source_date == date(2026, 9, 25)
        assert status.records == 1
        assert status.last_error is None

    def test_a_sharply_shrunk_catalogue_is_refused(self, db_session, track):
        """A truncated download looks exactly like CISA delisting everything."""
        finding = track("CVE-2024-0001")
        many = [f"CVE-2024-{1000 + i}" for i in range(20)]
        apply_kev(db_session, catalog("CVE-2024-0001", *many), source="network", now=NOW)

        with pytest.raises(FeedRejected, match="shrank"):
            apply_kev(db_session, catalog("CVE-2024-1000"), source="network", now=NOW)
        assert finding.vulnerability.in_kev is True

        apply_kev(
            db_session, catalog("CVE-2024-1000"), source="network", now=NOW, force=True
        )
        assert finding.vulnerability.in_kev is False

    def test_an_older_catalogue_is_refused(self, db_session, track):
        track("CVE-2024-0001")
        apply_kev(db_session, catalog("CVE-2024-0001"), source="network", now=NOW)

        with pytest.raises(FeedRejected, match="older"):
            apply_kev(
                db_session,
                catalog("CVE-2024-0001", released=date(2026, 9, 1)),
                source="import",
                now=NOW,
            )


class TestApplyEpss:
    def test_stores_the_scores_of_tracked_cves(self, db_session, track):
        finding = track("CVE-2024-0001")

        result = apply_epss(
            db_session, snapshot({"CVE-2024-0001": 0.62}), source="network", now=NOW
        )

        vuln = finding.vulnerability
        assert vuln.epss_score == pytest.approx(0.62)
        assert vuln.epss_percentile == pytest.approx(0.5)
        assert vuln.epss_date == date(2026, 9, 25)
        assert result.changed == 1

    def test_a_band_change_rescores(self, db_session, track):
        finding = track("CVE-2024-0001", cvss=6.0)

        result = apply_epss(
            db_session, snapshot({"CVE-2024-0001": 0.62}), source="network", now=NOW
        )

        assert finding.risk_score == 7.8  # 6.0 x 1.3
        assert result.rescored == 1

    def test_a_move_within_a_band_does_not_rescore(self, db_session, track):
        """EPSS drifts daily for almost every CVE; only a band change matters."""
        finding = track("CVE-2024-0001", epss_score=0.03, risk_score=1.23)

        result = apply_epss(
            db_session, snapshot({"CVE-2024-0001": 0.04}), source="network", now=NOW
        )

        assert result.changed == 1
        assert result.rescored == 0
        assert finding.risk_score == 1.23

    def test_a_kev_entry_ignores_epss(self, db_session, track):
        finding = track("CVE-2024-0001", in_kev=True, risk_score=1.23)

        result = apply_epss(
            db_session, snapshot({"CVE-2024-0001": 0.9}), source="network", now=NOW
        )

        assert result.rescored == 0
        assert finding.risk_score == 1.23

    def test_a_cve_missing_from_the_file_keeps_its_score(self, db_session, track):
        finding = track("CVE-2024-0001", epss_score=0.3)

        apply_epss(
            db_session, snapshot({"CVE-2099-0001": 0.1}), source="network", now=NOW
        )

        assert finding.vulnerability.epss_score == pytest.approx(0.3)

    def test_an_older_snapshot_is_refused_unless_forced(self, db_session, track):
        finding = track("CVE-2024-0001")
        apply_epss(
            db_session, snapshot({"CVE-2024-0001": 0.2}), source="network", now=NOW
        )
        older = snapshot({"CVE-2024-0001": 0.9}, score_date=date(2026, 9, 20))

        with pytest.raises(FeedRejected):
            apply_epss(db_session, older, source="import", now=NOW)
        assert finding.vulnerability.epss_score == pytest.approx(0.2)

        apply_epss(db_session, older, source="import", now=NOW, force=True)
        assert finding.vulnerability.epss_score == pytest.approx(0.9)


class FakeClient:
    def __init__(self, bodies):
        self.bodies = bodies

    def get(self, url):
        body = self.bodies[url]
        if isinstance(body, Exception):
            raise body
        return body


def kev_json(*cves):
    return json.dumps(
        {
            "catalogVersion": "2026.09.25",
            "dateReleased": "2026-09-25",
            "vulnerabilities": [
                {"cveID": cve, "dateAdded": "2024-01-10"} for cve in cves
            ],
        }
    ).encode()


def epss_gz(rows):
    lines = ["#model_version:v2026.06.15,score_date:2026-09-25T00:00:00+0000"]
    lines += ["cve,epss,percentile"] + [
        f"{cve},{score},0.5" for cve, score in rows.items()
    ]
    return gzip.compress("\n".join(lines).encode())


class TestRefresh:
    def test_applies_both_feeds(self, db_session, track):
        finding = track("CVE-2024-0001")
        client = FakeClient(
            {
                settings.THREAT_INTEL_KEV_URL: kev_json("CVE-2024-0001"),
                settings.THREAT_INTEL_EPSS_URL: epss_gz({"CVE-2024-0001": 0.7}),
            }
        )

        result = refresh_threat_intel(db_session, client=client, now=NOW)

        assert result.ok
        assert finding.vulnerability.in_kev is True
        assert finding.vulnerability.epss_score == pytest.approx(0.7)
        assert set(result.as_dict()) == {FEED_KEV, FEED_EPSS}

    def test_one_failing_feed_keeps_its_data_and_spares_the_other(
        self, db_session, track
    ):
        finding = track("CVE-2024-0001", in_kev=True)
        client = FakeClient(
            {
                settings.THREAT_INTEL_KEV_URL: ThreatFeedError("HTTP 503"),
                settings.THREAT_INTEL_EPSS_URL: epss_gz({"CVE-2024-0001": 0.7}),
            }
        )

        result = refresh_threat_intel(db_session, client=client, now=NOW)

        assert not result.ok
        assert result.as_dict()[FEED_KEV]["status"] == "failed"
        # The KEV flag survives the failed pull; EPSS went through regardless.
        assert finding.vulnerability.in_kev is True
        assert finding.vulnerability.epss_score == pytest.approx(0.7)
        status = db_session.get(ThreatFeedStatus, FEED_KEV)
        assert "503" in status.last_error
        assert status.last_success_at is None

    def test_a_malformed_feed_is_recorded_not_applied(self, db_session, track):
        track("CVE-2024-0001")
        client = FakeClient(
            {
                settings.THREAT_INTEL_KEV_URL: b"<html>maintenance</html>",
                settings.THREAT_INTEL_EPSS_URL: epss_gz({"CVE-2024-0001": 0.7}),
            }
        )

        result = refresh_threat_intel(db_session, client=client, now=NOW)

        assert result.as_dict()[FEED_KEV]["status"] == "failed"
        assert "JSON" in db_session.get(ThreatFeedStatus, FEED_KEV).last_error


class TestImportFeed:
    def test_imports_a_kev_file(self, db_session, track):
        finding = track("CVE-2024-0001")

        result = import_feed(db_session, FEED_KEV, kev_json("CVE-2024-0001"), now=NOW)

        assert result.status == "applied"
        assert finding.vulnerability.in_kev is True
        assert db_session.get(ThreatFeedStatus, FEED_KEV).source == "import"

    def test_imports_an_epss_file(self, db_session, track):
        finding = track("CVE-2024-0001")

        import_feed(db_session, FEED_EPSS, epss_gz({"CVE-2024-0001": 0.2}), now=NOW)

        assert finding.vulnerability.epss_score == pytest.approx(0.2)

    def test_an_unknown_feed_is_an_error(self, db_session):
        with pytest.raises(ThreatFeedError, match="Unknown feed"):
            import_feed(db_session, "nvd", b"{}")
