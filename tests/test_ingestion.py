import pytest

from app.core.config import settings
from app.models.asset import Asset, Criticality
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.services.ingestion import ingest_findings


def finding(ip="10.0.0.1", cve="CVE-2024-0001", cvss=7.5, severity="High", **kwargs):
    base = {
        "ip_address": ip,
        "hostname": "srv-01",
        "operating_system": "Ubuntu 22.04",
        "cve_id": cve,
        "title": "Test vulnerability",
        "description": "Description",
        "cvss_score": cvss,
        "severity": severity,
    }
    base.update(kwargs)
    return base


class TestIngestion:
    def test_empty_findings_is_a_no_op(self, db_session):
        result = ingest_findings(db_session, [], "nessus")
        assert result.processed_records == 0
        assert result.message == "No findings in scan file"

    def test_creates_assets_vulns_and_links(self, db_session):
        result = ingest_findings(db_session, [finding()], "nessus")

        assert result.new_assets == 1
        assert result.new_vulnerabilities == 1
        assert result.new_associations == 1

        link = db_session.query(AssetVulnerability).one()
        assert link.status == Status.open
        assert link.scan_source == "nessus"
        assert link.remediation_deadline is not None

    def test_computes_a_risk_score(self, db_session):
        """Regression: risk_scoring existed but was never wired into ingestion,
        so every finding was stored with no score at all."""
        ingest_findings(db_session, [finding(cvss=6.0)], "nessus")

        link = db_session.query(AssetVulnerability).one()
        # Medium criticality (the default for a discovered asset) -> 1.0x
        assert link.risk_score == 6.0

    def test_risk_score_reflects_asset_criticality(self, db_session):
        db_session.add(
            Asset(ip_address="10.0.0.9", business_criticality=Criticality.critical)
        )
        db_session.commit()

        ingest_findings(db_session, [finding(ip="10.0.0.9", cvss=6.0)], "nessus")

        link = db_session.query(AssetVulnerability).one()
        assert link.risk_score == 9.0  # 6.0 * 1.5

    def test_is_idempotent(self, db_session):
        findings = [finding()]
        ingest_findings(db_session, findings, "nessus")
        second = ingest_findings(db_session, findings, "nessus")

        assert second.new_assets == 0
        assert second.new_vulnerabilities == 0
        assert second.new_associations == 0
        assert db_session.query(AssetVulnerability).count() == 1

    def test_rescan_refreshes_last_seen(self, db_session):
        ingest_findings(db_session, [finding()], "nessus")
        first_seen = db_session.query(AssetVulnerability).one().last_seen_at

        ingest_findings(db_session, [finding()], "openvas")
        link = db_session.query(AssetVulnerability).one()

        assert link.last_seen_at >= first_seen
        assert link.scan_source == "openvas"

    def test_remediated_finding_is_reopened_when_seen_again(self, db_session):
        ingest_findings(db_session, [finding()], "nessus")
        link = db_session.query(AssetVulnerability).one()
        link.status = Status.remediated
        db_session.commit()

        result = ingest_findings(db_session, [finding()], "nessus")

        assert result.reopened == 1
        db_session.refresh(link)
        assert link.status == Status.open
        assert link.fixed_at is None

    def test_risk_accepted_finding_stays_accepted(self, db_session):
        """A triage decision must survive a rescan."""
        ingest_findings(db_session, [finding()], "nessus")
        link = db_session.query(AssetVulnerability).one()
        link.status = Status.risk_accepted
        db_session.commit()

        ingest_findings(db_session, [finding()], "nessus")

        db_session.refresh(link)
        assert link.status == Status.risk_accepted

    def test_enriches_existing_asset_without_overwriting(self, db_session):
        db_session.add(Asset(ip_address="10.0.0.1", hostname="curated-name"))
        db_session.commit()

        ingest_findings(db_session, [finding()], "nessus")

        asset = db_session.query(Asset).filter(Asset.ip_address == "10.0.0.1").one()
        assert asset.hostname == "curated-name"  # not clobbered
        assert asset.operating_system == "Ubuntu 22.04"  # filled in

    def test_deduplicates_within_a_single_batch(self, db_session):
        findings = [finding(), finding(), finding(cve="CVE-2024-0002")]
        result = ingest_findings(db_session, findings, "nessus")

        assert result.new_assets == 1
        assert result.new_vulnerabilities == 2
        assert result.new_associations == 2
        assert result.processed_records == 3

    def test_handles_multiple_assets(self, db_session):
        findings = [
            finding(ip="10.0.0.1", cve="CVE-2024-0001"),
            finding(ip="10.0.0.2", cve="CVE-2024-0001"),
            finding(ip="10.0.0.3", cve="CVE-2024-0002"),
        ]
        result = ingest_findings(db_session, findings, "openvas")

        assert result.new_assets == 3
        assert result.new_vulnerabilities == 2
        assert result.new_associations == 3
        assert db_session.query(Vulnerability).count() == 2


class TestAssetDeduplication:
    """Matching on the address alone made a DHCP host spawn a new asset — and a
    fresh copy of its whole backlog — every time its lease changed."""

    def test_host_that_changed_address_is_not_duplicated(self, db_session):
        ingest_findings(db_session, [finding(ip="10.0.0.1", hostname="srv-01")], "nessus")
        ingest_findings(db_session, [finding(ip="10.0.0.9", hostname="srv-01")], "nessus")

        assets = db_session.query(Asset).all()
        assert len(assets) == 1
        assert assets[0].ip_address == "10.0.0.9"

    def test_findings_follow_the_host_across_addresses(self, db_session):
        ingest_findings(db_session, [finding(ip="10.0.0.1", hostname="srv-01")], "nessus")
        ingest_findings(db_session, [finding(ip="10.0.0.9", hostname="srv-01")], "nessus")

        # The same CVE on the same host must stay a single finding.
        assert db_session.query(AssetVulnerability).count() == 1

    def test_shared_hostname_in_one_scan_does_not_merge_hosts(self, db_session):
        """Several addresses answering to one name in a single scan proves the
        name is not unique ("localhost", "ubuntu"): those must stay distinct."""
        ingest_findings(
            db_session,
            [
                finding(ip="10.0.0.1", hostname="localhost", cve="CVE-2024-0001"),
                finding(ip="10.0.0.2", hostname="localhost", cve="CVE-2024-0001"),
            ],
            "nessus",
        )
        assert db_session.query(Asset).count() == 2

    def test_asset_known_by_address_is_enriched_not_duplicated(self, db_session):
        db_session.add(Asset(ip_address="10.0.0.1"))
        db_session.commit()

        ingest_findings(db_session, [finding(ip="10.0.0.1", hostname="srv-01")], "nessus")

        assets = db_session.query(Asset).all()
        assert len(assets) == 1
        assert assets[0].hostname == "srv-01"

    def test_hostname_matching_is_case_insensitive(self, db_session):
        ingest_findings(db_session, [finding(ip="10.0.0.1", hostname="SRV-01")], "nessus")
        ingest_findings(db_session, [finding(ip="10.0.0.9", hostname="srv-01")], "nessus")

        assert db_session.query(Asset).count() == 1


class TestCriticalityRules:
    def test_criticality_comes_from_the_subnet(self, db_session, monkeypatch):
        monkeypatch.setattr(
            settings,
            "CRITICALITY_RULES",
            {"10.0.0.0/8": "Low", "10.0.5.0/24": "Critical"},
        )

        ingest_findings(
            db_session,
            [
                finding(ip="10.0.5.7", cve="CVE-2024-0001"),
                finding(ip="10.9.9.9", cve="CVE-2024-0002", hostname="other-host"),
            ],
            "nessus",
        )

        by_ip = {a.ip_address: a for a in db_session.query(Asset).all()}
        # The most specific prefix wins over the broad default.
        assert by_ip["10.0.5.7"].business_criticality == Criticality.critical
        assert by_ip["10.9.9.9"].business_criticality == Criticality.low

    def test_unmatched_address_falls_back_to_medium(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "CRITICALITY_RULES", {"192.168.0.0/16": "Critical"})

        ingest_findings(db_session, [finding(ip="10.0.0.1")], "nessus")

        asset = db_session.query(Asset).one()
        assert asset.business_criticality == Criticality.medium

    def test_malformed_rule_is_ignored(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "CRITICALITY_RULES", {"not-a-cidr": "Critical"})

        ingest_findings(db_session, [finding(ip="10.0.0.1")], "nessus")

        assert db_session.query(Asset).one().business_criticality == Criticality.medium


class TestAutomaticClosure:
    """A patched host used to leave its findings open forever, so the backlog
    drifted away from reality."""

    @pytest.fixture(autouse=True)
    def threshold(self, monkeypatch):
        monkeypatch.setattr(settings, "AUTO_REMEDIATE_AFTER_MISSES", 2)

    def test_finding_closes_after_enough_misses(self, db_session):
        ingest_findings(db_session, [finding()], "nessus")

        # Two later scans of the same source no longer report it.
        for _ in range(settings.AUTO_REMEDIATE_AFTER_MISSES):
            ingest_findings(
                db_session,
                [finding(ip="10.0.0.2", cve="CVE-2024-9999", hostname="other")],
                "nessus",
            )

        closed = db_session.query(AssetVulnerability).filter_by(vulnerability_id=1).one()
        assert closed.status == Status.remediated
        assert closed.fixed_at is not None

    def test_one_miss_is_not_enough(self, db_session):
        """A partial or failed scan must not close everything it did not cover."""
        ingest_findings(db_session, [finding()], "nessus")
        ingest_findings(
            db_session,
            [finding(ip="10.0.0.2", cve="CVE-2024-9999", hostname="other")],
            "nessus",
        )

        still_open = (
            db_session.query(AssetVulnerability).filter_by(vulnerability_id=1).one()
        )
        assert still_open.status == Status.open
        assert still_open.missed_scans == 1

    def test_reappearing_finding_resets_the_counter(self, db_session):
        ingest_findings(db_session, [finding()], "nessus")
        ingest_findings(
            db_session,
            [finding(ip="10.0.0.2", cve="CVE-2024-9999", hostname="other")],
            "nessus",
        )
        ingest_findings(db_session, [finding()], "nessus")

        refreshed = (
            db_session.query(AssetVulnerability).filter_by(vulnerability_id=1).one()
        )
        assert refreshed.missed_scans == 0
        assert refreshed.status == Status.open

    def test_other_sources_are_left_alone(self, db_session):
        """An OpenVAS scan says nothing about what Nessus reported."""
        ingest_findings(db_session, [finding()], "nessus")

        for _ in range(settings.AUTO_REMEDIATE_AFTER_MISSES):
            ingest_findings(
                db_session,
                [finding(ip="10.0.0.2", cve="CVE-2024-9999", hostname="other")],
                "openvas",
            )

        untouched = (
            db_session.query(AssetVulnerability).filter_by(vulnerability_id=1).one()
        )
        assert untouched.status == Status.open
        assert untouched.missed_scans == 0

    def test_closure_can_be_disabled(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "AUTO_REMEDIATE_AFTER_MISSES", 0)

        ingest_findings(db_session, [finding()], "nessus")
        for _ in range(3):
            ingest_findings(
                db_session,
                [finding(ip="10.0.0.2", cve="CVE-2024-9999", hostname="other")],
                "nessus",
            )

        assert (
            db_session.query(AssetVulnerability)
            .filter_by(vulnerability_id=1)
            .one()
            .status
            == Status.open
        )

    def test_result_reports_what_was_closed(self, db_session):
        ingest_findings(db_session, [finding()], "nessus")

        result = None
        for _ in range(settings.AUTO_REMEDIATE_AFTER_MISSES):
            result = ingest_findings(
                db_session,
                [finding(ip="10.0.0.2", cve="CVE-2024-9999", hostname="other")],
                "nessus",
            )

        assert result.auto_remediated == 1
        assert result.as_dict()["auto_remediated"] == 1
