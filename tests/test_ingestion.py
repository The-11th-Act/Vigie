from datetime import UTC, date, timedelta

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


def link_for(db_session, cve="CVE-2024-0001"):
    """The finding for ``cve``, found by identity rather than by id: ids are
    not predictable on PostgreSQL, whose sequences survive a rollback."""
    return (
        db_session.query(AssetVulnerability)
        .join(Vulnerability)
        .filter(Vulnerability.cve_id == cve)
        .one()
    )


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

        closed = link_for(db_session)
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

        still_open = link_for(db_session)
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

        refreshed = link_for(db_session)
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

        untouched = link_for(db_session)
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

        assert link_for(db_session).status == Status.open

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


class TestScopedClosure:
    """A file-based scan only says something about the hosts it covered."""

    @pytest.fixture(autouse=True)
    def threshold(self, monkeypatch):
        monkeypatch.setattr(settings, "AUTO_REMEDIATE_AFTER_MISSES", 2)

    def other_host_scan(self, db_session):
        return ingest_findings(
            db_session,
            [finding(ip="10.0.0.2", cve="CVE-2024-9999", hostname="other")],
            "nessus",
            scanned_addresses={"10.0.0.2"},
        )

    def test_a_host_outside_the_scan_counts_no_miss(self, db_session):
        """Regression: scanning one subnet used to close another's findings."""
        ingest_findings(db_session, [finding()], "nessus")

        for _ in range(settings.AUTO_REMEDIATE_AFTER_MISSES + 1):
            self.other_host_scan(db_session)

        untouched = link_for(db_session)
        assert untouched.status == Status.open
        assert untouched.missed_scans == 0

    def test_a_clean_host_in_scope_gets_its_findings_closed(self, db_session):
        """The patched host reports nothing at all: that is the case to close."""
        ingest_findings(db_session, [finding()], "nessus")

        result = None
        for _ in range(settings.AUTO_REMEDIATE_AFTER_MISSES):
            result = ingest_findings(
                db_session, [], "nessus", scanned_addresses={"10.0.0.1"}
            )

        assert link_for(db_session).status == Status.remediated
        assert result.auto_remediated == 1
        assert result.message == "No findings in scan file"

    def test_a_scan_covering_nothing_closes_nothing(self, db_session):
        ingest_findings(db_session, [finding()], "nessus")

        for _ in range(settings.AUTO_REMEDIATE_AFTER_MISSES + 1):
            ingest_findings(db_session, [], "nessus", scanned_addresses=set())

        assert link_for(db_session).status == Status.open

    def test_an_unknown_address_in_scope_is_harmless(self, db_session):
        ingest_findings(db_session, [finding()], "nessus")

        result = ingest_findings(db_session, [], "nessus", scanned_addresses={"10.9.9.9"})

        assert result.auto_remediated == 0
        assert link_for(db_session).missed_scans == 0


class TestThreatContextAtIngestion:
    def kev_vulnerability(self, db_session, cve="CVE-2024-0001", cvss=5.0):
        vuln = Vulnerability(
            cve_id=cve,
            title="Exploited",
            cvss_score=cvss,
            severity="Medium",
            in_kev=True,
            kev_date_added=date(2024, 1, 10),
        )
        db_session.add(vuln)
        db_session.commit()
        return vuln

    def test_a_kev_finding_gets_the_floor_and_the_short_window(self, db_session):
        self.kev_vulnerability(db_session)
        db_session.add(Asset(ip_address="10.0.0.1", business_criticality=Criticality.low))
        db_session.commit()

        ingest_findings(db_session, [finding(cvss=5.0, severity="Medium")], "nessus")

        link = link_for(db_session)
        assert link.risk_score == 7.0  # 5.0 x 0.7 x 1.3 = 4.55, raised to the floor
        window = _aware(link.remediation_deadline) - _aware(link.last_seen_at)
        assert window <= timedelta(days=14)

    def test_an_open_finding_is_tightened_once_its_cve_enters_kev(self, db_session):
        ingest_findings(db_session, [finding(severity="Medium")], "nessus")
        before = _aware(link_for(db_session).remediation_deadline)

        vuln = db_session.query(Vulnerability).one()
        vuln.in_kev = True
        db_session.commit()
        ingest_findings(db_session, [finding(severity="Medium")], "nessus")

        after = _aware(link_for(db_session).remediation_deadline)
        assert after < before
        assert after - _aware(link_for(db_session).detected_at) <= timedelta(days=14)

    def test_an_internet_facing_asset_raises_the_score(self, db_session):
        db_session.add(Asset(ip_address="10.0.0.1", internet_facing=True))
        db_session.commit()

        ingest_findings(db_session, [finding(cvss=5.0)], "nessus")

        assert link_for(db_session).risk_score == 6.0  # 5.0 x 1.2

    def test_scores_from_the_stored_cvss(self, db_session):
        """Two scanners can disagree on a CVE's CVSS; the stored one is the one
        the daily rescoring uses, so ingestion must agree with it."""
        ingest_findings(db_session, [finding(cvss=6.0)], "nessus")
        ingest_findings(db_session, [finding(cvss=9.0)], "openvas")

        assert link_for(db_session).risk_score == 6.0


def _aware(value):
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class TestExposureRules:
    def test_a_new_asset_in_an_exposed_subnet_is_internet_facing(
        self, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "INTERNET_FACING_SUBNETS", ["203.0.113.0/24"])

        ingest_findings(
            db_session,
            [
                finding(ip="203.0.113.7", cve="CVE-2024-0001", hostname="edge"),
                finding(ip="10.0.0.1", cve="CVE-2024-0002", hostname="internal"),
            ],
            "nessus",
        )

        by_ip = {a.ip_address: a for a in db_session.query(Asset).all()}
        assert by_ip["203.0.113.7"].internet_facing is True
        assert by_ip["10.0.0.1"].internet_facing is False

    def test_an_operator_choice_is_never_overwritten(self, db_session, monkeypatch):
        """The rule seeds new assets; it does not fight a later manual decision."""
        monkeypatch.setattr(settings, "INTERNET_FACING_SUBNETS", ["203.0.113.0/24"])
        ingest_findings(db_session, [finding(ip="203.0.113.7")], "nessus")
        asset = db_session.query(Asset).one()
        asset.internet_facing = False
        db_session.commit()

        ingest_findings(db_session, [finding(ip="203.0.113.7")], "nessus")

        assert db_session.query(Asset).one().internet_facing is False

    def test_malformed_or_unset_rules_mean_internal(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "INTERNET_FACING_SUBNETS", ["not-a-cidr"])

        ingest_findings(db_session, [finding(ip="10.0.0.1")], "nessus")

        assert db_session.query(Asset).one().internet_facing is False
