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
