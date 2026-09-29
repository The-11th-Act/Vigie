"""Remediation actions recorded at ingestion (KB, vendor fix per finding)."""

from app.models.remediation import FindingRemediation, RemediationAction
from app.models.vulnerability import AssetVulnerability, Vulnerability
from app.parsers.utils import remediation
from app.services.ingestion import ingest_findings


def finding(cve="CVE-2024-0001", ip="10.0.0.1", **kwargs):
    base = {
        "ip_address": ip,
        "hostname": None,
        "operating_system": "Windows Server 2019",
        "cve_id": cve,
        "title": "Test vulnerability",
        "description": None,
        "cvss_score": 8.1,
        "severity": "High",
    }
    base.update(kwargs)
    return base


def kb(reference, **kwargs):
    return remediation("kb", reference, title=f"{reference}: Security Update", **kwargs)


def references_of(db_session, cve="CVE-2024-0001", source=None):
    query = (
        db_session.query(RemediationAction.reference)
        .join(FindingRemediation, FindingRemediation.action_id == RemediationAction.id)
        .join(AssetVulnerability, AssetVulnerability.id == FindingRemediation.finding_id)
        .join(Vulnerability, Vulnerability.id == AssetVulnerability.vulnerability_id)
        .filter(Vulnerability.cve_id == cve)
    )
    if source:
        query = query.filter(FindingRemediation.source == source)
    return sorted(row.reference for row in query)


class TestRemediationLinks:
    def test_one_kb_fixing_many_cves_is_one_action(self, db_session):
        """The point of the whole feature: a rollup closing 3 CVEs on 2 hosts
        is one thing to deploy, not six."""
        rollup = [kb("KB5034441")]
        ingest_findings(
            db_session,
            [
                finding(cve=cve, ip=ip, remediations=rollup)
                for cve in ("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")
                for ip in ("10.0.0.1", "10.0.0.2")
            ],
            "nessus",
        )

        assert db_session.query(RemediationAction).count() == 1
        assert db_session.query(FindingRemediation).count() == 6
        action = db_session.query(RemediationAction).one()
        assert (action.reference, action.kind) == ("KB5034441", "kb")

    def test_versions_are_kept_per_host(self, db_session):
        fix = "nessus:171234"
        ingest_findings(
            db_session,
            [
                finding(
                    ip="10.0.0.1",
                    remediations=[
                        remediation(
                            "vendor_fix",
                            fix,
                            installed_version="2.4.52",
                            fixed_version="2.4.58",
                        )
                    ],
                ),
                finding(
                    ip="10.0.0.2",
                    remediations=[
                        remediation(
                            "vendor_fix",
                            fix,
                            installed_version="2.4.49",
                            fixed_version="2.4.58",
                        )
                    ],
                ),
            ],
            "nessus",
        )

        installed = sorted(
            link.installed_version for link in db_session.query(FindingRemediation)
        )
        assert installed == ["2.4.49", "2.4.52"]

    def test_a_superseded_update_is_replaced_on_the_next_scan(self, db_session):
        """A host still missing January's fixes is asked for February's rollup:
        listing both would send the team to deploy an obsolete update."""
        ingest_findings(db_session, [finding(remediations=[kb("KB5034441")])], "nessus")
        ingest_findings(db_session, [finding(remediations=[kb("KB5035845")])], "nessus")

        assert references_of(db_session) == ["KB5035845"]

    def test_the_same_scan_again_changes_nothing(self, db_session):
        findings = [finding(remediations=[kb("KB5034441")])]
        ingest_findings(db_session, findings, "nessus")
        ingest_findings(db_session, findings, "nessus")

        assert db_session.query(FindingRemediation).count() == 1

    def test_another_source_keeps_its_own_links(self, db_session):
        ingest_findings(db_session, [finding(remediations=[kb("KB5034441")])], "nessus")
        ingest_findings(
            db_session,
            [finding(remediations=[remediation("vendor_fix", "openvas:1.3.6.1.4.1")])],
            "openvas",
        )

        assert references_of(db_session, source="nessus") == ["KB5034441"]
        assert references_of(db_session, source="openvas") == ["openvas:1.3.6.1.4.1"]

    def test_a_source_silent_on_remediation_leaves_links_alone(self, db_session):
        """No ``remediations`` key: the source knows nothing about the fix, which
        is not the same as saying there is none."""
        ingest_findings(db_session, [finding(remediations=[kb("KB5034441")])], "nessus")
        ingest_findings(db_session, [finding()], "nessus")

        assert references_of(db_session) == ["KB5034441"]

    def test_an_empty_list_clears_the_source_links(self, db_session):
        ingest_findings(db_session, [finding(remediations=[kb("KB5034441")])], "nessus")
        ingest_findings(db_session, [finding(remediations=[])], "nessus")

        assert references_of(db_session) == []
        # The action itself stays: other findings, or history, may point at it.
        assert db_session.query(RemediationAction).count() == 1

    def test_two_plugins_on_one_pair_add_up(self, db_session):
        ingest_findings(
            db_session,
            [
                finding(remediations=[kb("KB5034441")]),
                finding(remediations=[kb("KB5034439")]),
            ],
            "nessus",
        )

        assert references_of(db_session) == ["KB5034439", "KB5034441"]

    def test_an_existing_action_only_has_its_gaps_filled(self, db_session):
        ingest_findings(
            db_session,
            [finding(remediations=[remediation("kb", "KB5034441", title="First")])],
            "nessus",
        )
        ingest_findings(
            db_session,
            [
                finding(
                    cve="CVE-2024-0002",
                    remediations=[
                        remediation(
                            "kb",
                            "KB5034441",
                            title="Second",
                            url="https://support.microsoft.com/kb/5034441",
                        )
                    ],
                )
            ],
            "nessus",
        )

        action = db_session.query(RemediationAction).one()
        assert action.title == "First"
        assert action.url == "https://support.microsoft.com/kb/5034441"

    def test_deleting_the_finding_removes_its_links(self, db_session):
        ingest_findings(db_session, [finding(remediations=[kb("KB5034441")])], "nessus")

        db_session.delete(db_session.query(AssetVulnerability).one())
        db_session.flush()

        assert db_session.query(FindingRemediation).count() == 0
