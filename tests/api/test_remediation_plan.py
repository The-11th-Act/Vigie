"""The remediation module: the backlog folded per KB or fix."""

import csv
import io

import pytest

from app.models.asset import Asset
from app.models.remediation import FindingRemediation
from app.models.vulnerability import AssetVulnerability, Status, Vulnerability
from app.parsers.utils import remediation
from app.services.ingestion import ingest_findings


def finding(cve, ip, cvss=8.0, fixes=None, hostname=None, **kwargs):
    base = {
        "ip_address": ip,
        "hostname": hostname,
        "operating_system": "Windows Server 2019",
        "cve_id": cve,
        "title": "Test",
        "description": None,
        "cvss_score": cvss,
        "severity": "High",
        "remediations": fixes if fixes is not None else [],
    }
    base.update(kwargs)
    return base


ROLLUP = remediation("kb", "KB5034127", title="January rollup", solution="Apply it")
APACHE = remediation(
    "vendor_fix",
    "nessus:183391",
    title="Apache < 2.4.58",
    installed_version="2.4.52",
    fixed_version="2.4.58",
)


@pytest.fixture
def backlog(db_session):
    """A rollup on two servers (3 CVEs each), Apache on one, one unfixable."""
    findings = [
        finding(cve, ip, fixes=[ROLLUP], hostname=name)
        for cve in ("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")
        for ip, name in (("10.0.0.1", "srv-a"), ("10.0.0.2", "srv-b"))
    ]
    findings.append(finding("CVE-2023-45802", "10.0.0.1", cvss=5.0, fixes=[APACHE]))
    findings.append(finding("CVE-2023-99999", "10.0.0.3", cvss=4.0))
    ingest_findings(db_session, findings, "nessus")
    return findings


def actions(client, **params):
    response = client.get("/api/v1/remediation/actions", params=params)
    assert response.status_code == 200, response.text
    return response.json()


class TestTopFixes:
    def test_the_fix_removing_the_most_risk_comes_first(self, client, backlog):
        body = actions(client)

        assert [item["action"]["reference"] for item in body["items"]] == [
            "KB5034127",
            "nessus:183391",
        ]
        rollup = body["items"][0]
        assert (rollup["findings"], rollup["assets"], rollup["cves"]) == (6, 2, 3)
        assert rollup["total_risk"] == pytest.approx(6 * 8.0)
        assert rollup["max_risk"] == 8.0
        assert rollup["next_deadline"] is not None

    def test_findings_without_a_fix_are_counted_apart(self, client, backlog):
        assert actions(client)["unremediated"] == {
            "findings": 1,
            "assets": 1,
            "total_risk": 4.0,
        }

    def test_two_sources_naming_the_same_kb_count_once(self, client, db_session, backlog):
        ingest_findings(
            db_session,
            [
                finding(cve, ip, fixes=[ROLLUP])
                for cve in ("CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003")
                for ip in ("10.0.0.1", "10.0.0.2")
            ],
            "openvas",
        )

        rollup = actions(client)["items"][0]
        assert rollup["findings"] == 6
        assert rollup["total_risk"] == pytest.approx(48.0)

    def test_closed_findings_leave_the_plan(self, client, db_session, backlog):
        for link in (
            db_session.query(AssetVulnerability)
            .join(AssetVulnerability.vulnerability)
            .filter(Vulnerability.cve_id == "CVE-2023-45802")
        ):
            link.status = Status.remediated
        db_session.commit()

        references = [item["action"]["reference"] for item in actions(client)["items"]]
        assert references == ["KB5034127"]

    def test_filters(self, client, backlog):
        assert actions(client, kind="vendor_fix")["total"] == 1
        assert actions(client, search="apache")["items"][0]["action"]["reference"] == (
            "nessus:183391"
        )
        assert actions(client, kev_only=True)["total"] == 0
        assert (
            client.get("/api/v1/remediation/actions", params={"kind": "nope"}).status_code
            == 422
        )

    def test_pagination(self, client, backlog):
        body = actions(client, limit=1, skip=1)
        assert body["total"] == 2
        assert [item["action"]["reference"] for item in body["items"]] == [
            "nessus:183391"
        ]


class TestActionHosts:
    def action_id(self, db_session, reference):
        link = (
            db_session.query(FindingRemediation)
            .join(FindingRemediation.action)
            .filter_by(reference=reference)
            .first()
        )
        return link.action_id

    def test_every_host_still_waiting_for_the_fix(self, client, db_session, backlog):
        action_id = self.action_id(db_session, "KB5034127")

        body = client.get(f"/api/v1/remediation/actions/{action_id}").json()

        assert body["action"]["solution"] == "Apply it"
        hosts = {host["hostname"]: host for host in body["hosts"]}
        assert set(hosts) == {"srv-a", "srv-b"}
        assert sorted(hosts["srv-a"]["cves"]) == [
            "CVE-2024-0001",
            "CVE-2024-0002",
            "CVE-2024-0003",
        ]
        assert hosts["srv-a"]["max_risk"] == 8.0

    def test_versions_come_per_host(self, client, db_session, backlog):
        action_id = self.action_id(db_session, "nessus:183391")

        [host] = client.get(f"/api/v1/remediation/actions/{action_id}").json()["hosts"]

        assert (host["installed_versions"], host["fixed_versions"]) == (
            ["2.4.52"],
            ["2.4.58"],
        )

    def test_the_host_list_exports_for_a_deployment_tool(
        self, client, db_session, backlog
    ):
        # A hostname is whatever a scan says it is.
        db_session.query(Asset).filter_by(hostname="srv-b").update(
            {"hostname": "=cmd|'/c calc'!A1"}
        )
        db_session.commit()
        action_id = self.action_id(db_session, "KB5034127")

        response = client.get(f"/api/v1/remediation/actions/{action_id}/hosts.csv")

        assert response.status_code == 200
        assert "KB5034127" in response.headers["content-disposition"]
        header, *rows = csv.reader(io.StringIO(response.content.decode("utf-8-sig")))
        assert header[:2] == ["hostname", "ip_address"]
        assert {row[1] for row in rows} == {"10.0.0.1", "10.0.0.2"}
        assert all(not row[0].startswith("=") for row in rows)

    def test_an_unknown_action_is_404(self, client):
        assert client.get("/api/v1/remediation/actions/999999").status_code == 404


class TestAccess:
    def test_the_module_is_checked(self, client, db_session):
        client.patch("/api/v1/admin/modules/remediation", json={"enabled": False})
        # Even an administrator loses a module switched off for the instance.
        assert client.get("/api/v1/remediation/actions").status_code == 403
