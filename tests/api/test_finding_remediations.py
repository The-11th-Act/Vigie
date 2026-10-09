import csv
import io

from app.models.asset import Asset
from app.models.threat_intel import FEED_MSRC
from app.parsers.utils import remediation
from app.services.ingestion import ingest_findings
from app.services.threat_intel import import_feed
from tests.test_kb_supersedence import cvrf


def ingest(db_session, cve, remediations, ip="10.90.0.1"):
    ingest_findings(
        db_session,
        [
            {
                "ip_address": ip,
                "hostname": None,
                "operating_system": None,
                "cve_id": cve,
                "title": "Test",
                "description": None,
                "cvss_score": 8.0,
                "severity": "High",
                "remediations": remediations,
            }
        ],
        "nessus",
    )


def export_rows(client):
    response = client.get("/api/v1/vulnerabilities/findings/export.csv")
    assert response.status_code == 200
    header, *data = csv.reader(io.StringIO(response.content.decode("utf-8-sig")))
    return [dict(zip(header, row, strict=True)) for row in data]


class TestFindingRemediations:
    def test_the_backlog_says_what_to_deploy(self, client, db_session):
        ingest(
            db_session,
            "CVE-2024-20674",
            [
                remediation(
                    "kb",
                    "KB5034127",
                    title="KB5034127: Windows Server 2019 Security Update",
                    solution="Apply Security Update 5034127",
                    url="https://support.microsoft.com/help/5034127",
                )
            ],
        )

        [item] = client.get("/api/v1/vulnerabilities/findings").json()["items"]
        [fix] = item["remediations"]
        assert fix["source"] == "nessus"
        assert fix["action"] == {
            "reference": "KB5034127",
            "kind": "kb",
            "title": "KB5034127: Windows Server 2019 Security Update",
            "url": "https://support.microsoft.com/help/5034127",
        }

    def test_a_superseded_kb_shows_the_later_one_and_what_it_replaces(
        self, client, db_session
    ):
        import_feed(db_session, FEED_MSRC, cvrf("2024-Jan", ("KB5034127", "KB5033371")))
        ingest(db_session, "CVE-2023-36025", [remediation("kb", "KB5033371")])

        [item] = client.get("/api/v1/vulnerabilities/findings").json()["items"]
        [fix] = item["remediations"]
        assert fix["action"]["reference"] == "KB5034127"
        assert fix["reported_reference"] == "KB5033371"

    def test_the_asset_view_carries_them_too(self, client, db_session):
        ingest(db_session, "CVE-2024-20674", [remediation("kb", "KB5034127")])
        asset = db_session.query(Asset).one()

        response = client.get(f"/api/v1/vulnerabilities/assets/{asset.id}")

        [item] = response.json()["items"]
        assert item["remediations"][0]["action"]["reference"] == "KB5034127"

    def test_a_finding_without_fix_has_an_empty_list(self, client, db_session):
        ingest(db_session, "CVE-2024-20674", [])

        [item] = client.get("/api/v1/vulnerabilities/findings").json()["items"]
        assert item["remediations"] == []

    def test_the_export_names_the_kb_or_the_fix(self, client, db_session):
        ingest(db_session, "CVE-2024-20674", [remediation("kb", "KB5034127")])
        ingest(
            db_session,
            "CVE-2023-45802",
            [
                remediation(
                    "vendor_fix",
                    "nessus:183391",
                    title="Apache 2.4.x < 2.4.58 Multiple Vulnerabilities",
                    fixed_version="2.4.58",
                )
            ],
            ip="10.90.0.2",
        )

        rows = {row["cve_id"]: row for row in export_rows(client)}

        assert rows["CVE-2024-20674"]["remediation"] == "KB5034127"
        assert rows["CVE-2024-20674"]["fixed_version"] == ""
        apache = rows["CVE-2023-45802"]
        assert apache["remediation"] == "Apache 2.4.x < 2.4.58 Multiple Vulnerabilities"
        assert apache["fixed_version"] == "2.4.58"
