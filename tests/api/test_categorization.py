"""The categorization matrix and its cells."""

import pytest

from app.core.security import decode_token, require_admin
from app.main import app
from app.models.asset import Asset, Criticality
from app.models.vulnerability import Vulnerability
from app.services.ingestion import ingest_findings
from tests.conftest import _make_user


def finding(ip, cve, title, cvss=8.0):
    return {
        "ip_address": ip,
        "hostname": None,
        "operating_system": None,
        "cve_id": cve,
        "title": title,
        "description": None,
        "cvss_score": cvss,
        "severity": "High",
    }


@pytest.fixture
def estate(db_session):
    """Two workstations with a browser flaw, a server with an OS and a DB flaw."""
    db_session.add_all(
        [
            Asset(
                ip_address="10.0.1.1", asset_type="workstation", owner_team="Workplace"
            ),
            Asset(
                ip_address="10.0.1.2", asset_type="workstation", owner_team="Workplace"
            ),
            Asset(
                ip_address="10.0.2.1",
                asset_type="server",
                environment="production",
                business_criticality=Criticality.critical,
                internet_facing=True,
            ),
            Asset(ip_address="10.0.3.1"),
        ]
    )
    db_session.commit()
    ingest_findings(
        db_session,
        [
            finding("10.0.1.1", "CVE-2024-0001", "Google Chrome < 120"),
            finding("10.0.1.2", "CVE-2024-0001", "Google Chrome < 120"),
            finding("10.0.2.1", "CVE-2024-0002", "Windows Server kernel flaw", 9.0),
            finding("10.0.2.1", "CVE-2024-0003", "PostgreSQL < 16.1", 6.0),
            finding("10.0.3.1", "CVE-2024-0004", "CVE-2024-0004: unknown"),
        ],
        "nessus",
    )
    kev = db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-0002").one()
    kev.in_kev = True
    db_session.commit()


def matrix(client, **params):
    response = client.get("/api/v1/categorization/matrix", params=params)
    assert response.status_code == 200, response.text
    body = response.json()
    cells = {(cell["row"], cell["col"]): cell for cell in body["cells"]}
    return body, cells


class TestMatrix:
    def test_by_asset_type(self, client, estate):
        body, cells = matrix(client)

        assert [row["key"] for row in body["rows"]] == [
            "operating_system",
            "browser",
            "database",
            "uncategorized",
        ]
        assert [col["key"] for col in body["columns"]] == [
            "server",
            "workstation",
            "__none__",
        ]
        assert body["columns"][-1]["label"] == "Unknown type"
        browsers = cells[("browser", "workstation")]
        assert (browsers["findings"], browsers["assets"]) == (2, 2)
        assert browsers["total_risk"] == pytest.approx(16.0)
        assert cells[("operating_system", "server")]["kev"] == 1

    @pytest.mark.parametrize(
        ("columns", "expected"),
        [
            ("business_criticality", ["Critical", "Medium"]),
            ("internet_facing", ["true", "false"]),
            ("environment", ["production", "__none__"]),
            ("owner_team", ["Workplace", "__none__"]),
        ],
    )
    def test_other_dimensions(self, client, estate, columns, expected):
        body, _ = matrix(client, columns=columns)
        assert [col["key"] for col in body["columns"]] == expected

    def test_filters(self, client, estate):
        _, cells = matrix(client, kev_only=True)
        assert list(cells) == [("operating_system", "server")]

        _, cells = matrix(client, owner_team="Workplace")
        assert list(cells) == [("browser", "workstation")]

    def test_an_unknown_dimension_is_refused(self, client):
        response = client.get("/api/v1/categorization/matrix", params={"columns": "os"})
        assert response.status_code == 422

    def test_closed_findings_are_not_counted(self, client, db_session, estate):
        from app.models.vulnerability import AssetVulnerability, Status

        for link in db_session.query(AssetVulnerability):
            link.status = Status.remediated
        db_session.commit()

        body, _ = matrix(client)
        assert body["cells"] == []


class TestCellFindings:
    def cell(self, client, **params):
        response = client.get("/api/v1/categorization/findings", params=params)
        assert response.status_code == 200, response.text
        return [item["vulnerability"]["cve_id"] for item in response.json()["items"]]

    def test_the_findings_behind_a_cell(self, client, estate):
        assert self.cell(client, category="browser", value="workstation") == [
            "CVE-2024-0001",
            "CVE-2024-0001",
        ]
        assert self.cell(client, category="uncategorized", value="__none__") == [
            "CVE-2024-0004"
        ]

    def test_on_every_dimension(self, client, estate):
        assert self.cell(
            client, category="database", columns="business_criticality", value="Critical"
        ) == ["CVE-2024-0003"]
        assert self.cell(
            client, category="browser", columns="internet_facing", value="false"
        ) == ["CVE-2024-0001", "CVE-2024-0001"]
        assert self.cell(
            client, category="operating_system", columns="environment", value="production"
        ) == ["CVE-2024-0002"]


def test_it_is_a_module(client, db_session, estate):
    user = _make_user(db_session, "remy-cat", "remediator")
    app.dependency_overrides.pop(require_admin, None)
    app.dependency_overrides[decode_token] = lambda: {
        "sub": str(user.id),
        "role": "remediator",
        "username": user.username,
    }
    assert client.get("/api/v1/categorization/matrix").status_code == 403
