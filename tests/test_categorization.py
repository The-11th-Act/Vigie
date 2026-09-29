"""Categories of findings and types of hosts."""

import pytest

from app.core.config import settings
from app.models.asset import Asset
from app.models.vulnerability import AssetVulnerability
from app.parsers.utils import remediation
from app.services.categorization import (
    UNCATEGORIZED,
    asset_type_for,
    categorize_missing,
    classify_finding,
    more_specific,
)
from app.services.ingestion import ingest_findings


@pytest.mark.parametrize(
    ("title", "families", "expected"),
    [
        ("KB5034127: Windows 10 version 1809 Security Update", (), "operating_system"),
        ("Ubuntu 22.04 : linux vulnerabilities (USN-6541-1)", (), "operating_system"),
        ("Microsoft Edge (Chromium) < 120.0.2210.61", (), "browser"),
        ("Google Chrome < 120.0.6099.109", (), "browser"),
        ("Security Updates for Microsoft Office Products (January 2024)", (), "office"),
        ("Adobe Acrobat < 23.008 Multiple Vulnerabilities", (), "office"),
        # Before "Windows" or "Microsoft": the framework, not the OS.
        ("Security Updates for Microsoft .NET Framework (January 2024)", (), "runtime"),
        ("Oracle Java SE Multiple Vulnerabilities", (), "runtime"),
        ("Apache Log4j 2.x < 2.17.1 RCE", (), "runtime"),
        ("Microsoft SQL Server Security Update", (), "database"),
        ("Apache 2.4.x < 2.4.58 Multiple Vulnerabilities", (), "web_server"),
        ("Apache Tomcat 9.0.x < 9.0.83", (), "web_server"),
        ("Cisco IOS XE Software Web UI Privilege Escalation", (), "network_device"),
        (
            "Palo Alto Networks PAN-OS GlobalProtect Command Injection",
            (),
            "network_device",
        ),
        ("OpenSSH < 9.6 Multiple Vulnerabilities", (), "remote_access"),
        ("Citrix ADC and Citrix Gateway Multiple Vulnerabilities", (), "remote_access"),
        # Nessus files third-party Windows programs in its "Windows" family.
        ("7-Zip < 23.01", ("Windows",), "application"),
        ("Some vendor tool < 3.2", (), "application"),
        # The title says nothing, the family does.
        ("Remote service vulnerable", ("Web Servers",), "web_server"),
        ("Package update", ("Red Hat Local Security Checks",), "operating_system"),
        # A Spotlight title is the CVE and its description.
        ("CVE-2024-1234: A flaw was found", (), UNCATEGORIZED),
        ("CVE-2024-1234: A flaw in the Linux kernel", (), "operating_system"),
        (None, (), UNCATEGORIZED),
    ],
)
def test_findings_fold_into_the_taxonomy(title, families, expected):
    assert classify_finding(title, families) == expected


@pytest.mark.parametrize(
    ("operating_system", "expected"),
    [
        ("Microsoft Windows Server 2019 Standard", "server"),
        ("Microsoft Windows 11 Enterprise", "workstation"),
        ("Mac OS X 14.1", "workstation"),
        ("Ubuntu 22.04", "server"),
        ("VMware ESXi 8.0", "server"),
        ("Cisco IOS 15.2", "network"),
        ("Fortinet FortiOS 7.2", "network"),
        # An iPhone is not a Cisco router.
        ("Apple iOS 17", None),
        ("Unknown", None),
        (None, None),
    ],
)
def test_hosts_get_a_type_from_their_os(operating_system, expected):
    assert asset_type_for(operating_system) == expected


def test_a_vague_answer_never_replaces_a_precise_one():
    assert more_specific("browser", "application") == "browser"
    assert more_specific("browser", UNCATEGORIZED) == "browser"
    assert more_specific("application", "browser") == "browser"
    assert more_specific(None, "application") == "application"
    assert more_specific("application", UNCATEGORIZED) == "application"


def finding(ip, title, os_name=None, family=None, cve="CVE-2024-0001"):
    return {
        "ip_address": ip,
        "hostname": None,
        "operating_system": os_name,
        "cve_id": cve,
        "title": title,
        "description": None,
        "cvss_score": 7.0,
        "severity": "High",
        "remediations": [remediation("vendor_fix", f"nessus:{cve}", family=family)],
    }


class TestAtIngestion:
    def test_findings_and_hosts_are_categorized(self, db_session, monkeypatch):
        monkeypatch.setattr(settings, "ENVIRONMENT_RULES", {"10.0.0.0/8": "production"})
        ingest_findings(
            db_session,
            [finding("10.0.0.1", "Google Chrome < 120", "Microsoft Windows 11 Pro")],
            "nessus",
        )

        asset = db_session.query(Asset).one()
        assert (asset.asset_type, asset.environment) == ("workstation", "production")
        assert db_session.query(AssetVulnerability).one().category == "browser"

    def test_a_type_set_by_hand_is_kept(self, db_session):
        db_session.add(
            Asset(ip_address="10.0.0.2", operating_system="Ubuntu 22.04", asset_type="ot")
        )
        db_session.commit()

        ingest_findings(db_session, [finding("10.0.0.2", "Something")], "nessus")

        assert db_session.query(Asset).one().asset_type == "ot"

    def test_two_checks_on_one_pair_keep_the_precise_category(self, db_session):
        ingest_findings(
            db_session,
            [
                finding("10.0.0.3", "Google Chrome < 120"),
                finding("10.0.0.3", "Generic check"),
            ],
            "nessus",
        )
        assert db_session.query(AssetVulnerability).one().category == "browser"


def test_uncategorized_findings_are_caught_up(db_session):
    ingest_findings(db_session, [finding("10.0.0.4", "OpenSSH < 9.6")], "nessus")
    link = db_session.query(AssetVulnerability).one()
    link.category = None
    db_session.commit()
    db_session.autoflush = False  # as in the worker
    try:
        assert categorize_missing(db_session, batch_size=1) == 1
    finally:
        db_session.autoflush = True

    db_session.refresh(link)
    assert link.category == "remote_access"
