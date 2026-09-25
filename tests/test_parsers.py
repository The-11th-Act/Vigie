"""Parser robustness tests.

These cover the failure modes that previously reached the database: severity
values outside the enum, unparseable CVSS scores, junk CVE identifiers, and
XML entity expansion attacks.
"""

from app.models.vulnerability import Severity
from app.parsers.nessus import parse_nessus_report, parse_nessus_scan
from app.parsers.openvas import parse_openvas_report, parse_openvas_scan

VALID_SEVERITIES = {s.value for s in Severity}


NESSUS_REPORT = b"""<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="test">
    <ReportHost name="10.0.0.1">
      <HostProperties>
        <tag name="host-fqdn">web-01.example.com</tag>
        <tag name="operating-system">Ubuntu 22.04</tag>
      </HostProperties>
      <ReportItem pluginName="Critical RCE" severity="4">
        <cve>CVE-2024-1234</cve>
        <cvss_base_score>9.8</cvss_base_score>
        <description>A critical issue.</description>
      </ReportItem>
      <ReportItem pluginName="Informational" severity="0">
        <cve>CVE-2024-9999</cve>
        <cvss_base_score>0.0</cvss_base_score>
      </ReportItem>
      <ReportItem pluginName="Broken score" severity="2">
        <cve>CVE-2024-5678</cve>
        <cvss_base_score>N/A</cvss_base_score>
      </ReportItem>
      <ReportItem pluginName="Junk CVE" severity="3">
        <cve>NOCVE</cve>
        <cvss_base_score>7.5</cvss_base_score>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


class TestNessusParser:
    def test_extracts_host_metadata(self):
        findings = parse_nessus_report(NESSUS_REPORT)
        critical = next(f for f in findings if f["cve_id"] == "CVE-2024-1234")
        assert critical["ip_address"] == "10.0.0.1"
        assert critical["hostname"] == "web-01.example.com"
        assert critical["operating_system"] == "Ubuntu 22.04"
        assert critical["cvss_score"] == 9.8
        assert critical["severity"] == "Critical"

    def test_every_severity_is_a_valid_enum_value(self):
        """Regression: severity 0 used to map to "None", which is not in the
        Severity enum and blew up on insert."""
        findings = parse_nessus_report(NESSUS_REPORT)
        assert findings
        assert all(f["severity"] in VALID_SEVERITIES for f in findings)

    def test_informational_findings_are_skipped(self):
        findings = parse_nessus_report(NESSUS_REPORT)
        assert not any(f["cve_id"] == "CVE-2024-9999" for f in findings)

    def test_unparseable_cvss_defaults_to_zero(self):
        findings = parse_nessus_report(NESSUS_REPORT)
        broken = next(f for f in findings if f["cve_id"] == "CVE-2024-5678")
        assert broken["cvss_score"] == 0.0
        assert broken["severity"] == "Medium"  # kept from the vendor label

    def test_junk_cve_identifiers_are_dropped(self):
        findings = parse_nessus_report(NESSUS_REPORT)
        assert all(f["cve_id"].startswith("CVE-") for f in findings)
        assert not any(f["cve_id"] == "NOCVE" for f in findings)

    def test_malformed_xml_returns_empty_list(self):
        assert parse_nessus_report(b"<not-xml") == []

    def test_empty_input_returns_empty_list(self):
        assert parse_nessus_report(b"") == []


OPENVAS_REPORT = b"""<?xml version="1.0"?>
<report>
  <results>
    <result>
      <host>192.168.1.5<hostname>db-01</hostname></host>
      <threat>High</threat>
      <description>Something bad.</description>
      <nvt>
        <name>OpenSSL flaw</name>
        <cve>CVE-2024-2222</cve>
        <cvss_base>7.5</cvss_base>
      </nvt>
    </result>
    <result>
      <host>192.168.1.6</host>
      <nvt>
        <name>No CVE here</name>
        <cve>NOCVE</cve>
        <cvss_base>5.0</cvss_base>
      </nvt>
    </result>
    <result>
      <host>192.168.1.7</host>
      <nvt>
        <name>Multi CVE</name>
        <cve>CVE-2024-3333, CVE-2024-4444</cve>
        <cvss_base>bogus</cvss_base>
      </nvt>
      <severity>6.1</severity>
    </result>
  </results>
</report>
"""


class TestOpenVASParser:
    def test_parses_basic_result(self):
        findings = parse_openvas_report(OPENVAS_REPORT)
        first = next(f for f in findings if f["cve_id"] == "CVE-2024-2222")
        assert first["ip_address"].startswith("192.168.1.5")
        assert first["cvss_score"] == 7.5
        assert first["severity"] == "High"

    def test_results_without_a_cve_are_skipped(self):
        findings = parse_openvas_report(OPENVAS_REPORT)
        assert not any(f["ip_address"] == "192.168.1.6" for f in findings)

    def test_comma_separated_cves_are_split(self):
        findings = parse_openvas_report(OPENVAS_REPORT)
        cves = {f["cve_id"] for f in findings}
        assert "CVE-2024-3333" in cves
        assert "CVE-2024-4444" in cves

    def test_falls_back_to_severity_element(self):
        findings = parse_openvas_report(OPENVAS_REPORT)
        multi = next(f for f in findings if f["cve_id"] == "CVE-2024-3333")
        assert multi["cvss_score"] == 6.1
        assert multi["severity"] == "Medium"

    def test_every_severity_is_a_valid_enum_value(self):
        findings = parse_openvas_report(OPENVAS_REPORT)
        assert findings
        assert all(f["severity"] in VALID_SEVERITIES for f in findings)

    def test_malformed_xml_returns_empty_list(self):
        assert parse_openvas_report(b"<broken") == []


class TestScannedScope:
    """Parsers report every host a scan covered, not only hosts with findings.

    Automatic closure relies on it: a host that came back clean is exactly the
    one whose old findings must close, and a host absent from the file must not
    count a miss at all.
    """

    def test_nessus_counts_a_host_without_any_cve(self):
        report = NESSUS_REPORT.replace(
            b"</Report>",
            b'<ReportHost name="10.0.0.2"><HostProperties/></ReportHost></Report>',
        )
        scan = parse_nessus_scan(report)
        assert scan.scanned_addresses == {"10.0.0.1", "10.0.0.2"}
        assert {f["ip_address"] for f in scan.findings} == {"10.0.0.1"}

    def test_nessus_falls_back_to_the_host_ip_tag(self):
        report = b"""<NessusClientData_v2><Report>
          <ReportHost name=""><HostProperties>
            <tag name="host-ip">10.0.0.3</tag>
          </HostProperties></ReportHost>
        </Report></NessusClientData_v2>"""
        assert parse_nessus_scan(report).scanned_addresses == {"10.0.0.3"}

    def test_openvas_counts_results_without_a_cve(self):
        scan = parse_openvas_scan(OPENVAS_REPORT)
        # 192.168.1.6 only raised a non-CVE result: scanned, but no finding.
        assert "192.168.1.6" in scan.scanned_addresses
        assert not any(f["ip_address"] == "192.168.1.6" for f in scan.findings)

    def test_openvas_counts_hosts_listed_without_results(self):
        report = OPENVAS_REPORT.replace(
            b"</report>", b"<host><ip>192.168.1.9</ip></host></report>"
        )
        assert "192.168.1.9" in parse_openvas_scan(report).scanned_addresses

    def test_wrappers_return_the_same_findings(self):
        assert (
            parse_nessus_report(NESSUS_REPORT)
            == parse_nessus_scan(NESSUS_REPORT).findings
        )
        assert (
            parse_openvas_report(OPENVAS_REPORT)
            == parse_openvas_scan(OPENVAS_REPORT).findings
        )

    def test_malformed_xml_covers_nothing(self):
        for parse in (parse_nessus_scan, parse_openvas_scan):
            scan = parse(b"<broken")
            assert scan.findings == []
            assert scan.scanned_addresses == set()


BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<report><results><result><host>&lol3;</host></result></results></report>
"""

XXE_ATTACK = b"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<report><results><result><host>&xxe;</host></result></results></report>
"""


class TestXmlHardening:
    """Regression: the OpenVAS parser used the stdlib ElementTree, which is
    vulnerable to entity expansion. Both parsers now use defusedxml."""

    def test_openvas_rejects_entity_expansion(self):
        assert parse_openvas_report(BILLION_LAUGHS) == []

    def test_openvas_rejects_external_entities(self):
        assert parse_openvas_report(XXE_ATTACK) == []

    def test_nessus_rejects_entity_expansion(self):
        assert parse_nessus_report(BILLION_LAUGHS) == []

    def test_nessus_rejects_external_entities(self):
        assert parse_nessus_report(XXE_ATTACK) == []
