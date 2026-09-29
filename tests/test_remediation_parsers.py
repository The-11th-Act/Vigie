"""What each parser extracts about how to fix a finding.

The reports are trimmed to the elements that matter, in the layout Nessus,
GVM and Spotlight document; the Windows rollup reproduces the typical case of
one update fixing many CVEs.
"""

from app.parsers.crowdstrike import _normalize
from app.parsers.nessus import parse_nessus_report
from app.parsers.openvas import parse_openvas_report
from app.parsers.utils import kb_reference, kb_references_in, versions_in

NESSUS_REPORT = b"""<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="test">
    <ReportHost name="10.0.0.5">
      <HostProperties>
        <tag name="operating-system">Microsoft Windows Server 2019</tag>
      </HostProperties>
      <ReportItem pluginID="187901" pluginName="KB5034127: Windows 10 version 1809 / Windows Server 2019 Security Update (January 2024)" pluginFamily="Windows : Microsoft Bulletins" severity="3">
        <cve>CVE-2024-20674</cve>
        <cve>CVE-2024-20700</cve>
        <cvss3_base_score>9.0</cvss3_base_score>
        <solution>Apply Security Update 5034127</solution>
        <see_also>https://support.microsoft.com/help/5034127
https://example.com/other</see_also>
        <xref>MSKB:5034127</xref>
        <xref>MSKB:5034122</xref>
        <xref>MSFT:MS24-5034127</xref>
        <plugin_output>
The remote host is missing one of the following rollup KBs :
  - 5034127

  - C:\\Windows\\system32\\ntoskrnl.exe has not been patched.
    Remote version : 10.0.17763.5206
    Should be      : 10.0.17763.5329
</plugin_output>
      </ReportItem>
      <ReportItem pluginID="187902" pluginName="Security Updates for Microsoft Office Products (January 2024)" pluginFamily="Windows : Microsoft Bulletins" severity="3">
        <cve>CVE-2024-20677</cve>
        <cvss3_base_score>7.8</cvss3_base_score>
        <solution>Microsoft has released the following security updates.</solution>
        <xref>MSKB:5002522</xref>
        <xref>IAVA:2024-A-0012</xref>
      </ReportItem>
      <ReportItem pluginID="183391" pluginName="Apache 2.4.x &lt; 2.4.58 Multiple Vulnerabilities" pluginFamily="Web Servers" severity="2">
        <cve>CVE-2023-45802</cve>
        <cvss3_base_score>5.9</cvss3_base_score>
        <solution>Upgrade to Apache version 2.4.58 or later.</solution>
        <plugin_output>
  URL               : http://10.0.0.5/
  Installed version : 2.4.52
  Fixed version     : 2.4.58
</plugin_output>
      </ReportItem>
      <ReportItem pluginID="100000" pluginName="Unpatched product" pluginFamily="Misc." severity="2">
        <cve>CVE-2023-11111</cve>
        <cvss3_base_score>5.0</cvss3_base_score>
        <solution>There is no known fix at this time.</solution>
      </ReportItem>
      <ReportItem pluginName="No plugin id" severity="2">
        <cve>CVE-2023-22222</cve>
        <cvss3_base_score>5.0</cvss3_base_score>
        <solution>n/a</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def nessus(cve):
    return next(f for f in parse_nessus_report(NESSUS_REPORT) if f["cve_id"] == cve)


class TestNessusRemediation:
    def test_the_rollup_names_the_kb_this_host_is_missing(self):
        """The plugin cross-references every OS's update (5034122 is another
        Windows version's): only the one the output names applies here."""
        [fix] = nessus("CVE-2024-20674")["remediations"]
        assert fix["kind"] == "kb"
        assert fix["reference"] == "KB5034127"
        assert fix["family"] == "Windows : Microsoft Bulletins"
        assert fix["url"] == "https://support.microsoft.com/help/5034127"

    def test_every_cve_of_the_plugin_gets_the_same_fix(self):
        first = nessus("CVE-2024-20674")["remediations"]
        second = nessus("CVE-2024-20700")["remediations"]
        assert first == second

    def test_the_cross_references_are_the_fallback(self):
        [fix] = nessus("CVE-2024-20677")["remediations"]
        assert fix["reference"] == "KB5002522"

    def test_a_non_microsoft_fix_is_keyed_by_the_plugin(self):
        [fix] = nessus("CVE-2023-45802")["remediations"]
        assert fix["kind"] == "vendor_fix"
        assert fix["reference"] == "nessus:183391"
        assert fix["title"] == "Apache 2.4.x < 2.4.58 Multiple Vulnerabilities"
        assert fix["solution"] == "Upgrade to Apache version 2.4.58 or later."
        assert (fix["installed_version"], fix["fixed_version"]) == ("2.4.52", "2.4.58")

    def test_no_known_fix_is_said_so(self):
        [fix] = nessus("CVE-2023-11111")["remediations"]
        assert fix["kind"] == "no_fix"

    def test_without_kb_or_plugin_id_there_is_nothing_to_key(self):
        assert nessus("CVE-2023-22222")["remediations"] == []


OPENVAS_REPORT = b"""<?xml version="1.0"?>
<report>
  <results>
    <result>
      <host>192.168.1.5</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.117822">
        <name>Apache HTTP Server &lt; 2.4.58 Multiple Vulnerabilities</name>
        <family>Web Servers</family>
        <cvss_base>7.5</cvss_base>
        <solution type="VendorFix">Update to version 2.4.58 or later.</solution>
        <refs>
          <ref type="cve" id="CVE-2023-45802"/>
          <ref type="url" id="https://httpd.apache.org/security/vulnerabilities_24.html"/>
        </refs>
      </nvt>
      <threat>High</threat>
      <description>Installed version: 2.4.52
Fixed version:     2.4.58
Installation path / port: 80/tcp</description>
    </result>
    <result>
      <host>192.168.1.5</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.832781">
        <name>Microsoft Windows Multiple Vulnerabilities (KB5034127)</name>
        <family>Windows : Microsoft Bulletins</family>
        <cvss_base>8.8</cvss_base>
        <tags>summary=Missing update|solution=Apply the latest updates.|solution_type=VendorFix</tags>
        <refs><ref type="cve" id="CVE-2024-20674"/></refs>
      </nvt>
      <threat>High</threat>
    </result>
    <result>
      <host>192.168.1.5</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.999999">
        <name>Workaround only</name>
        <cvss_base>5.0</cvss_base>
        <tags>solution=Disable the module.|solution_type=Workaround</tags>
        <refs><ref type="cve" id="CVE-2023-33333"/></refs>
      </nvt>
      <threat>Medium</threat>
    </result>
  </results>
</report>
"""


def openvas(cve):
    return next(f for f in parse_openvas_report(OPENVAS_REPORT) if f["cve_id"] == cve)


class TestOpenVASRemediation:
    def test_a_vendor_fix_is_keyed_by_the_nvt(self):
        [fix] = openvas("CVE-2023-45802")["remediations"]
        assert fix["kind"] == "vendor_fix"
        assert fix["reference"] == "openvas:1.3.6.1.4.1.25623.1.0.117822"
        assert fix["solution"] == "Update to version 2.4.58 or later."
        assert fix["url"] == "https://httpd.apache.org/security/vulnerabilities_24.html"
        assert (fix["installed_version"], fix["fixed_version"]) == ("2.4.52", "2.4.58")

    def test_a_named_kb_is_shared_with_the_other_scanners(self):
        [fix] = openvas("CVE-2024-20674")["remediations"]
        assert (fix["kind"], fix["reference"]) == ("kb", "KB5034127")
        assert fix["solution"] == "Apply the latest updates."

    def test_the_solution_type_of_older_reports_is_read_from_the_tags(self):
        [fix] = openvas("CVE-2023-33333")["remediations"]
        assert fix["kind"] == "workaround"
        assert fix["solution"] == "Disable the module."


def spotlight_entity(**overrides):
    base = {
        "id": "vuln-1",
        "host_info": {"local_ip": "10.0.2.15", "hostname": "win-01"},
        "cve": {"id": "CVE-2024-20674", "base_score": 9.0, "severity": "CRITICAL"},
        "apps": [{"product_name_version": "Windows Server 2019"}],
    }
    base.update(overrides)
    return base


class TestSpotlightRemediation:
    def test_a_kb_reference_is_a_kb(self):
        finding = _normalize(
            spotlight_entity(
                remediation={
                    "entities": [
                        {
                            "id": "rem-1",
                            "reference": "KB5034127",
                            "title": "Install patch for Windows Server 2019",
                            "action": "Install cumulative update KB5034127",
                            "link": "https://support.microsoft.com/help/5034127",
                        }
                    ]
                }
            )
        )
        [fix] = finding["remediations"]
        assert (fix["kind"], fix["reference"]) == ("kb", "KB5034127")
        assert fix["installed_version"] == "Windows Server 2019"

    def test_another_action_is_keyed_by_its_spotlight_id(self):
        finding = _normalize(
            spotlight_entity(
                remediation={
                    "entities": [{"id": "rem-2", "action": "Update Chrome to 120"}]
                }
            )
        )
        [fix] = finding["remediations"]
        assert (fix["kind"], fix["reference"]) == ("vendor_fix", "crowdstrike:rem-2")
        assert fix["title"] == "Update Chrome to 120"

    def test_remediation_ids_alone_say_nothing(self):
        """Without the details expanded, the key stays absent so an earlier
        sync's links are not erased."""
        finding = _normalize(spotlight_entity(remediation={"ids": ["rem-1"]}))
        assert "remediations" not in finding
        assert "remediations" not in _normalize(spotlight_entity())


class TestHelpers:
    def test_kb_spellings(self):
        assert kb_reference("MSKB:5034441") == "KB5034441"
        assert kb_reference("KB 5034441") == "KB5034441"
        assert kb_reference("5034441") == "KB5034441"
        assert kb_reference("IAVA:2024-A-0012") is None
        assert kb_references_in("KB5034441 then kb5034441 and KB5035845") == [
            "KB5034441",
            "KB5035845",
        ]

    def test_versions_are_optional(self):
        assert versions_in(None) == (None, None)
        assert versions_in("Fixed version : 3.0.13") == (None, "3.0.13")
