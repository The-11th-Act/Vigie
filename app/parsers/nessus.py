import logging
import re

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.models.remediation import RemediationKind
from app.parsers.utils import (
    ParsedFinding,
    ParsedRemediation,
    ParsedScan,
    clean_text,
    first_url,
    is_valid_cve,
    kb_reference,
    kb_references_in,
    normalize_severity,
    remediation,
    safe_float,
    versions_in,
)

logger = logging.getLogger(__name__)

# Nessus plugin severity levels. Level 0 ("Info") carries no risk and is
# skipped entirely rather than mapped onto a severity the enum does not have.
NESSUS_SEVERITY_MAP = {
    "1": "Low",
    "2": "Medium",
    "3": "High",
    "4": "Critical",
}

MAX_DESCRIPTION_LENGTH = 10_000

# Rollup plugins list the updates *this host* is missing as bare numbers:
#   The remote host is missing one of the following rollup KBs :
#     - 5034439
#     - 5034441
MISSING_KB_BLOCK = re.compile(r"KBs?\s*:\s*((?:\s*-\s*\d{6,8})+)", re.IGNORECASE)

NO_FIX = re.compile(
    r"no known (solution|fix|patch)|there is no (solution|fix|patch)|will not (be )?fixed",
    re.IGNORECASE,
)


def parse_nessus_report(xml_content: bytes) -> list[ParsedFinding]:
    """Parse a .nessus report into normalised findings.

    Returns an empty list on malformed input — ingestion callers treat that as
    "nothing to import" rather than a hard failure.
    """
    return parse_nessus_scan(xml_content).findings


def parse_nessus_scan(xml_content: bytes) -> ParsedScan:
    """Findings of a .nessus report, plus every host it covered.

    Every ``ReportHost`` counts as scanned, including one without a single CVE:
    a fully patched host is exactly the case where its old findings must close.
    """
    scan = ParsedScan()
    results = scan.findings

    try:
        root = ET.fromstring(xml_content)
    except (ET.ParseError, DefusedXmlException, ValueError) as exc:
        logger.error("Error parsing Nessus file: %s", exc)
        return scan

    for host in root.findall(".//ReportHost"):
        ip_address = clean_text(host.attrib.get("name")) or "Unknown"
        hostname = None
        os_name = None

        for prop in host.findall(".//HostProperties/tag"):
            tag_name = prop.attrib.get("name")
            if tag_name == "host-fqdn":
                hostname = clean_text(prop.text)
            elif tag_name == "operating-system":
                os_name = clean_text(prop.text)
            elif tag_name == "host-ip" and ip_address == "Unknown":
                ip_address = clean_text(prop.text) or "Unknown"

        if ip_address != "Unknown":
            scan.scanned_addresses.add(ip_address)

        for item in host.findall(".//ReportItem"):
            cve_elements = item.findall("cve")
            if not cve_elements:
                continue

            # Level 0 findings are informational; they are not vulnerabilities.
            raw_severity = item.attrib.get("severity", "0")
            if raw_severity == "0":
                continue

            cvss_el = item.find("cvss3_base_score")
            if cvss_el is None:
                cvss_el = item.find("cvss_base_score")
            cvss_score = safe_float(cvss_el.text if cvss_el is not None else None)

            severity = normalize_severity(
                NESSUS_SEVERITY_MAP.get(raw_severity), cvss_score
            )

            description_el = item.find("description")
            description = clean_text(
                description_el.text if description_el is not None else None,
                MAX_DESCRIPTION_LENGTH,
            )
            title = clean_text(item.attrib.get("pluginName")) or "Vulnerability"
            remediations = _remediations(item, title)

            for cve_el in cve_elements:
                cve_id = clean_text(cve_el.text)
                if not is_valid_cve(cve_id):
                    logger.debug("Skipping invalid CVE identifier: %r", cve_el.text)
                    continue

                results.append(
                    ParsedFinding(
                        ip_address=ip_address,
                        hostname=hostname,
                        operating_system=os_name,
                        cve_id=cve_id.upper(),
                        title=title,
                        description=description,
                        cvss_score=cvss_score,
                        severity=severity,
                        remediations=remediations,
                    )
                )

    logger.info(
        "Parsed %d findings on %d hosts from Nessus report",
        len(results),
        len(scan.scanned_addresses),
    )
    return scan


def _text(item, tag: str) -> str | None:
    element = item.find(tag)
    return element.text if element is not None else None


def _missing_kbs(output: str | None) -> list[str]:
    """The KBs the plugin output says this host lacks.

    Preferred over the plugin's cross-references, which list the update for
    every Windows version the plugin covers: a Server 2019 host must not be
    told to install the Windows 11 update.
    """
    kbs = kb_references_in(output)
    for block in MISSING_KB_BLOCK.findall(output or ""):
        kbs.extend(f"KB{number}" for number in re.findall(r"\d{6,8}", block))
    return list(dict.fromkeys(kbs))


def _remediations(item, title: str) -> list[ParsedRemediation]:
    """How to fix a ReportItem, as the remediation team will act on it.

    A Microsoft update is keyed by its KB, so every plugin asking for it lands
    on the same action. Anything else is keyed by the plugin: one plugin is one
    upgrade instruction ("Upgrade to Apache 2.4.58 or later").
    """
    output = _text(item, "plugin_output")
    solution = clean_text(_text(item, "solution"))
    if solution and solution.lower() == "n/a":
        solution = None
    family = item.attrib.get("pluginFamily")
    url = first_url(_text(item, "see_also"))
    installed, fixed = versions_in(output)

    kbs = _missing_kbs(output)
    if not kbs:
        kbs = [
            kb for kb in (kb_reference(xref.text) for xref in item.findall("xref")) if kb
        ]
    if not kbs:
        kbs = kb_references_in(title)
    if kbs:
        return [
            remediation(
                RemediationKind.kb.value,
                kb,
                title=title,
                solution=solution,
                url=url,
                family=family,
                installed_version=installed,
                fixed_version=fixed,
            )
            for kb in dict.fromkeys(kbs)
        ]

    plugin_id = clean_text(item.attrib.get("pluginID"))
    if not plugin_id:
        return []
    kind = RemediationKind.vendor_fix
    if solution and NO_FIX.search(solution):
        kind = RemediationKind.no_fix
    return [
        remediation(
            kind.value,
            f"nessus:{plugin_id}",
            title=title,
            solution=solution,
            url=url,
            family=family,
            installed_version=installed,
            fixed_version=fixed,
        )
    ]
