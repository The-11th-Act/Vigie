import logging
from typing import Any, Dict, List

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.parsers.utils import (
    clean_text,
    is_valid_cve,
    normalize_severity,
    safe_float,
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


def parse_nessus_report(xml_content: bytes) -> List[Dict[str, Any]]:
    """Parse a .nessus report into normalised findings.

    Returns an empty list on malformed input — ingestion callers treat that as
    "nothing to import" rather than a hard failure.
    """
    results: List[Dict[str, Any]] = []

    try:
        root = ET.fromstring(xml_content)
    except (ET.ParseError, DefusedXmlException, ValueError) as exc:
        logger.error("Error parsing Nessus file: %s", exc)
        return results

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

            for cve_el in cve_elements:
                cve_id = clean_text(cve_el.text)
                if not is_valid_cve(cve_id):
                    logger.debug("Skipping invalid CVE identifier: %r", cve_el.text)
                    continue

                results.append(
                    {
                        "ip_address": ip_address,
                        "hostname": hostname,
                        "operating_system": os_name,
                        "cve_id": cve_id.upper(),
                        "title": title,
                        "description": description,
                        "cvss_score": cvss_score,
                        "severity": severity,
                    }
                )

    logger.info("Parsed %d findings from Nessus report", len(results))
    return results
