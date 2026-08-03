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

MAX_DESCRIPTION_LENGTH = 10_000


def _extract_cve_ids(nvt_el) -> List[str]:
    """Collect CVE identifiers from an NVT node.

    OpenVAS exposes them either as a single <cve> element (sometimes holding a
    comma-separated list) or as <refs><ref type="cve" id="..."/></refs>.
    """
    candidates: List[str] = []

    cve_el = nvt_el.find("cve")
    if cve_el is not None and cve_el.text:
        candidates.extend(part.strip() for part in cve_el.text.split(","))

    for ref in nvt_el.findall(".//refs/ref"):
        if (ref.attrib.get("type") or "").lower() == "cve":
            ref_id = ref.attrib.get("id")
            if ref_id:
                candidates.append(ref_id.strip())

    seen = set()
    valid = []
    for candidate in candidates:
        if not is_valid_cve(candidate):
            continue
        normalized = candidate.upper()
        if normalized not in seen:
            seen.add(normalized)
            valid.append(normalized)
    return valid


def parse_openvas_report(xml_content: bytes) -> List[Dict[str, Any]]:
    """Parse an OpenVAS/GVM XML report into normalised findings."""
    results: List[Dict[str, Any]] = []

    try:
        root = ET.fromstring(xml_content)
    except (ET.ParseError, DefusedXmlException, ValueError) as exc:
        logger.error("Error parsing OpenVAS file: %s", exc)
        return results

    for result in root.findall(".//results/result"):
        nvt_el = result.find("nvt")
        if nvt_el is None:
            continue

        cve_ids = _extract_cve_ids(nvt_el)
        if not cve_ids:
            continue

        host_el = result.find("host")
        ip_address = (
            clean_text(host_el.text if host_el is not None else None) or "Unknown"
        )

        hostname_el = result.find("host/hostname")
        hostname = clean_text(hostname_el.text if hostname_el is not None else None)

        cvss_el = nvt_el.find("cvss_base")
        cvss_score = safe_float(cvss_el.text if cvss_el is not None else None)

        # Newer GVM reports carry the score on <severity> instead.
        if cvss_score == 0.0:
            severity_el = result.find("severity")
            cvss_score = safe_float(severity_el.text if severity_el is not None else None)

        threat_el = result.find("threat")
        severity = normalize_severity(
            threat_el.text if threat_el is not None else None, cvss_score
        )

        name_el = nvt_el.find("name")
        title = (
            clean_text(name_el.text if name_el is not None else None) or "Vulnerability"
        )

        description_el = result.find("description")
        description = clean_text(
            description_el.text if description_el is not None else None,
            MAX_DESCRIPTION_LENGTH,
        )

        for cve_id in cve_ids:
            results.append(
                {
                    "ip_address": ip_address,
                    "hostname": hostname,
                    "operating_system": None,
                    "cve_id": cve_id,
                    "title": title,
                    "description": description,
                    "cvss_score": cvss_score,
                    "severity": severity,
                }
            )

    logger.info("Parsed %d findings from OpenVAS report", len(results))
    return results
