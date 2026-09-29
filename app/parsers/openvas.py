import logging
from typing import Any

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from app.models.remediation import RemediationKind
from app.parsers.utils import (
    ParsedScan,
    clean_text,
    is_valid_cve,
    kb_references_in,
    normalize_severity,
    remediation,
    safe_float,
    versions_in,
)

logger = logging.getLogger(__name__)

MAX_DESCRIPTION_LENGTH = 10_000

# GVM solution types, onto what the remediation team is asked to do.
SOLUTION_KINDS = {
    "vendorfix": RemediationKind.vendor_fix,
    "workaround": RemediationKind.workaround,
    "mitigation": RemediationKind.mitigation,
    "nonavailable": RemediationKind.no_fix,
    "noneavailable": RemediationKind.no_fix,
    "willnotfix": RemediationKind.no_fix,
}


def _extract_cve_ids(nvt_el) -> list[str]:
    """Collect CVE identifiers from an NVT node.

    OpenVAS exposes them either as a single <cve> element (sometimes holding a
    comma-separated list) or as <refs><ref type="cve" id="..."/></refs>.
    """
    candidates: list[str] = []

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


def parse_openvas_report(xml_content: bytes) -> list[dict[str, Any]]:
    """Parse an OpenVAS/GVM XML report into normalised findings."""
    return parse_openvas_scan(xml_content).findings


def parse_openvas_scan(xml_content: bytes) -> ParsedScan:
    """Findings of an OpenVAS/GVM report, plus every host it covered.

    A host counts as scanned when the report lists it in a ``<host><ip>`` block
    or when any result — CVE or not — was raised against it, so a host that
    came back clean still lets its old findings close.
    """
    scan = ParsedScan()
    results = scan.findings

    try:
        root = ET.fromstring(xml_content)
    except (ET.ParseError, DefusedXmlException, ValueError) as exc:
        logger.error("Error parsing OpenVAS file: %s", exc)
        return scan

    for ip_el in root.findall(".//host/ip"):
        address = clean_text(ip_el.text)
        if address:
            scan.scanned_addresses.add(address)

    for result in root.findall(".//results/result"):
        host_el = result.find("host")
        ip_address = (
            clean_text(host_el.text if host_el is not None else None) or "Unknown"
        )
        if ip_address != "Unknown":
            scan.scanned_addresses.add(ip_address)

        nvt_el = result.find("nvt")
        if nvt_el is None:
            continue

        cve_ids = _extract_cve_ids(nvt_el)
        if not cve_ids:
            continue

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

        remediations = _remediations(nvt_el, title, description)

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
                    "remediations": remediations,
                }
            )

    logger.info(
        "Parsed %d findings on %d hosts from OpenVAS report",
        len(results),
        len(scan.scanned_addresses),
    )
    return scan


def _solution(nvt_el) -> tuple[str | None, str | None]:
    """The solution text and type of an NVT.

    Recent GVM reports carry a ``<solution type="VendorFix">`` element; older
    ones pack both into the ``<tags>`` string (``|solution=...|solution_type=``).
    """
    solution_el = nvt_el.find("solution")
    if solution_el is not None:
        return clean_text(solution_el.text), solution_el.attrib.get("type")

    tags: dict[str, str] = {}
    tags_el = nvt_el.find("tags")
    tags_text = tags_el.text if tags_el is not None else None
    for part in (tags_text or "").split("|"):
        key, _, value = part.partition("=")
        tags[key.strip()] = value
    return clean_text(tags.get("solution")), tags.get("solution_type")


def _remediations(nvt_el, title: str, description: str | None) -> list[dict[str, Any]]:
    """How to fix an NVT result: its KB when it names one, otherwise the NVT.

    One NVT is one fix instruction, so the NVT's OID keys the action; a
    Microsoft update is keyed by its KB, shared with the other scanners.
    """
    solution, solution_type = _solution(nvt_el)
    kind = SOLUTION_KINDS.get(
        (solution_type or "").strip().lower(), RemediationKind.vendor_fix
    )
    family_el = nvt_el.find("family")
    family = family_el.text if family_el is not None else None
    url = next(
        (
            ref.attrib.get("id")
            for ref in nvt_el.findall(".//refs/ref")
            if (ref.attrib.get("type") or "").lower() == "url"
        ),
        None,
    )
    installed, fixed = versions_in(description)
    details = {
        "title": title,
        "solution": solution,
        "url": url,
        "family": family,
        "installed_version": installed,
        "fixed_version": fixed,
    }

    kbs = kb_references_in(title) or kb_references_in(solution)
    if kbs and kind == RemediationKind.vendor_fix:
        return [remediation(RemediationKind.kb.value, kb, **details) for kb in kbs]

    oid = clean_text(nvt_el.attrib.get("oid"))
    if not oid:
        return []
    return [remediation(kind.value, f"openvas:{oid}", **details)]
