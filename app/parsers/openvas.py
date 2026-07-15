import xml.etree.ElementTree as ET
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


def parse_openvas_report(xml_content: bytes) -> List[Dict[str, Any]]:
    results = []
    try:
        root = ET.fromstring(xml_content)
        for result in root.findall('.//results/result'):
            host_el = result.find('host')
            ip_address = host_el.text if host_el is not None else "Unknown"

            nvt_el = result.find('nvt')
            if nvt_el is None:
                continue

            cve_text = nvt_el.find('cve')
            cve_id = cve_text.text if cve_text is not None and cve_text.text and cve_text.text != "NOCVE" else None
            if not cve_id:
                continue

            cvss_text = nvt_el.find('cvss_base')
            cvss_score = float(cvss_text.text) if cvss_text is not None and cvss_text.text else 0.0

            severity_text = "Low"
            if cvss_score >= 9.0:
                severity_text = "Critical"
            elif cvss_score >= 7.0:
                severity_text = "High"
            elif cvss_score >= 4.0:
                severity_text = "Medium"

            results.append({
                "ip_address": ip_address,
                "hostname": None,
                "operating_system": None,
                "cve_id": cve_id,
                "title": nvt_el.find('name').text if nvt_el.find('name') is not None else "Vulnerability",
                "description": result.find('description').text if result.find('description') is not None else None,
                "cvss_score": cvss_score,
                "severity": severity_text
            })
    except ET.ParseError as e:
        logger.error("Error parsing OpenVAS file: %s", e)
    return results