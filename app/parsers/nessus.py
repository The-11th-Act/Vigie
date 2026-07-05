import xml.etree.ElementTree as ET
from typing import List, Dict, Any

def parse_nessus_report(xml_content: bytes) -> List[Dict[str, Any]]:
    results = []
    try:
        root = ET.fromstring(xml_content)
        for host in root.findall('.//ReportHost'):
            ip_address = host.attrib.get('name', 'Unknown')
            hostname = None
            os_name = None
            for prop in host.findall('.//HostProperties/tag'):
                if prop.attrib.get('name') == 'host-fqdn':
                    hostname = prop.text
                elif prop.attrib.get('name') == 'operating-system':
                    os_name = prop.text

            for item in host.findall('.//ReportItem'):
                cve_elements = item.findall('cve')
                if not cve_elements:
                    continue
                    
                cvss_score = float(item.find('cvss_base_score').text) if item.find('cvss_base_score') is not None else 0.0
                severity = item.attrib.get('severity', '0')
                severity_map = {"0": "None", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
                severity_text = severity_map.get(severity, "Low")

                for cve_el in cve_elements:
                    cve_id = cve_el.text
                    results.append({
                        "ip_address": ip_address,
                        "hostname": hostname,
                        "operating_system": os_name,
                        "cve_id": cve_id,
                        "title": item.attrib.get('pluginName', 'Vulnerability'),
                        "description": item.find('description').text if item.find('description') is not None else None,
                        "cvss_score": cvss_score,
                        "severity": severity_text
                    })
    except Exception as e:
        print(f"Error parsing Nessus file: {e}")
    return results
