import requests
from typing import List, Dict, Any

class CrowdstrikeClient:
    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = "https://api.crowdstrike.com"

    def fetch_vulnerabilities(self) -> List[Dict[str, Any]]:
        return [
            {
                "ip_address": "10.0.2.15",
                "hostname": "win-prod-db-01",
                "operating_system": "Windows Server 2019",
                "cve_id": "CVE-2023-24897",
                "title": "Microsoft .NET Framework Remote Code Execution Vulnerability",
                "description": "A remote code execution vulnerability exists in .NET Framework.",
                "cvss_score": 7.8,
                "severity": "High"
            }
        ]
