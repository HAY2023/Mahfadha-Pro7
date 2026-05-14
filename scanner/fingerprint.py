"""
Camera Fingerprinting Module for CamHunter v2.0
───────────────────────────────────────────────
Identifies camera brands and models based on network responses.
"""

import logging
import re
from typing import Optional, Dict

logger = logging.getLogger("camhunter.fingerprint")

class Fingerprinter:
    # Vendor matching rules: (Marker in Header/Body, Brand Name)
    RULES = {
        "hikvision": [
            "hikvision", "webcomponents", "doc/page/login",
            "hik-server", "ivms-4200"
        ],
        "dahua": [
            "dahua", "dhwebclientplugin", "magicbox", "web-x.x.x",
            "login-form-dahua", "dvr-login"
        ],
        "axis": [
            "axis communications", "vapix", "axis-net-camera"
        ],
        "foscam": [
            "foscam", "ipcamera", "foscam-login"
        ],
        "reolink": [
            "reolink"
        ],
        "amcrest": [
            "amcrest"
        ],
        "vivotek": [
            "vivotek"
        ],
        "tp-link": [
            "tp-link", "tplink"
        ],
        "xmeye": [
            "xmeye", "dvr-login", "34567"
        ]
    }

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def identify(self, host_info: dict) -> Optional[dict]:
        """
        Takes host info (ip, open_ports, banner, etc.) and returns a camera dict.
        """
        ip = host_info.get("ip")
        banner = host_info.get("banner", "").lower()
        hints = host_info.get("fingerprint_hints", {})
        
        brand = "Unknown"
        model = host_info.get("model", "—")
        
        # Combine all searchable text
        search_text = (banner + " " + str(hints)).lower()
        
        # Match against rules
        for vendor, markers in self.RULES.items():
            if any(m in search_text for m in markers):
                brand = vendor.capitalize()
                break
                
        # Special case for ports
        if brand == "Unknown":
            ports = host_info.get("ports", [])
            if 37777 in ports: brand = "Dahua"
            elif 34567 in ports: brand = "XMEye"
            elif 8000 in ports: brand = "Hikvision"

        return {
            "ip": ip,
            "ports": host_info.get("ports", []),
            "brand": brand,
            "model": model,
            "auth_type": host_info.get("auth_type", "Basic/Digest"),
            "is_camera": True
        }
