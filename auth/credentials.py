"""
Credential Manager for CamHunter v2.0
─────────────────────────────────────
Manages default credentials for various IP camera brands and models.
"""

import os
import logging
from typing import List, Dict, Optional

logger = logging.getLogger("camhunter.auth")

class CredentialManager:
    # Comprehensive database of default credentials
    DEFAULT_CREDS = {
        "common": [
            ("admin", "admin"), ("admin", "12345"), ("admin", "123456"),
            ("admin", ""), ("admin", "password"), ("root", "root"),
            ("root", ""), ("admin", "admin123"), ("admin", "1234"),
            ("admin", "888888"), ("admin", "666666"), ("user", "user")
        ],
        "hikvision": [
            ("admin", "12345"), ("admin", "hik12345"), ("admin", "admin12345"),
            ("admin", "beyond"), ("admin", "12345abc")
        ],
        "dahua": [
            ("admin", "admin"), ("888888", "888888"), ("666666", "666666"),
            ("admin", "dahua"), ("admin", "")
        ],
        "axis": [
            ("root", "pass"), ("root", "root"), ("root", ""), ("admin", "admin")
        ],
        "foscam": [
            ("admin", ""), ("admin", "foscam"), ("admin", "admin")
        ],
        "reolink": [
            ("admin", ""), ("admin", "admin")
        ],
        "amcrest": [
            ("admin", "admin"), ("admin", "password")
        ],
        "tp-link": [
            ("admin", "admin"), ("admin", "2011")
        ],
        "xmeye": [
            ("admin", ""), ("admin", "123456"), ("admin", "admin")
        ]
    }

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.wordlist_dir = os.path.join(os.path.dirname(__file__), "wordlists")
        if not os.path.exists(self.wordlist_dir):
            os.makedirs(self.wordlist_dir)

    def get_credentials(self, brand: Optional[str] = None, wordlist_path: Optional[str] = None) -> List[tuple]:
        """
        Retrieve a list of (username, password) tuples.
        Priority: 1. Custom Wordlist, 2. Brand-specific, 3. Common defaults.
        """
        creds = []

        # 1. Load from custom wordlist if provided
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if ":" in line:
                            u, p = line.strip().split(":", 1)
                            creds.append((u, p))
            except Exception as e:
                logger.error(f"Error reading wordlist: {e}")

        # 2. Add brand-specific credentials
        if brand:
            brand_lower = brand.lower()
            for b_name, b_creds in self.DEFAULT_CREDS.items():
                if b_name in brand_lower:
                    creds.extend(b_creds)

        # 3. Add common credentials
        creds.extend(self.DEFAULT_CREDS["common"])

        # Remove duplicates while preserving order
        unique_creds = []
        seen = set()
        for c in creds:
            if c not in seen:
                unique_creds.append(c)
                seen.add(c)

        return unique_creds
