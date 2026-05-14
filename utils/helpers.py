"""
Common utility functions.
"""

import re
import socket
import struct
import ipaddress
from typing import Optional


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def cidr_to_ip_list(cidr: str) -> list:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def get_local_ip() -> Optional[str]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def get_local_cidr() -> Optional[str]:
    ip = get_local_ip()
    if ip:
        parts = ip.rsplit(".", 1)
        return f"{parts[0]}.0/24"
    return None


def extract_between(text: str, start: str, end: str) -> Optional[str]:
    pattern = re.escape(start) + r"(.*?)" + re.escape(end)
    match = re.search(pattern, text, re.DOTALL)
    return match.group(1).strip() if match else None


def normalize_port(port) -> int:
    if isinstance(port, int):
        return port
    try:
        return int(str(port).strip())
    except (ValueError, TypeError):
        return 0


def safe_decode(data: bytes, encodings=("utf-8", "latin-1", "ascii")) -> str:
    for enc in encodings:
        try:
            return data.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return str(data)


def chunk_list(lst: list, size: int) -> list:
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def sanitize_filename(name: str) -> str:
    return re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
