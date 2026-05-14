"""
Network Scanner Module
──────────────────────
Async port scanning + service detection for IP cameras.
Supports CIDR ranges, single IPs, and file-based target lists.
"""

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set

import aiohttp

from utils.rate_limiter import RateLimiter
# from utils.proxy import ProxyRotator
from utils.helpers import is_valid_cidr, is_valid_ip, cidr_to_ip_list

logger = logging.getLogger("camhunter.scanner")


# ──────────────────────────────────────────────
#  Data Models
# ──────────────────────────────────────────────
@dataclass
class PortResult:
    port: int
    state: str  # "open", "closed", "filtered"
    service: str = ""
    banner: str = ""


@dataclass
class ScanResult:
    ip: str
    hostname: str = ""
    open_ports: List[PortResult] = field(default_factory=list)
    http_alive: bool = False
    http_title: str = ""
    http_server: str = ""
    http_status: int = 0
    response_time_ms: float = 0.0
    fingerprint_hints: Dict[str, str] = field(default_factory=dict)
    scan_time: float = 0.0

    @property
    def is_camera_candidate(self) -> bool:
        camera_keywords = [
            "camera", "ipcam", "hikvision", "dahua", "axis",
            "foscam", "amcrest", "reolink", "vivotek", "onvif",
            "dvr", "nvr", "webcam", "surveillance", "cctv",
            "avtech", "tp-link", "netcam", "tenvis", "wanscam",
            "yoosee", "vstarcam", "sricam", "escam", "hanbang",
        ]
        combined = (
            f"{self.http_title} {self.http_server} "
            f"{' '.join(self.fingerprint_hints.values())}"
        ).lower()
        return any(kw in combined for kw in camera_keywords)


# ──────────────────────────────────────────────
#  Scanner Engine
# ──────────────────────────────────────────────
class NetworkScanner:
    """Async network scanner with service detection."""

    CAMERA_PORTS = [80, 443, 554, 8080, 8443, 8554, 37777, 34567, 49152]
    COMMON_PATHS = [
        "/", "/login.htm", "/login.html", "/index.html",
        "/doc/page/login.asp", "/web/index.html",
        "/cgi-bin/magicBox.cgi?action=getSystemInfo",
    ]
    CAMERA_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36"
    }

    def __init__(self, config: dict):
        self.config = config
        scan_cfg = config.get("scanner", {})
        self.timeout = scan_cfg.get("timeout", 5)
        self.max_concurrent = scan_cfg.get("max_concurrent", 200)
        self.ports = scan_cfg.get("ports", self.CAMERA_PORTS)
        self.retries = scan_cfg.get("retries", 2)
        self.rate_limiter = RateLimiter(
            scan_cfg.get("rate_limit", 500)
        )
        # self.proxy_rotator: Optional[ProxyRotator] = None
        self._semaphore = asyncio.Semaphore(self.max_concurrent)
        self._results: List[ScanResult] = []
        self._scanned_count = 0
        self._total_targets = 0

        # if config.get("proxy", {}).get("enabled"):
        #     self.proxy_rotator = ProxyRotator(config["proxy"])

    # ──────────── Public API ────────────

    async def scan(
        self,
        targets: List[str],
        ports: Optional[List[int]] = None,
        progress_callback=None,
    ) -> List[ScanResult]:
        """
        Scan a list of targets (IPs, CIDRs, hostnames).
        Returns list of ScanResult for hosts with open ports.
        """
        if ports:
            self.ports = ports

        all_ips = self._expand_targets(targets)
        self._total_targets = len(all_ips)
        self._scanned_count = 0
        self._results = []

        logger.info(
            f"Starting scan: {self._total_targets} hosts, "
            f"{len(self.ports)} ports each"
        )

        connector = aiohttp.TCPConnector(
            limit=self.max_concurrent,
            ttl_dns_cache=300,
            ssl=False,
        )
        http_timeout = aiohttp.ClientTimeout(total=self.timeout + 2)

        async with aiohttp.ClientSession(
            connector=connector,
            timeout=http_timeout,
            headers=self.CAMERA_HEADERS,
        ) as session:
            tasks = []
            for ip in all_ips:
                task = asyncio.create_task(
                    self._scan_host(ip, session, progress_callback)
                )
                tasks.append(task)
            await asyncio.gather(*tasks, return_exceptions=True)

        alive = [r for r in self._results if r.open_ports]
        cameras = [r for r in alive if r.is_camera_candidate]

        logger.info(
            f"Scan complete: {len(alive)} alive hosts, "
            f"{len(cameras)} camera candidates"
        )
        return self._results

    # ──────────── Host Scanning ────────────

    async def _scan_host(
        self,
        ip: str,
        session: aiohttp.ClientSession,
        progress_callback=None,
    ) -> None:
        async with self._semaphore:
            await self.rate_limiter.acquire()
            start = time.monotonic()
            result = ScanResult(ip=ip)

            # reverse DNS (non-blocking)
            result.hostname = await self._reverse_dns(ip)

            # port scan
            port_tasks = [
                self._scan_port(ip, port) for port in self.ports
            ]
            port_results = await asyncio.gather(
                *port_tasks, return_exceptions=True
            )
            for pr in port_results:
                if isinstance(pr, PortResult) and pr.state == "open":
                    result.open_ports.append(pr)

            # HTTP probing on web ports
            web_ports = [
                p.port for p in result.open_ports
                if p.port in (80, 443, 8080, 8443, 8888, 81, 82, 9000)
            ]
            if web_ports:
                await self._http_probe(ip, web_ports, session, result)

            result.scan_time = round(
                (time.monotonic() - start) * 1000, 2
            )

            if result.open_ports:
                self._results.append(result)

            self._scanned_count += 1
            if progress_callback:
                progress_callback(self._scanned_count, self._total_targets)

    async def _scan_port(self, ip: str, port: int) -> PortResult:
        """TCP connect scan with retries."""
        for attempt in range(self.retries + 1):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                # grab banner
                banner = ""
                try:
                    writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                    await writer.drain()
                    data = await asyncio.wait_for(
                        writer.read(1024), timeout=2
                    )
                    banner = data.decode("utf-8", errors="replace").strip()
                except Exception:
                    pass
                finally:
                    writer.close()
                    await writer.wait_closed()

                service = self._identify_service(port, banner)
                return PortResult(
                    port=port,
                    state="open",
                    service=service,
                    banner=banner[:256],
                )
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                if attempt < self.retries:
                    await asyncio.sleep(0.3 * (attempt + 1))
                continue

        return PortResult(port=port, state="closed")

    # ──────────── HTTP Probing ────────────

    async def _http_probe(
        self,
        ip: str,
        ports: List[int],
        session: aiohttp.ClientSession,
        result: ScanResult,
    ) -> None:
        for port in ports:
            scheme = "https" if port in (443, 8443) else "http"
            base_url = f"{scheme}://{ip}:{port}"

            for path in self.COMMON_PATHS:
                url = f"{base_url}{path}"
                try:
                    proxy = None
                    # if self.proxy_rotator:
                    #     proxy = self.proxy_rotator.get_proxy()

                    async with session.get(
                        url, proxy=proxy, allow_redirects=True
                    ) as resp:
                        result.http_alive = True
                        result.http_status = resp.status
                        result.http_server = resp.headers.get(
                            "Server", ""
                        )

                        body = await resp.text(errors="replace")
                        result.http_title = self._extract_title(body)

                        # collect fingerprint hints
                        self._collect_hints(resp.headers, body, result)
                        return  # first successful probe is enough

                except Exception as exc:
                    logger.debug(f"HTTP probe failed {url}: {exc}")
                    continue

    # ──────────── Helpers ────────────

    def _expand_targets(self, targets: List[str]) -> List[str]:
        expanded: List[str] = []
        seen: Set[str] = set()
        for t in targets:
            try:
                network = ipaddress.ip_network(t, strict=False)
                for host in network.hosts():
                    ip_str = str(host)
                    if ip_str not in seen:
                        seen.add(ip_str)
                        expanded.append(ip_str)
            except ValueError:
                if t not in seen:
                    seen.add(t)
                    expanded.append(t)
        return expanded

    async def _reverse_dns(self, ip: str) -> str:
        try:
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(
                    None, socket.gethostbyaddr, ip
                ),
                timeout=2,
            )
            return result[0]
        except Exception:
            return ""

    @staticmethod
    def _identify_service(port: int, banner: str) -> str:
        port_map = {
            80: "http", 443: "https", 554: "rtsp",
            8080: "http-proxy", 8443: "https-alt",
            8554: "rtsp-alt", 37777: "dahua-dvr",
            34567: "xmeye", 49152: "upnp",
        }
        if banner:
            bl = banner.lower()
            if "rtsp" in bl:
                return "rtsp"
            if "http" in bl:
                return "http"
            if "ssh" in bl:
                return "ssh"
        return port_map.get(port, "unknown")

    @staticmethod
    def _extract_title(html: str) -> str:
        import re
        match = re.search(
            r"<title[^>]*>(.*?)</title>",
            html,
            re.IGNORECASE | re.DOTALL,
        )
        if match:
            title = match.group(1).strip()
            return title[:200]
        return ""

    @staticmethod
    def _collect_hints(
        headers: dict,
        body: str,
        result: ScanResult,
    ) -> None:
        server = headers.get("Server", "")
        if server:
            result.fingerprint_hints["server"] = server

        www_auth = headers.get("WWW-Authenticate", "")
        if www_auth:
            result.fingerprint_hints["auth_realm"] = www_auth

        powered = headers.get("X-Powered-By", "")
        if powered:
            result.fingerprint_hints["powered_by"] = powered

        body_lower = body.lower()
        vendor_markers = {
            "hikvision": ["hikvision", "webcomponents", "doc/page/login"],
            "dahua": ["dahua", "dhwebclientplugin", "magicbox"],
            "axis": ["axis communications", "vapix"],
            "foscam": ["foscam", "ipcamera"],
            "reolink": ["reolink"],
            "amcrest": ["amcrest"],
            "vivotek": ["vivotek"],
            "tp-link": ["tp-link", "tplink"],
            "avtech": ["avtech", "avn"],
        }
        for vendor, markers in vendor_markers.items():
            if any(m in body_lower for m in markers):
                result.fingerprint_hints["vendor_guess"] = vendor
                break
