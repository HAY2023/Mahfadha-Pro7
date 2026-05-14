"""
Proxy configuration for requests and sockets.
"""

import socks
import socket
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProxyManager:
    PROXY_TYPES = {
        "socks5": socks.SOCKS5,
        "socks4": socks.SOCKS4,
        "http":   socks.HTTP,
    }

    def __init__(self, cfg: dict):
        self.enabled = cfg.get("enabled", False)
        self.proxy_type = cfg.get("type", "socks5")
        self.host = cfg.get("host", "127.0.0.1")
        self.port = cfg.get("port", 9050)
        self.username = cfg.get("username")
        self.password = cfg.get("password")

    def get_requests_proxies(self) -> dict:
        if not self.enabled:
            return {}

        auth = ""
        if self.username and self.password:
            auth = f"{self.username}:{self.password}@"

        proxy_url = f"{self.proxy_type}://{auth}{self.host}:{self.port}"
        return {
            "http": proxy_url,
            "https": proxy_url,
        }

    def patch_socket(self):
        if not self.enabled:
            return

        proxy_type = self.PROXY_TYPES.get(self.proxy_type, socks.SOCKS5)
        socks.set_default_proxy(
            proxy_type,
            self.host,
            self.port,
            username=self.username,
            password=self.password,
        )
        socket.socket = socks.socksocket

    def unpatch_socket(self):
        socket.socket = socks.socksocket.__bases__[0]

    def get_session(self):
        import requests
        session = requests.Session()
        if self.enabled:
            session.proxies = self.get_requests_proxies()
        session.verify = False
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0.0.0 Safari/537.36",
        })
        return session
