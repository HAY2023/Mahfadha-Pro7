#!/usr/bin/env python3
"""
CamHunter v2.0 — IP Camera Discovery & Security Auditor
"""

import argparse
import sys
import os
import time
import yaml
import signal
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()

BANNER = r"""[bold cyan]
  ██████╗ █████╗ ███╗   ███╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔════╝██╔══██╗████╗ ████║██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║     ███████║██╔████╔██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║     ██╔══██║██║╚██╔╝██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ╚██████╗██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝
                       v2.0 — IP Camera Security Auditor
[/bold cyan]"""


def deep_merge(base: dict, override: dict) -> dict:
    merged = base.copy()
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


def load_config(config_path: str = "config.yaml") -> dict:
    defaults = {
        "network":  {"interface": None, "timeout": 5,
                     "ports": [80, 443, 554, 8080, 8443, 37777, 34567, 81, 9000]},
        "scanning": {"threads": 25, "rate_limit": 60, "retry_count": 3, "retry_backoff": 1.5},
        "brute":    {"max_threads": 10, "timeout": 10, "stop_on_first": True,
                     "protocols": ["http", "rtsp", "onvif"], "delay_between_attempts": 0.1},
        "proxy":    {"enabled": False, "type": "socks5", "host": "127.0.0.1",
                     "port": 9050, "username": None, "password": None},
        "logging":  {"level": "INFO", "file": "logs/camhunter.log",
                     "console": True, "max_file_size": 10485760, "backup_count": 5},
        "output":   {"directory": "results", "database": "results/cameras.db",
                     "snapshots": "results/snapshots", "format": ["json", "html"]},
    }
    if os.path.exists(config_path):
        with open(config_path, "r", encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
        return deep_merge(defaults, user_cfg)
    return defaults


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="camhunter",
        description="IP Camera Discovery & Security Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  camhunter scan --network 192.168.1.0/24
  camhunter scan --target 192.168.1.100
  camhunter scan --file targets.txt
  camhunter brute --target 192.168.1.100 --wordlist custom.txt
  camhunter full --network 192.168.1.0/24
  camhunter report --format html
        """,
    )

    p.add_argument("-c", "--config", default="config.yaml", help="Config file path")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug output")
    p.add_argument("-q", "--quiet", action="store_true", help="Minimal output")

    sub = p.add_subparsers(dest="command", help="Available commands")

    # ── scan ──
    scan_p = sub.add_parser("scan", help="Discover cameras on network")
    scan_target = scan_p.add_mutually_exclusive_group(required=True)
    scan_target.add_argument("-n", "--network", help="CIDR range (e.g. 192.168.1.0/24)")
    scan_target.add_argument("-t", "--target", help="Single IP or hostname")
    scan_target.add_argument("-f", "--file", help="File with targets (one per line)")
    scan_target.add_argument("--local", action="store_true", help="Auto-detect local network")
    scan_p.add_argument("--ports", nargs="+", type=int, help="Override scan ports")
    scan_p.add_argument("--threads", type=int, help="Override thread count")
    scan_p.add_argument("--timeout", type=int, help="Override timeout")

    # ── brute ──
    brute_p = sub.add_parser("brute", help="Brute-force camera credentials")
    brute_target = brute_p.add_mutually_exclusive_group(required=True)
    brute_target.add_argument("-t", "--target", help="Single IP")
    brute_target.add_argument("-f", "--file", help="File with targets")
    brute_target.add_argument("--db", action="store_true", help="Use cameras from database")
    brute_p.add_argument("-w", "--wordlist", help="Custom wordlist file")
    brute_p.add_argument("--protocols", nargs="+", choices=["http", "rtsp", "onvif"],
                         help="Protocols to brute")
    brute_p.add_argument("--threads", type=int, help="Override thread count")
    brute_p.add_argument("--delay", type=float, help="Delay between attempts (sec)")

    # ── full ──
    full_p = sub.add_parser("full", help="Full pipeline: scan → fingerprint → brute → report")
    full_target = full_p.add_mutually_exclusive_group(required=True)
    full_target.add_argument("-n", "--network", help="CIDR range")
    full_target.add_argument("-t", "--target", help="Single IP")
    full_target.add_argument("-f", "--file", help="File with targets")
    full_target.add_argument("--local", action="store_true", help="Auto-detect local network")
    full_p.add_argument("-w", "--wordlist", help="Custom wordlist")

    # ── report ──
    report_p = sub.add_parser("report", help="Generate report from database")
    report_p.add_argument("--format", choices=["json", "html", "csv"], default="html")
    report_p.add_argument("-o", "--output", help="Output file path")

    # ── resume ──
    sub.add_parser("resume", help="Resume last interrupted scan")

    return p


def ensure_directories(cfg: dict):
    dirs = [
        cfg["output"]["directory"],
        cfg["output"]["snapshots"],
        os.path.dirname(cfg["logging"]["file"]),
    ]
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)


def get_targets(args, cfg: dict) -> list:
    """Resolve target list from arguments."""
    from scanner.network import NetworkScanner

    net = NetworkScanner(cfg)

    if hasattr(args, "local") and args.local:
        return net.discover_local_range()

    if hasattr(args, "network") and args.network:
        return net.cidr_to_list(args.network)

    if hasattr(args, "target") and args.target:
        return [args.target.strip()]

    if hasattr(args, "file") and args.file:
        with open(args.file, "r") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    if hasattr(args, "db") and args.db:
        from reporting.database import Database
        db = Database(cfg["output"]["database"])
        return db.get_all_ips()

    return []


class CamHunter:
    def __init__(self, cfg: dict, args):
        self.cfg = cfg
        self.args = args
        self.start_time = None
        self._interrupted = False

        from reporting.logger import setup_logger
        self.log = setup_logger(cfg)

        from reporting.database import Database
        self.db = Database(cfg["output"]["database"])

    def _signal_handler(self, sig, frame):
        if not self._interrupted:
            self._interrupted = True
            console.print("\n[bold yellow]⚠ Interrupted — saving progress...[/bold yellow]")
            self.db.save_state({"phase": "interrupted", "timestamp": datetime.now().isoformat()})
            sys.exit(0)

    def run_scan(self, targets: list) -> list:
        from scanner.network import NetworkScanner
        from scanner.fingerprint import Fingerprinter

        net = NetworkScanner(self.cfg)
        fp = Fingerprinter(self.cfg)
        discovered = []

        console.print(f"\n[bold green]📡 Scanning {len(targets)} targets...[/bold green]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Port scanning", total=len(targets))

            alive_hosts = net.parallel_port_scan(targets, progress_callback=lambda: progress.advance(task))

        if not alive_hosts:
            console.print("[yellow]No cameras found with open ports.[/yellow]")
            return []

        console.print(f"\n[green]✓ {len(alive_hosts)} hosts with open camera ports[/green]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Fingerprinting", total=len(alive_hosts))

            for host_info in alive_hosts:
                camera = fp.identify(host_info)
                if camera:
                    discovered.append(camera)
                    self.db.insert_camera(camera)
                    self.log.info(f"Camera found: {camera['ip']} — {camera.get('brand','Unknown')}")
                progress.advance(task)

        self._display_scan_results(discovered)
        return discovered

    def run_brute(self, targets: list = None) -> list:
        from scanner.http_brute import HTTPBrute
        from scanner.rtsp import RTSPBrute
        from auth.credentials import CredentialManager

        cred_mgr = CredentialManager(self.cfg)
        cracked = []

        if targets is None:
            targets = self.db.get_uncracked_cameras()

        if not targets:
            console.print("[yellow]No targets for brute-force.[/yellow]")
            return []

        console.print(f"\n[bold red]🔓 Brute-forcing {len(targets)} cameras...[/bold red]\n")

        protocols = self.cfg["brute"]["protocols"]
        if hasattr(self.args, "protocols") and self.args.protocols:
            protocols = self.args.protocols

        custom_wordlist = None
        if hasattr(self.args, "wordlist") and self.args.wordlist:
            custom_wordlist = self.args.wordlist

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold red]{task.description}"),
            BarColumn(bar_width=40),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Cracking", total=len(targets))

            for cam in targets:
                ip = cam if isinstance(cam, str) else cam.get("ip", cam)
                result = {"ip": ip, "cracked": False, "credentials": []}

                brand = None
                if isinstance(cam, dict):
                    brand = cam.get("brand")

                creds = cred_mgr.get_credentials(brand=brand, wordlist_path=custom_wordlist)

                if "http" in protocols:
                    http_b = HTTPBrute(self.cfg)
                    http_result = http_b.attack(ip, creds)
                    if http_result:
                        result["cracked"] = True
                        result["credentials"].append({"proto": "http", **http_result})
                        self.log.info(f"HTTP cracked: {ip} → {http_result['username']}:{http_result['password']}")
                        if self.cfg["brute"]["stop_on_first"]:
                            cracked.append(result)
                            self.db.update_cracked(ip, result)
                            progress.advance(task)
                            continue

                if "rtsp" in protocols:
                    rtsp_b = RTSPBrute(self.cfg)
                    rtsp_result = rtsp_b.attack(ip, creds)
                    if rtsp_result:
                        result["cracked"] = True
                        result["credentials"].append({"proto": "rtsp", **rtsp_result})
                        self.log.info(f"RTSP cracked: {ip} → {rtsp_result['username']}:{rtsp_result['password']}")

                if result["cracked"]:
                    cracked.append(result)
                    self.db.update_cracked(ip, result)

                progress.advance(task)

        self._display_brute_results(cracked)
        return cracked

    def run_full(self, targets: list):
        self.start_time = time.time()

        # Phase 1: Scan
        cameras = self.run_scan(targets)

        if not cameras:
            console.print("[yellow]Pipeline stopped — no cameras discovered.[/yellow]")
            return

        # Phase 2: Brute
        cracked = self.run_brute(cameras)

        # Phase 3: Report
        self.run_report()

        elapsed = time.time() - self.start_time
        console.print(Panel(
            f"[bold green]Pipeline complete[/bold green]\n"
            f"Cameras found: {len(cameras)}\n"
            f"Credentials cracked: {len(cracked)}\n"
            f"Time elapsed: {elapsed:.1f}s",
            title="Summary",
            border_style="green",
        ))

    def run_report(self, fmt: str = None, output_path: str = None):
        from reporting.export import Exporter

        if fmt is None:
            fmt = self.cfg["output"]["format"][0] if self.cfg["output"]["format"] else "json"

        if hasattr(self.args, "format") and self.args.format:
            fmt = self.args.format

        exporter = Exporter(self.cfg, self.db)
        path = exporter.export(fmt=fmt, output_path=output_path)
        console.print(f"[green]📄 Report saved: {path}[/green]")

    def resume(self):
        state = self.db.load_state()
        if not state:
            console.print("[yellow]No interrupted session found.[/yellow]")
            return
        console.print(f"[cyan]Resuming from phase: {state.get('phase', 'unknown')}[/cyan]")
        remaining = self.db.get_unscanned_targets()
        if remaining:
            self.run_full(remaining)

    def _display_scan_results(self, cameras: list):
        if not cameras:
            return
        table = Table(title="Discovered Cameras", show_lines=True)
        table.add_column("IP", style="cyan", width=16)
        table.add_column("Port(s)", style="green", width=18)
        table.add_column("Brand", style="yellow", width=14)
        table.add_column("Model", style="white", width=20)
        table.add_column("Auth", style="red", width=10)

        for cam in cameras:
            ports = ", ".join(str(p) for p in cam.get("ports", []))
            table.add_row(
                cam.get("ip", "?"),
                ports,
                cam.get("brand", "Unknown"),
                cam.get("model", "—"),
                cam.get("auth_type", "?"),
            )
        console.print(table)

    def _display_brute_results(self, cracked: list):
        if not cracked:
            console.print("[yellow]No credentials cracked.[/yellow]")
            return
        table = Table(title="🔓 Cracked Credentials", show_lines=True)
        table.add_column("IP", style="cyan", width=16)
        table.add_column("Protocol", style="magenta", width=10)
        table.add_column("Username", style="green", width=16)
        table.add_column("Password", style="red", width=20)

        for entry in cracked:
            for cred in entry.get("credentials", []):
                table.add_row(
                    entry["ip"],
                    cred.get("proto", "?"),
                    cred.get("username", "?"),
                    cred.get("password", "?"),
                )
        console.print(table)


def main():
    console.print(BANNER)

    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    cfg = load_config(args.config)
    ensure_directories(cfg)

    # CLI overrides
    if hasattr(args, "threads") and args.threads:
        cfg["scanning"]["threads"] = args.threads
    if hasattr(args, "timeout") and args.timeout:
        cfg["network"]["timeout"] = args.timeout
    if hasattr(args, "ports") and args.ports:
        cfg["network"]["ports"] = args.ports
    if hasattr(args, "delay") and args.delay:
        cfg["brute"]["delay_between_attempts"] = args.delay
    if args.verbose:
        cfg["logging"]["level"] = "DEBUG"

    hunter = CamHunter(cfg, args)
    signal.signal(signal.SIGINT, hunter._signal_handler)

    try:
        if args.command == "scan":
            targets = get_targets(args, cfg)
            hunter.run_scan(targets)

        elif args.command == "brute":
            targets = get_targets(args, cfg)
            hunter.run_brute(targets)

        elif args.command == "full":
            targets = get_targets(args, cfg)
            hunter.run_full(targets)

        elif args.command == "report":
            output = args.output if hasattr(args, "output") else None
            hunter.run_report(output_path=output)

        elif args.command == "resume":
            hunter.resume()

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Aborted.[/bold yellow]")
        sys.exit(1)
    except Exception as exc:
        console.print(f"\n[bold red]Fatal: {exc}[/bold red]")
        if args.verbose:
            console.print_exception()
        sys.exit(1)


if __name__ == "__main__":
    main()
