#!/usr/bin/env python3
"""
Goomsy - Decorated Termux host checker + IP locator

Features / Decorations:
 - ASCII banner and version info
 - Colorized output (colorama)
 - Pretty tables (tabulate)
 - Spinner progress indicator for port scans
 - JSON / CSV export of results
 - Safe: no IMEI / precise GPS functionality. IP geolocation is approximate.
"""

import argparse
import csv
import json
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

# Third-party libs (requests, colorama, tabulate)
try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install with: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init as colorama_init
except Exception:
    print("Missing dependency 'colorama'. Install with: pip install colorama")
    sys.exit(1)

try:
    from tabulate import tabulate
except Exception:
    print("Missing dependency 'tabulate'. Install with: pip install tabulate")
    sys.exit(1)

colorama_init(autoreset=True)

VERSION = "1.3.0"
GEO_API = "http://ip-api.com/json/{}"  # free for non-commercial use
COMMON_PORTS = [21,22,23,25,53,80,110,143,443,587,3306,8080]

# ---------- Utilities & UI ----------
def banner():
    b = r"""
   ____    Goomsy made by Codeccia & Allin Isla Minde                  __
  / ___|___  _ __ ___  _ __ / _| ___  ___
 | |  _/ _ \| '_ ` _ \| '_ \ |_ / _ \/ __|
 | |_| | (_) | | | | | | |_) | ||  __/\__ \
  \____|\___/|_| |_| |_| .__/|_| \___||___/
                       |_|
    """
    print(Fore.CYAN + b + Style.BRIGHT + f" Goomsy {VERSION} — Termux host checker + IP locator\n" + Style.RESET_ALL)

def info(msg):
    print(Fore.CYAN + "[*] " + Style.RESET_ALL + str(msg))

def success(msg):
    print(Fore.GREEN + "[+] " + Style.RESET_ALL + str(msg))

def warn(msg):
    print(Fore.YELLOW + "[!] " + Style.RESET_ALL + str(msg))

def error(msg):
    print(Fore.RED + "[-] " + Style.RESET_ALL + str(msg))

# ---------- Network functions ----------
def resolve_host(host: str) -> Tuple[str, List[str]]:
    try:
        info = socket.gethostbyname_ex(host)
        ip = info[2][0] if info and info[2] else ""
        return ip, info[2] if info else []
    except Exception:
        return "", []

def ping_host(host: str, count: int = 3, timeout: int = 2) -> bool:
    # Use system ping (works in Termux). On some Android builds ping flags differ; we try common ones.
    commands = [
        ["ping", "-c", str(count), "-W", str(timeout), host],
        ["ping", "-c", str(count), host]
    ]
    for cmd in commands:
        try:
            proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return proc.returncode == 0
        except FileNotFoundError:
            break
        except Exception:
            continue
    # Fallback: simple socket connect to port 80 (non-ideal)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, 80))
        s.close()
        return True
    except Exception:
        return False

def parse_ports_arg(arg: str) -> List[int]:
    if not arg:
        return COMMON_PORTS
    arg = arg.strip()
    if "-" in arg:
        try:
            start, end = arg.split("-", 1)
            s, e = int(start), int(end)
            if e - s > 20000:
                warn("Large port range; limiting to first 2000 ports to avoid very long scans.")
                e = s + 1999
            return list(range(s, e+1))
        except Exception:
            return COMMON_PORTS
    if "," in arg:
        try:
            return [int(p) for p in arg.split(",") if p.strip()]
        except Exception:
            return COMMON_PORTS
    try:
        return [int(arg)]
    except Exception:
        return COMMON_PORTS

def port_scan_sync(ip: str, ports: List[int], timeout: float = 0.6):
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            r = s.connect_ex((ip, p))
            if r == 0:
                open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

# ---------- Spinner for long operations ----------
class Spinner:
    def __init__(self, message="Working"):
        self._running = False
        self._thread = None
        self.msg = message
        self.chars = "|/-\\"

    def _spin(self):
        i = 0
        while self._running:
            ch = self.chars[i % len(self.chars)]
            print(f"\r{Fore.MAGENTA}{self.msg} {ch}{Style.RESET_ALL}", end="", flush=True)
            i += 1
            time.sleep(0.12)
        print("\r" + " " * (len(self.msg) + 6) + "\r", end="", flush=True)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.5)

# ---------- Traceroute & WHOIS ----------
def traceroute(host: str) -> str:
    for cmd in (["traceroute", host], ["tracepath", host]):
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=40)
            if proc.returncode == 0 or proc.stdout:
                return proc.stdout.strip()
        except FileNotFoundError:
            continue
        except Exception:
            return "Traceroute failed or timed out."
    return "No traceroute/tracepath installed."

def whois_lookup(query: str) -> str:
    try:
        proc = subprocess.run(["whois", query], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)
        out = proc.stdout.strip()
        return out[:8000] + ("\n...output truncated..." if len(out) > 8000 else "")
    except FileNotFoundError:
        return "whois command not found. Install: pkg install whois"
    except Exception:
        return "WHOIS lookup failed."

# ---------- Geo lookup ----------
def ip_geolocate(ip: str) -> dict:
    try:
        resp = requests.get(GEO_API.format(ip), timeout=8)
        if resp.status_code != 200:
            return {"error": f"Geo API HTTP {resp.status_code}"}
        j = resp.json()
        if j.get("status") != "success":
            return {"error": j.get("message", "unknown")}
        return {
            "ip": j.get("query"),
            "country": j.get("country"),
            "countryCode": j.get("countryCode"),
            "region": j.get("regionName"),
            "city": j.get("city"),
            "zip": j.get("zip"),
            "timezone": j.get("timezone"),
            "lat": j.get("lat"),
            "lon": j.get("lon"),
            "isp": j.get("isp"),
            "org": j.get("org"),
            "as": j.get("as"),
        }
    except Exception as e:
        return {"error": str(e)}

# ---------- Export helpers ----------
def save_json(data: dict, path: Path):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        success(f"Saved JSON results to {path}")
    except Exception as e:
        error(f"Failed to save JSON: {e}")

def save_csv_portscan(ip: str, ports_open: List[int], path: Path):
    try:
        with open(path, "w", newline='', encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "open_port"])
            for p in ports_open:
                writer.writerow([ip, p])
        success(f"Saved CSV port-scan to {path}")
    except Exception as e:
        error(f"Failed to save CSV: {e}")

# ---------- Main CLI logic ----------
def main():
    banner()

    ap = argparse.ArgumentParser(prog="Goomsy", description="Goomsy — decorated Termux host checker + IP locator")
    ap.add_argument("--host", help="Domain or host to check (will resolve to IP)")
    ap.add_argument("--ip", help="IP address to operate on (skips DNS resolve)")
    ap.add_argument("--geo", action="store_true", help="Perform IP geolocation lookup")
    ap.add_argument("--ports", help="Port range or list e.g. 1-1024 or 22,80,443 (default: common ports)")
    ap.add_argument("--scan", action="store_true", help="Run port scan")
    ap.add_argument("--ping", action="store_true", help="Ping host")
    ap.add_argument("--whois", action="store_true", help="Run whois")
    ap.add_argument("--traceroute", action="store_true", help="Run traceroute")
    ap.add_argument("--json", help="Save results to JSON file (path)")
    ap.add_argument("--csv", help="Save port scan results to CSV file (path)")
    ap.add_argument("--timeout", type=float, default=0.6, help="Socket timeout for port scanning (seconds)")
    ap.add_argument("--no-spinner", action="store_true", help="Disable spinner during long actions")
    args = ap.parse_args()

    timestamp = datetime.utcnow().isoformat() + "Z"
    results = {"meta": {"tool": "Goomsy", "version": VERSION, "timestamp": timestamp}, "target": {}, "port_scan": {}, "geo": {}, "whois": None, "traceroute": None}

    target_ip = ""
    target_host = args.host if args.host else None

    if args.ip:
        target_ip = args.ip
        results["target"]["input"] = args.ip
        info(f"Target IP: {args.ip}")
    elif args.host:
        ip, all_ips = resolve_host(args.host)
        if not ip:
            error("Could not resolve host.")
        else:
            target_ip = ip
            results["target"]["input"] = args.host
            results["target"]["resolved_ip"] = ip
            results["target"]["aliases"] = all_ips
            success(f"Resolved {args.host} -> {ip}")
    else:
        warn("No --host or --ip provided. Provide one to run checks.")
        print("\nExample: python goomsy.py --host example.com --ping --geo --scan --ports 1-1024\n")
        return

    # Ping
    if args.ping and (target_ip or target_host):
        to_ping = target_host if target_host else target_ip
        info(f"Pinging {to_ping} ...")
        ok = ping_host(to_ping)
        results["target"]["ping"] = bool(ok)
        if ok:
            success(f"{to_ping} is reachable")
        else:
            warn(f"{to_ping} appears unreachable")

    # Traceroute
    if args.traceroute and (target_ip or target_host):
        info("Running traceroute (may require traceroute/tracepath installed)...")
        tr = traceroute(target_host if target_host else target_ip)
        results["traceroute"] = tr
        print(Fore.MAGENTA + "\nTraceroute output:\n" + Style.RESET_ALL)
        print(tr[:5000] + ("\n...truncated..." if len(tr) > 5000 else ""))

    # WHOIS
    if args.whois:
        q = target_host if target_host else target_ip
        if not q:
            warn("Provide --host or --ip for whois.")
        else:
            info("Performing WHOIS (may require 'whois' to be installed)...")
            w = whois_lookup(q)
            results["whois"] = w
            print(Fore.MAGENTA + "\nWHOIS (truncated):\n" + Style.RESET_ALL)
            print(w)

    # Geo lookup
    if args.geo:
        if not target_ip:
            warn("No IP to geolocate. Provide --ip or --host.")
        else:
            info("Querying IP geolocation (approximate) ...")
            geo = ip_geolocate(target_ip)
            results["geo"] = geo
            if "error" in geo:
                error("Geo lookup failed: " + geo["error"])
            else:
                geo_table = [
                    ["IP", geo.get("ip")],
                    ["Country", f"{geo.get('country')} ({geo.get('countryCode')})"],
                    ["Region/City", f"{geo.get('region')} / {geo.get('city')}"],
                    ["Lat, Lon", f"{geo.get('lat')}, {geo.get('lon')}"],
                    ["Timezone", geo.get("timezone")],
                    ["ISP / Org", f"{geo.get('isp')} / {geo.get('org')}"],
                ]
                print("\n" + tabulate(geo_table, tablefmt="plain"))

    # Port scan
    if args.scan:
        if not target_ip:
            warn("No IP to scan. Provide --ip or --host.")
        else:
            ports = parse_ports_arg(args.ports)
            info(f"Scanning {target_ip} — {len(ports)} ports (this may take a while)...")
            spinner = None
            if not args.no_spinner:
                spinner = Spinner(message="Scanning ports")
                spinner.start()
            start = time.time()
            open_ports = port_scan_sync(target_ip, ports, timeout=args.timeout)
            duration = time.time() - start
            if spinner:
                spinner.stop()
            results["port_scan"] = {"ports_tested": len(ports), "open_ports": open_ports, "duration_seconds": round(duration, 2)}
            if open_ports:
                success(f"Found {len(open_ports)} open port(s): {', '.join(map(str, open_ports))}")
                table = [[p, "open"] for p in open_ports]
                print("\n" + tabulate(table, headers=["Port", "Status"], tablefmt="github"))
            else:
                warn("No open ports found in scanned list.")

    # Save outputs
    if args.json:
        try:
            p = Path(args.json).expanduser()
            save_json(results, p)
        except Exception as e:
            error(f"Could not write JSON: {e}")

    if args.csv:
        if "port_scan" in results and results["port_scan"].get("open_ports"):
            try:
                p = Path(args.csv).expanduser()
                save_csv_portscan(target_ip, results["port_scan"]["open_ports"], p)
            except Exception as e:
                error(f"Could not write CSV: {e}")
        else:
            warn("No port-scan data to write to CSV. Run with --scan and find open ports first.")

    info("Done. Stay legal: only scan targets you own or have permission to test.")
    info("Reminder: IP geolocation is approximate — not precise GPS. No IMEI / personal-identifying device data is obtainable via IP alone.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        error("Interrupted by user. Exiting.")
        sys.exit(1)
