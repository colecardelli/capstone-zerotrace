import os
import re
import ipaddress
import platform
import socket
import subprocess
import ctypes
import shutil
import json
from datetime import datetime
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party libs (must be installed)
import scapy.all as scapy
import nmap
import openpyxl
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TimeRemainingColumn


import sys
sys.stdout.reconfigure(encoding='utf-8')

console = Console()



# ---------------------------
# Config
# ---------------------------
CONFIG = {
    "excel_output": "zerotrace_report.xlsx",
    "device_thread_workers": 20,
    "scan_thread_workers": 30,
    "ping_count": 3,
    "nmap_timeout": 60,         # per-host timeout for nmap
    "max_service_version_len": 120
}

# ---------------------------
# OUI vendor map loading
# ---------------------------
OUI_VENDOR_MAP = {}
OUI_FILE_PATH = os.path.join(os.path.dirname(__file__), "oui.txt")

def load_oui_file():
    """Load IEEE OUI file (standards-oui.ieee.org format)."""
    global OUI_VENDOR_MAP
    if not os.path.exists(OUI_FILE_PATH):
        console.print("[yellow]oui.txt not found — vendor lookups may be limited.[/yellow]")
        return
    try:
        count = 0
        with open(OUI_FILE_PATH, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                # typical IEEE format: "00-11-22   (hex)    Vendor Name"
                if "(hex)" in line:
                    parts = line.strip().split("(hex)")
                    if len(parts) == 2:
                        prefix = parts[0].strip().replace("-", "").replace(":", "").upper()[:6]
                        vendor = parts[1].strip()
                        if prefix:
                            OUI_VENDOR_MAP[prefix] = vendor
                            count += 1
        console.print(f"[green]Loaded {count:,} OUIs from oui.txt[/green]")
    except Exception as e:
        console.print(f"[red]Failed to load OUI file: {e}[/red]")

def mac_vendor_lookup(mac: str) -> tuple[str, int]:
    """
    Return (vendor_name, confidence_percent).
    Confidence:
      - 95-100%: matched via local OUI file
      - 80%: matched via external API
      - 30-50%: heuristics (partial match)
      - 0%: unknown
    """
    if not mac:
        return ("Unknown Vendor", 0)
    mac_norm = mac.upper().replace(":", "").replace("-", "")
    prefix = mac_norm[:6]
    vendor = OUI_VENDOR_MAP.get(prefix)
    if vendor:
        return (vendor, 98)
    # try external API
    try:
        r = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if r.status_code == 200 and r.text.strip():
            return (r.text.strip(), 80)
    except Exception:
        pass
    # heuristic: try partial OUI match (first 5 hex chars) maybe lower confidence
    try:
        for k, v in OUI_VENDOR_MAP.items():
            if mac_norm.startswith(k[:5]):
                return (v, 40)
    except Exception:
        pass
    return ("Unknown Vendor", 0)

# ---------------------------
# System / Network helpers
# ---------------------------
def is_admin() -> bool:
    try:
        return os.getuid() == 0
    except AttributeError:  # windows
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

def get_local_ip() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return None
    finally:
        s.close()

def get_wifi_ssid() -> str | None:
    """Return SSID if connected to Wi-Fi on Windows (or Linux)."""
    try:
        system = platform.system().lower()
        if system == "windows":
            out = subprocess.check_output("netsh wlan show interfaces", shell=True, universal_newlines=True, stderr=subprocess.DEVNULL)
            m = re.search(r"SSID\s*:\s(.+)", out)
            return m.group(1).strip() if m else None
        else:
            out = subprocess.check_output("iwgetid -r", shell=True, universal_newlines=True, stderr=subprocess.DEVNULL)
            s = out.strip()
            return s or None
    except Exception:
        return None

def get_connection_type() -> str:
    """Naive check: if SSID present => Wi-Fi, else check ethernet state on Windows."""
    try:
        ssid = get_wifi_ssid()
        if ssid:
            return "Wi-Fi"
        system = platform.system().lower()
        if system == "windows":
            out = subprocess.check_output("netsh interface show interface", shell=True, universal_newlines=True, stderr=subprocess.DEVNULL)
            if "Ethernet" in out and "Connected" in out:
                return "Ethernet"
    except Exception:
        pass
    return "Unknown"

# ---------------------------
# Discovery methods
# ---------------------------
def arp_discover(network_cidr: str):
    console.print(f"[cyan]Running ARP discovery on {network_cidr}...[/cyan]")
    arp = scapy.ARP(pdst=network_cidr)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    try:
        answered = scapy.srp(packet, timeout=3, verbose=False)[0]
    except Exception as e:
        console.print(f"[yellow]ARP failed: {e}[/yellow]")
        return []
    devices = []
    for _, r in answered:
        devices.append({"ip": r.psrc, "mac": (r.hwsrc or "").upper(), "info": None})
    console.print(f"[green]ARP discovered {len(devices)} devices[/green]")
    return devices

def nmap_discover(network_cidr: str):
    nm = nmap.PortScanner()
    if not shutil.which("nmap"):
        console.print("[yellow]nmap binary not found — falling back to ARP[/yellow]")
        return arp_discover(network_cidr)
    console.print(f"[cyan]Running nmap discovery (-sn) on {network_cidr}...[/cyan]")
    try:
        nm.scan(hosts=network_cidr, arguments="-sn")
        devices = []
        for host in nm.all_hosts():
            mac = ""
            try:
                mac = nm[host]["addresses"].get("mac", "").upper()
            except Exception:
                mac = ""
            devices.append({"ip": host, "mac": mac, "info": nm[host]})
        console.print(f"[green]nmap discovered {len(devices)} hosts[/green]")
        return devices
    except Exception as e:
        console.print(f"[yellow]nmap discovery error: {e} — using ARP[/yellow]")
        return arp_discover(network_cidr)

# ---------------------------
# Per-host nmap wrapper (for deeper enrichment)
# ---------------------------
def nmap_scan_host(ip: str, mode: str = "quick"):
    """Return parsed host object (or None). mode 'deep' uses version/os/vuln scripts."""
    nm = nmap.PortScanner()
    try:
        if mode == "quick":
            # Include -O for OS detection even in quick mode
            args = "-sS -T4 --top-ports 20 -O -Pn"
        else:
            # deep includes service/version, OS/fingerprinting and vuln scripts
            args = "-sS -sV -O --osscan-guess --top-ports 200 --script vuln -Pn"
        nm.scan(ip, arguments=args, timeout=CONFIG["nmap_timeout"])
        if ip in nm.all_hosts():
            return nm[ip]
        return None
    except Exception as e:
        # nmap may raise on permissions or timeout
        # return None, caller will handle
        return None

# ---------------------------
# Ping helpers (latency + packet loss + ttl)
# ---------------------------
def ping_device(ip: str, count: int = None):
    """Return (avg_ms, loss_percent, ttl) or (None, None, None). Windows-style ping parsing used."""
    if count is None:
        count = CONFIG["ping_count"]
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", str(count), ip]
    else:
        cmd = ["ping", "-c", str(count), ip]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, universal_newlines=True, timeout=15)
    except Exception:
        return (None, None, None)
    avg = None
    loss = None
    ttl = None
    # Windows parse
    if system == "windows":
        m_avg = re.search(r"Average = (\d+)ms", out)
        m_loss = re.search(r"Lost = \d+.*,\s+(\d+)% loss", out) or re.search(r"Lost = \d+.*,\s+Lost% = (\d+)%", out)
        m_ttl = re.search(r"TTL=(\d+)", out)
        if m_avg:
            try:
                avg = float(m_avg.group(1))
            except Exception:
                avg = None
        if m_loss:
            try:
                loss = float(m_loss.group(1))
            except Exception:
                loss = None
        if m_ttl:
            try:
                ttl = int(m_ttl.group(1))
            except Exception:
                ttl = None
    else:
        m_avg = re.search(r"rtt [\w/]+ = [\d\.]+/([\d\.]+)/", out)
        m_loss = re.search(r"(\d+)% packet loss", out)
        m_ttl = re.search(r"time=(?:[\d\.]+) ms\s+ttl=(\d+)", out) or re.search(r"ttl=(\d+)", out)
        if m_avg:
            try:
                avg = float(m_avg.group(1))
            except Exception:
                avg = None
        if m_loss:
            try:
                loss = float(m_loss.group(1))
            except Exception:
                loss = None
        if m_ttl:
            try:
                ttl = int(m_ttl.group(1))
            except Exception:
                ttl = None
    return (avg, loss, ttl)

# ---------------------------
# Role & OS inference + confidence scoring
# ---------------------------
def infer_role_and_confidence(vendor: str, os_name: str, open_ports: list, ttl: int | None) -> tuple[str, int]:
    """
    Heuristic role inference using vendor, OS, ports, TTL.
    Returns (role, confidence_percent)
    """
    v = (vendor or "").lower()
    o = (os_name or "").lower()
    ports = set(open_ports or [])
    score = 40  # base

    # strong indicators from ports (take precedence)
    if any(p in ports for p in (554, 8554, 5544)) or "camera" in o or "hikvision" in v or "axis" in v:
        return ("IP Camera", 95)
    if "printer" in v or 9100 in ports:
        return ("Printer", 93)
    if any(k in v for k in ("roku", "amazon", "chromecast", "philips")) or "smarttv" in o or "tv" in o:
        return ("Smart TV / Streaming Device", 90)
    
    # Alarm.com, Control4, and similar smart home devices
    if any(k in v for k in ("alarm.com", "control4", "nest", "aura")):
        return ("Smart Home Device", 90)
    
    if any(k in v for k in ("apple",)) and ("iphone" in o or "ipad" in o or "ios" in o):
        return ("Phone / Tablet (Apple)", 92)
    if any(k in v for k in ("samsung", "xiaomi", "huawei")) or "android" in o:
        return ("Phone / Tablet (Android)", 88)
    if any(k in v for k in ("cisco", "juniper", "netgear", "tp-link", "arris", "eero", "luxul", "ubiquiti")):
        return ("Router / Switch", 92)
    if "windows" in o or any(k in v for k in ("dell", "hp", "lenovo", "microsoft")):
        return ("Laptop / Desktop (Windows)", 85)
    if "mac os" in o or "darwin" in o:
        return ("Mac / macOS", 88)
    if "linux" in o or any(k in v for k in ("raspberry", "ubuntu", "debian", "centos", "red hat", "redhat")):
        # server vs IoT — if ports suggest server
        if any(p in ports for p in (22, 80, 443, 3306, 5432)):
            return ("Server / Linux Host", 90)
        return ("Linux / Embedded", 75)

    # TTL heuristics: many routers reply with TTL high/low? (weak)
    if ttl is not None:
        if ttl <= 64:
            score += 5
        elif ttl > 128:
            score += 3

    # port-based signals
    if 22 in ports and not (80 in ports or 443 in ports):
        return ("SSH Host / Appliance", 80)
    if 80 in ports or 443 in ports:
        return ("Web-Connected Device", 70)

    # fallback
    return ("Generic Device", min(95, score))

def os_confidence_from_nmap(nmap_host):
    """Return (os_guess, confidence). Heuristics: prefer nmap osmatch if present."""
    if not nmap_host:
        return ("Unknown", 0)
    try:
        # python-nmap exposes 'osmatch' as list
        osmatch = nmap_host.get("osmatch", [])
        if osmatch:
            name = osmatch[0].get("name", "Unknown")
            # nmap produces a 'accuracy' field sometimes
            acc = osmatch[0].get("accuracy")
            try:
                conf = int(acc) if acc is not None else 85
            except Exception:
                conf = 85
            return (name, conf)
        # fallback to osclass
        osclass = nmap_host.get("osclass", [])
        if osclass:
            fam = osclass[0].get("osfamily") or osclass[0].get("osgen") or "Unknown"
            conf = osclass[0].get("accuracy") or 70
            try:
                conf = int(conf)
            except Exception:
                conf = 70
            return (fam, conf)
    except Exception:
        pass
    return ("Unknown", 0)

# ---------------------------
# Vulnerability extraction helpers
# ---------------------------
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

def parse_nmap_scripts_for_cves(nmap_host):
    """Extract CVE IDs and short descriptions from nmap hostscript output (if present)."""
    results = []
    # hostscript is usually list of dict { 'id': 'vuln', 'output': '... CVE-...' }
    try:
        hostscript = nmap_host.get("hostscript", []) if nmap_host else []
    except Exception:
        hostscript = []
    for s in hostscript:
        out = (s.get("output") or "")
        # find CVE tokens
        cves = CVE_RE.findall(out)
        if cves:
            for cve in sorted(set(cves)):
                # extract small snippet containing cve
                m = re.search(r".{0,80}"+re.escape(cve)+r".{0,80}", out, re.IGNORECASE)
                snippet = m.group(0).strip() if m else out[:120].strip()
                # form "CVE-xxxx-xxxx - snippet" (normalize newlines safely)
                snippet_clean = snippet.replace("\n", " ").strip()
                readable = f"{cve} - {snippet_clean}"
                results.append(readable)
        else:
            # sometimes script output names a CVE-like description
            if len(out) > 10:
                results.append(out.strip()[:200])
    # also check scripts listed in 'script' keys in services
    try:
        services = nmap_host.get("tcp", {}) if nmap_host else {}
        for port, svc in services.items():
            scripts = svc.get("script", {}) if isinstance(svc.get("script", {}), dict) else svc.get("script", [])
            # script may be dict or list
            if isinstance(scripts, dict):
                for k, v in scripts.items():
                    text = v if isinstance(v, str) else str(v)
                    cves = CVE_RE.findall(text)
                    if cves:
                        for cve in sorted(set(cves)):
                            m = re.search(r".{0,80}"+re.escape(cve)+r".{0,80}", text, re.IGNORECASE)
                            snippet = m.group(0).strip() if m else text[:120].strip()
                            snippet_clean = snippet.replace("\n", " ").strip()
                            results.append(f"{cve} - {snippet_clean}")
                    elif text:
                        results.append(text.strip()[:200])
            elif isinstance(scripts, list):
                for item in scripts:
                    text = item.get("output") if isinstance(item, dict) else str(item)
                    cves = CVE_RE.findall(text)
                    if cves:
                        for cve in sorted(set(cves)):
                            m = re.search(r".{0,80}"+re.escape(cve)+r".{0,80}", text, re.IGNORECASE)
                            snippet = m.group(0).strip() if m else text[:120].strip()
                            snippet_clean = snippet.replace("\n", " ").strip()
                            results.append(f"{cve} - {snippet_clean}")
                    elif text:
                        results.append(text.strip()[:200])
    except Exception:
        pass

    # dedupe & limit
    seen = []
    for r in results:
        if r not in seen:
            seen.append(r)
    return seen[:10]

# ---------------------------
# Service versions summarization
# ---------------------------
def summarize_service_versions(nmap_host):
    """Return short summary string of services/products and versions."""
    if not nmap_host:
        return "None"
    services = []
    try:
        tcp = nmap_host.get("tcp", {}) or {}
        for port_s, info in tcp.items():
            try:
                port = int(port_s)
            except Exception:
                continue
            state = info.get("state", "")
            if state != "open":
                continue
            name = info.get("name") or ""
            product = info.get("product") or ""
            version = info.get("version") or ""
            extr = f"{product} {version}".strip()
            if extr:
                services.append(f"{port}/{name} ({extr})")
            else:
                services.append(f"{port}/{name}")
    except Exception:
        pass
    if not services:
        return "None"
    joined = "; ".join(services)
    if len(joined) > CONFIG["max_service_version_len"]:
        joined = joined[:CONFIG["max_service_version_len"]-3] + "..."
    return joined

# ---------------------------
# Per-device enrichment
# ---------------------------
def enrich_device(device: dict, mode: str = "quick"):
    ip = device.get("ip")
    mac = device.get("mac") or ""
    result = {
        "ip": ip,
        "mac": mac,
        "vendor": "Unknown",
        "vendor_conf": 0,
        "hostname": "",
        "os": "Unknown",
        "os_conf": 0,
        "role": "Generic Device",
        "role_conf": 0,
        "latency_ms": "N/A",
        "packet_loss": "N/A",
        "ttl": None,
        "open_ports": "None",
        "services": "None",
        "vulnerabilities": "None",
        "discovered_at": datetime.utcnow().isoformat() + "Z",
        "last_seen_at": datetime.utcnow().isoformat() + "Z"
    }

    # vendor
    try:
        vendor, vconf = mac_vendor_lookup(mac)
        result["vendor"] = vendor
        result["vendor_conf"] = vconf
    except Exception:
        pass

    # ping
    try:
        avg, loss, ttl = ping_device(ip)
        result["latency_ms"] = f"{avg:.1f} ms" if avg is not None else "N/A"
        result["packet_loss"] = f"{loss:.0f}%" if loss is not None else "N/A"
        result["ttl"] = ttl
    except Exception:
        pass

    # nmap deep/quick
    ndata = None
    try:
        ndata = nmap_scan_host(ip, mode)
    except Exception:
        ndata = None

    # OS guess & confidence
    try:
        os_guess, os_conf = os_confidence_from_nmap(ndata)
        result["os"] = os_guess or "Unknown"
        result["os_conf"] = os_conf or 0
    except Exception:
        pass

    # open ports & service versions
    try:
        sv = summarize_service_versions(ndata)
        result["services"] = sv
        # build open ports list
        open_ports = []
        if ndata:
            tcp = ndata.get("tcp", {}) or {}
            for p, info in tcp.items():
                try:
                    if info.get("state") == "open":
                        open_ports.append(int(p))
                except Exception:
                    continue
        result["open_ports"] = ", ".join(map(str, sorted(open_ports))) if open_ports else "None"
    except Exception:
        pass

    # vulnerabilities / CVEs
    try:
        cves = parse_nmap_scripts_for_cves(ndata)
        if cves:
            result["vulnerabilities"] = "; ".join(cves)
        else:
            # heuristics: if dangerous ports open, flag potential issues
            op = [int(p) for p in (result["open_ports"].split(", ") if result["open_ports"] and result["open_ports"] != "None" else []) if p]
            weak_ports = []
            if 23 in op:
                weak_ports.append("Telnet open (plaintext)")
            if 21 in op:
                weak_ports.append("FTP open (plaintext)")
            if 445 in op:
                weak_ports.append("SMB exposed")
            if weak_ports:
                result["vulnerabilities"] = "; ".join(weak_ports)
    except Exception:
        pass

    # hostname
    try:
        hostname = None
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = None
        # netbios fallback (Windows)
        if not hostname:
            try:
                nb = subprocess.check_output(["nbtstat", "-A", ip], universal_newlines=True, stderr=subprocess.DEVNULL, timeout=3)
                m = re.search(r"^\s*([A-Z0-9_\-]+)\s+<00>", nb, re.MULTILINE)
                if m:
                    hostname = m.group(1)
            except Exception:
                hostname = hostname
        result["hostname"] = hostname or ip
    except Exception:
        result["hostname"] = ip

    # infer role with confidence
    try:
        open_ports_list = []
        if result["open_ports"] and result["open_ports"] != "None":
            open_ports_list = [int(p) for p in result["open_ports"].split(",") if p and p.strip().isdigit()]
        role, rconf = infer_role_and_confidence(result["vendor"], result["os"], open_ports_list, result["ttl"])
        result["role"] = role
        result["role_conf"] = rconf
    except Exception:
        result["role"] = "Generic Device"
        result["role_conf"] = 30

    return result

# ---------------------------
# Parallel enrichment wrapper
# ---------------------------
def enrich_devices(devices: list, mode: str):
    enriched = []
    with ThreadPoolExecutor(max_workers=CONFIG["device_thread_workers"]) as ex:
        futures = {ex.submit(enrich_device, d, mode): d for d in devices}
        with Progress(SpinnerColumn(), "[progress.description]{task.description}", BarColumn(), "{task.completed}/{task.total}", TimeRemainingColumn()) as prog:
            task = prog.add_task("Enriching devices", total=len(futures))
            '''
            for fut in as_completed(futures):
                try:
                    enriched.append(fut.result())
                except Exception:
                    enriched.append(futures[fut])
            '''
    for fut in as_completed(futures):
        try:
            res = fut.result()
            enriched.append(res)
            progress_data = {
                "current": len(enriched),
                "total": len(futures),
                "ip": res.get("ip")
            }
            print("PROGRESS " + json.dumps(progress_data), flush=True)
        except Exception:
            enriched.append(futures[fut])

        prog.update(task, advance=1)
    return enriched

# ---------------------------
# Export helpers (Excel/CSV/JSON)
# ---------------------------
def save_excel(devices: list, path: str):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Scan Report"
    headers = [
        "IP", "MAC", "Vendor", "Vendor_Confidence", "Hostname",
        "OS", "OS_Confidence", "Role", "Role_Confidence",
        "Latency_ms", "Packet_Loss", "Open_Ports", "Services",
        "Vulnerabilities", "Discovered_At", "Last_Seen"
    ]
    ws.append(headers)
    for d in devices:
        row = [
            d.get("ip"), d.get("mac"), d.get("vendor"), d.get("vendor_conf"),
            d.get("hostname"), d.get("os"), d.get("os_conf"),
            d.get("role"), d.get("role_conf"),
            d.get("latency_ms"), d.get("packet_loss"),
            d.get("open_ports"), d.get("services"),
            d.get("vulnerabilities"), d.get("discovered_at"), d.get("last_seen_at")
        ]
        ws.append(row)

    # Access Points sheet
    try:
        aps = list_access_points()
        if aps:
            ws_ap = wb.create_sheet("Access Points")
            ws_ap.append(["SSID", "BSSID", "Signal", "Type"])
            ssid_groups = defaultdict(list)
            for ap in aps:
                ssid = ap.get("ssid") or "Unknown"
                ssid_groups[ssid].append(ap)
            for ap in aps:
                ssid = ap.get("ssid") or "Unknown"
                typ = "Mesh/Extender" if len(ssid_groups[ssid]) > 1 else "Primary"
                ws_ap.append([ap.get("ssid"), ap.get("bssid"), ap.get("signal"), typ])
            # If current connection, add
            cur = current_connection()
            if cur:
                ws_ap.append([])
                ws_ap.append(["Current Connection"])
                ws_ap.append(["SSID", cur.get("ssid"), cur.get("bssid"), cur.get("rate"), cur.get("signal")])
    except Exception:
        pass

    wb.save(path)
    console.print(f"[green]Excel saved to {os.path.abspath(path)}[/green]")

def save_csv(devices: list, path: str):
    import csv
    headers = [
        "IP", "MAC", "Vendor", "Vendor_Confidence", "Hostname",
        "OS", "OS_Confidence", "Role", "Role_Confidence",
        "Latency_ms", "Packet_Loss", "Open_Ports", "Services",
        "Vulnerabilities", "Discovered_At", "Last_Seen"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for d in devices:
            w.writerow([
                d.get("ip"), d.get("mac"), d.get("vendor"), d.get("vendor_conf"),
                d.get("hostname"), d.get("os"), d.get("os_conf"),
                d.get("role"), d.get("role_conf"),
                d.get("latency_ms"), d.get("packet_loss"),
                d.get("open_ports"), d.get("services"),
                d.get("vulnerabilities"), d.get("discovered_at"), d.get("last_seen_at")
            ])
    console.print(f"[green]CSV saved to {os.path.abspath(path)}[/green]")

def save_json(devices: list, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=2)
    console.print(f"[green]JSON saved to {os.path.abspath(path)}[/green]")

# ---------------------------
# Wi-Fi/AP helpers (Windows-focused)
# ---------------------------
def list_access_points():
    system = platform.system().lower()
    aps = []
    try:
        if system == "windows":
            out = subprocess.check_output("netsh wlan show networks mode=bssid", shell=True, universal_newlines=True, stderr=subprocess.DEVNULL)
            ssid = None
            bssid = None
            signal = None
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    ssid = line.split(":", 1)[1].strip()
                elif "BSSID" in line:
                    bssid = line.split(":", 1)[1].strip()
                elif "Signal" in line:
                    signal = line.split(":", 1)[1].strip()
                    if ssid and bssid:
                        aps.append({"ssid": ssid, "bssid": bssid, "signal": signal})
        else:
            out = subprocess.check_output("nmcli -t -f SSID,BSSID,SIGNAL dev wifi", shell=True, universal_newlines=True, stderr=subprocess.DEVNULL)
            for line in out.strip().split("\n"):
                parts = line.split(":")
                if len(parts) >= 3:
                    aps.append({"ssid": parts[0], "bssid": parts[1], "signal": parts[2]})
    except Exception:
        pass
    return aps

def current_connection():
    system = platform.system().lower()
    if system == "windows":
        try:
            out = subprocess.check_output("netsh wlan show interfaces", shell=True, universal_newlines=True, stderr=subprocess.DEVNULL)
            ssid = re.search(r"SSID\s*:\s(.+)", out)
            bssid = re.search(r"BSSID\s*:\s(.+)", out)
            rate = re.search(r"Receive rate \(Mbps\)\s*:\s(.+)", out)
            signal = re.search(r"Signal\s*:\s(.+)", out)
            return {
                "ssid": ssid.group(1).strip() if ssid else None,
                "bssid": bssid.group(1).strip() if bssid else None,
                "rate": rate.group(1).strip() if rate else None,
                "signal": signal.group(1).strip() if signal else None
            }
        except Exception:
            return None
    else:
        try:
            out = subprocess.check_output("iw dev wlan0 link", shell=True, universal_newlines=True, stderr=subprocess.DEVNULL)
            ssid = re.search(r"SSID: (.+)", out)
            bssid = re.search(r"Connected to (.+)", out)
            rate = re.search(r"tx bitrate: (.+)", out)
            return {
                "ssid": ssid.group(1).strip() if ssid else None,
                "bssid": bssid.group(1).strip() if bssid else None,
                "rate": rate.group(1).strip() if rate else None
            }
        except Exception:
            return None

# ---------------------------
# Main: Orchestration
# ---------------------------
def main():
    console.print("[bold cyan]ZeroTrace Enhanced Scanner — v4[/bold cyan]")
    admin = is_admin()
    if admin:
        console.print("[green]Running with administrator privileges[/green]")
    else:
        console.print("[yellow]Not running as administrator — some scans (OS detection / vuln scripts) may be limited.[/yellow]")

    load_oui_file()

    conn_type = get_connection_type()
    ssid = get_wifi_ssid() if conn_type == "Wi-Fi" else None
    console.print(f"[blue]Connection type:[/] {conn_type}")
    if ssid:
        console.print(f"[blue]Connected SSID:[/] {ssid}")

    # choose quick/deep/both
    mode = console.input("[cyan]Scan mode ([b]quick[/b]/[b]deep[/b]/[b]both[/b]) [quick]: ").strip().lower() or "quick"
    while mode not in ("quick", "deep", "both"):
        mode = console.input("[cyan]Choose 'quick', 'deep' or 'both': ").strip().lower()

    # choose discovery
    disc = console.input("[cyan]Discovery method ([b]nmap[/b]/[b]arp[/b]/[b]both[/b]) [nmap]: ").strip().lower() or "nmap"
    while disc not in ("nmap", "arp", "both"):
        disc = console.input("[cyan]Choose 'nmap', 'arp' or 'both': ").strip().lower()

    # choose export type (default excel)
    export_choice = console.input("[cyan]Export format ([b]excel[/b]/[b]csv[/b]/[b]json) [excel]: ").strip().lower() or "excel"
    while export_choice not in ("excel", "csv", "json"):
        export_choice = console.input("[cyan]Choose 'excel', 'csv' or 'json': ").strip().lower()

    local_ip = get_local_ip()
    if not local_ip:
        console.print("[red]Could not determine local IP address — aborting.[/red]")
        return
    network_cidr = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    console.print(f"[blue]Scanning subnet: {network_cidr}[/blue]")

    # discovery phase
    discovered = []
    if disc == "arp":
        discovered = arp_discover(network_cidr)
    elif disc == "nmap":
        discovered = nmap_discover(network_cidr)
    else:
        arp_list = arp_discover(network_cidr)
        nmap_list = nmap_discover(network_cidr)
        ipmap = {}
        for d in arp_list:
            ipmap[d["ip"]] = d
        for n in nmap_list:
            if n["ip"] not in ipmap:
                ipmap[n["ip"]] = n
            else:
                # prefer mac if missing
                if not ipmap[n["ip"]].get("mac") and n.get("mac"):
                    ipmap[n["ip"]]["mac"] = n.get("mac")
        discovered = list(ipmap.values())

    if not discovered:
        console.print("[red]No devices discovered.[/red]")
        return

    # scanning mode: if 'both', do quick discovery then deep enrichment (we pass mode accordingly)
    nmap_mode = "deep" if mode in ("deep", "both") else "quick"

    console.print(f"[cyan]Discovered {len(discovered)} devices — enriching (mode={nmap_mode})...[/cyan]")

    devices_enriched = enrich_devices(discovered, nmap_mode)

    # timestamp last seen/update
    ts = datetime.utcnow().isoformat() + "Z"
    for d in devices_enriched:
        d["last_seen_at"] = ts

    # Show table summary
    headers = ["IP", "Name", "Vendor (conf)", "OS (conf)", "Role (conf)", "Latency", "Packet Loss", "Open Ports", "Vulns"]
    tbl = Table(title="ZeroTrace Network Summary (preview)", show_lines=False)
    for h in headers:
        tbl.add_column(h, overflow="fold")
    for d in devices_enriched:
        vendor_conf = f"{d.get('vendor')} ({d.get('vendor_conf',0)}%)"
        os_conf = f"{d.get('os')} ({d.get('os_conf',0)}%)"
        role_conf = f"{d.get('role')} ({d.get('role_conf',0)}%)"
        tbl.add_row(
            str(d.get("ip") or ""),
            str(d.get("hostname") or ""),
            vendor_conf,
            os_conf,
            role_conf,
            str(d.get("latency_ms") or ""),
            str(d.get("packet_loss") or ""),
            str(d.get("open_ports") or ""),
            str(d.get("vulnerabilities") or "")
        )
    console.print(tbl)

    # Save report (default Excel in same folder)
    outname = CONFIG["excel_output"]
    if export_choice == "excel":
        save_excel(devices_enriched, outname)
    elif export_choice == "csv":
        outcsv = os.path.splitext(outname)[0] + ".csv"
        save_csv(devices_enriched, outcsv)
    else:
        outjson = os.path.splitext(outname)[0] + ".json"
        save_json(devices_enriched, outjson)

    console.print("[green]Done.[/green]")

if __name__ == "__main__":
    
    

    import sys
    if "--web" in sys.argv:
        # Run in web mode — return JSON instead of rich console output
        from io import StringIO
        import json
        try:
            load_oui_file()
            local_ip = get_local_ip()
            network_cidr = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
            devices = nmap_discover(network_cidr)
            if not devices:
                devices = arp_discover(network_cidr)
            enriched = enrich_devices(devices, "quick")
            for d in enriched:
                d["timestamp"] = datetime.utcnow().isoformat()

            # Write results to scan_results.json for web frontend
            results_path = os.path.join(os.path.dirname(__file__), "scan_results.json")
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump(enriched, f, indent=2)

            print(json.dumps(enriched, indent=2))
        except Exception as e:
            # Also write error to scan_results.json
            results_path = os.path.join(os.path.dirname(__file__), "scan_results.json")
            with open(results_path, "w", encoding="utf-8") as f:
                json.dump({"error": str(e)}, f)
            print(json.dumps({"error": str(e)}))
    else:
        main()
