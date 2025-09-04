'''
import subprocess
import re
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from mac_vendor_lookup import MacLookup
import nmap
from rich.console import Console
from rich.progress import track
import ipaddress

console = Console()
mac_lookup = MacLookup()
nm = nmap.PortScanner()

# Hardcoded risky ports for risk assessment
RISKY_PORTS = {
    23: "Telnet", 21: "FTP", 139: "SMB", 445: "SMB",
    3389: "RDP", 5900: "VNC", 3306: "MySQL", 27017: "MongoDB", 1900: "UPnP"
}
HIGH_RISK_PORTS = [23, 21, 3389, 5900]

# IoT MAC prefixes
IOT_MAC_PREFIXES = {
    "AC:63:BE": "Amazon Smart Speaker",
    "D0:73:D5": "Google Smart Hub",
    "B8:27:EB": "Raspberry Pi",
    "00:1A:11": "Philips Smart Light",
    "F0:27:2D": "TP-Link Smart Plug",
    "3C:5A:B4": "Wyze IP Camera"
}

# Ports to scan
PORTS_TO_SCAN = list(RISKY_PORTS.keys()) + [80, 443, 22, 554, 1883, 8883]
PORTS_STR = ",".join(map(str, sorted(PORTS_TO_SCAN)))


def get_network_range():
    """Detect local IP and subnet automatically."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network = ipaddress.IPv4Network(local_ip + '/24', strict=False)
        return network
    except Exception as e:
        console.print(f"[red][!] Could not detect network: {e}[/red]")
        return None


def arp_scan():
    """Use ARP to discover devices on the network (IP + MAC)."""
    network = get_network_range()
    if not network:
        return []

    try:
        output = subprocess.check_output(
            ["arp", "-a"], universal_newlines=True
        )
        devices = []
        for line in output.splitlines():
            match = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9:-]{17})", line, re.I)
            if match:
                ip, mac = match.groups()
                devices.append({"ip": ip, "mac": mac.upper()})
        return devices
    except Exception as e:
        console.print(f"[red][!] ARP scan failed: {e}[/red]")
        return []


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "-"


def identify_iot(mac, open_ports):
    if mac != "-":
        prefix = mac[:8]
        for k, v in IOT_MAC_PREFIXES.items():
            if prefix.startswith(k):
                return v
    for port in open_ports:
        if port in [554, 1883, 8883]:
            return "Unknown IoT Device"
    return "-"


def assess_risk(host):
    reasons = []
    for p in host['ports']:
        if p['port'] in RISKY_PORTS and p['state'] == 'open':
            reasons.append(f"{RISKY_PORTS[p['port']]} port open")
    if any(p['port'] in HIGH_RISK_PORTS for p in host['ports']):
        return "HIGH ⚠️", reasons
    elif reasons:
        return "Medium", reasons
    else:
        return "Low", reasons


def scan_device(device):
    ip, mac = device['ip'], device['mac']
    try:
        nm.scan(hosts=ip, arguments=f'-sS -sV -O -Pn -T4 -p{PORTS_STR}')
    except Exception as e:
        console.print(f"[red][!] Nmap scan failed for {ip}: {e}[/red]")
        return None

    host_info = {
        'ip': ip,
        'hostname': get_hostname(ip),
        'mac': mac,
        'vendor': '-',
        'os': '-',
        'ports': [],
        'iot': None,
        'risk_level': "Low",
        'risk_reasons': []
    }

    # Vendor lookup
    try:
        if mac != "-":
            host_info['vendor'] = mac_lookup.lookup(mac)
    except:
        host_info['vendor'] = "Unknown Vendor"

    if ip in nm.all_hosts():
        # OS info
        if "osmatch" in nm[ip] and nm[ip]['osmatch']:
            host_info['os'] = f"{nm[ip]['osmatch'][0]['name']} ({nm[ip]['osmatch'][0]['accuracy']}% confidence)"
        # Ports info
        open_ports = []
        for proto in nm[ip].all_protocols():
            for port, svc in nm[ip][proto].items():
                host_info['ports'].append({
                    'port': port,
                    'state': svc['state'],
                    'name': svc.get('name', ''),
                    'product': svc.get('product', '')
                })
                if svc['state'] == 'open':
                    open_ports.append(port)
        host_info['iot'] = identify_iot(mac, open_ports)

    host_info['risk_level'], host_info['risk_reasons'] = assess_risk(host_info)
    return host_info


def scan_network():
    """ARP discover devices, then scan them with Nmap."""
    devices = arp_scan()
    all_devices = []

    console.print(f"[blue]Discovered {len(devices)} devices. Running detailed scans...[/blue]")

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(scan_device, dev): dev['ip'] for dev in devices}
        for future in track(as_completed(futures), total=len(futures), description="[green]Scanning devices...[/green]"):
            try:
                host = future.result()
                if host:
                    all_devices.append(host)
            except Exception as e:
                console.print(f"[red][!] Error scanning device: {e}[/red]")

    return all_devices


def generate_report(all_devices):
    filename = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w', encoding="utf-8") as f:
        for h in all_devices:
            f.write("="*30 + "\n")
            f.write(f"Device: {h['ip']}\n")
            f.write("="*30 + "\n")
            f.write(f"Hostname: {h['hostname']}\n")
            f.write(f"MAC Address: {h['mac']}\n")
            f.write(f"Vendor: {h['vendor']}\n")
            f.write(f"Operating System: {h['os']}\n")
            if h['ports']:
                f.write("Open Ports:\n")
                for p in h['ports']:
                    name = f"({p['name']})" if p['name'] else ""
                    product = f"{p['product']}" if p['product'] else ""
                    f.write(f"  - {p['port']}/tcp {name} {product}\n")
            f.write(f"Device Type / IoT: {h['iot']}\n")
            f.write(f"Risk Level: {h['risk_level']}\n")
            if h['risk_reasons']:
                f.write("Reasons:\n")
                for r in h['risk_reasons']:
                    f.write(f"  - {r}\n")
            f.write("\n---------------------------\n\n")
    console.print(f"[green]Detailed scan report saved as {filename}[/green]")


if __name__ == "__main__":
    console.print("[blue]Detecting network and scanning all devices...[/blue]")
    devices = scan_network()
    generate_report(devices)

'''
'''
import subprocess
import re
import socket
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from mac_vendor_lookup import MacLookup
import nmap
from rich.console import Console
from rich.progress import track
import ipaddress
import time

console = Console()
mac_lookup = MacLookup()

# ----------------------------
# Risk & Detection Dictionaries
# ----------------------------
RISKY_PORTS = {
    23: "Telnet", 21: "FTP", 139: "NetBIOS/SMB", 445: "SMB",
    3389: "RDP", 5900: "VNC", 3306: "MySQL", 27017: "MongoDB", 1900: "UPnP"
}
HIGH_RISK_PORTS = [23, 21, 3389, 5900]

# IoT MAC prefixes (quick hints)
IOT_MAC_PREFIXES = {
    "AC:63:BE": "Amazon Smart Speaker",
    "D0:73:D5": "Google Smart Hub",
    "B8:27:EB": "Raspberry Pi",
    "00:1A:11": "Philips Smart Light",
    "F0:27:2D": "TP-Link Smart Plug",
    "3C:5A:B4": "Wyze IP Camera",
    "00:19:D2": "Alarm.com"
}

# Extra OUI fallbacks for vendor labeling (helps when MacLookup misses)
OUI_FALLBACK = {
    "0019D2": "Alarm.com",
    "B827EB": "Raspberry Pi Foundation",
    "F8E079": "Apple, Inc.",
    "00163E": "Samsung Electronics",
    "0003FF": "Hewlett-Packard",
    "3C5A37": "Amazon Technologies",
    "D850E6": "Microsoft"
}

# Ports to scan (tune for speed/coverage)
PORTS_TO_SCAN = sorted(set(list(RISKY_PORTS.keys()) + [80, 443, 22, 554, 1883, 8883]))
PORTS_STR = ",".join(map(str, PORTS_TO_SCAN))

# ----------------------------
# Network Helpers
# ----------------------------
def get_network_range():
    """
    Detect local IP and assume /24 network.
    (Simple, works well on home/LANs. For other masks, extend to parse netmask.)
    """
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        network = ipaddress.IPv4Network(local_ip + '/24', strict=False)
        return network
    except Exception as e:
        console.print(f"[red][!] Could not detect network: {e}[/red]")
        return None

def all_ips_in_network():
    net = get_network_range()
    if not net:
        return []
    return [str(ip) for ip in net.hosts()]

def ping_host(ip: str, timeout_ms: int = 300) -> bool:
    """
    Send one ping to prime ARP table. Works without admin.
    Returns True if ping command exits 0 (not required for ARP priming).
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            # -n 1 one echo, -w timeout ms
            result = subprocess.run(["ping", "-n", "1", "-w", str(timeout_ms), ip],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            # -c 1 one echo, -W timeout s (round up)
            result = subprocess.run(["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def prime_arp_table():
    """
    Ping-sweep the /24 quickly to populate the ARP cache,
    then we can read 'arp -a' and get IP->MAC (like Fing/OPNsense discovery).
    """
    ips = all_ips_in_network()
    if not ips:
        return
    console.print(f"[blue]Priming ARP table with a quick ping sweep over {len(ips)} hosts...[/blue]")
    # Use a modest pool to avoid flooding Wi-Fi
    with ThreadPoolExecutor(max_workers=64) as pool:
        list(track(pool.map(ping_host, ips), total=len(ips), description="[green]Pinging...[/green]"))
    # Give OS a brief moment to settle ARP entries
    time.sleep(0.5)

def normalize_mac(mac: str) -> str:
    mac = mac.strip().upper().replace("-", ":")
    return mac

def parse_windows_arp() -> list:
    """
    Parse `arp -a` on Windows:
    Internet Address      Physical Address      Type
    192.168.1.1           aa-bb-cc-dd-ee-ff    dynamic
    Returns list of dicts: {ip, mac, arp_type}
    """
    devices = []
    try:
        output = subprocess.check_output(["arp", "-a"], universal_newlines=True, errors="ignore")
        for line in output.splitlines():
            # Match lines like: "  192.168.1.1        aa-bb-cc-dd-ee-ff     dynamic"
            m = re.search(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([a-f0-9:-]{17})\s+(\w+)\s*$", line, re.I)
            if m:
                ip, mac, arp_type = m.groups()
                devices.append({"ip": ip, "mac": normalize_mac(mac), "arp_type": arp_type.lower()})
    except Exception as e:
        console.print(f"[red][!] ARP parse failed: {e}[/red]")
    return devices

def parse_unix_arp() -> list:
    """
    Parse `arp -a` on Unix-like systems:
    ? (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on en0
    """
    devices = []
    try:
        output = subprocess.check_output(["arp", "-a"], universal_newlines=True, errors="ignore")
        for line in output.splitlines():
            m = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([a-f0-9:]{17})", line, re.I)
            if m:
                ip, mac = m.groups()
                devices.append({"ip": ip, "mac": normalize_mac(mac), "arp_type": "dynamic"})
    except Exception as e:
        console.print(f"[red][!] ARP parse failed: {e}[/red]")
    return devices

def arp_scan() -> list:
    system = platform.system().lower()
    return parse_windows_arp() if system == "windows" else parse_unix_arp()

# ----------------------------
# Hostname & Vendor Resolution
# ----------------------------
def get_reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "-"

def get_netbios_name(ip: str) -> str | None:
    """
    Windows NetBIOS name via nbtstat (helps for Windows devices when PTR isn't set)
    """
    if platform.system().lower() != "windows":
        return None
    try:
        out = subprocess.check_output(["nbtstat", "-A", ip], universal_newlines=True, errors="ignore")
        # Look for the UNIQUE <00> entry which is the machine name
        m = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", out, re.I | re.M)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None

def robust_hostname(ip: str, nm_host_obj=None) -> str:
    # Try reverse DNS 
    name = get_reverse_dns(ip)
    if name and name != "-":
        return name
    # Try NetBIOS (Windows)
    nb = get_netbios_name(ip)
    if nb:
        return nb
    # Try Nmap’s detected hostname if available
    try:
        if nm_host_obj is not None:
            nm_name = nm_host_obj.hostname()
            if nm_name:
                return nm_name
    except Exception:
        pass
    return "-"

def resolve_vendor(mac: str) -> str:
    if not mac or mac == "-":
        return "-"
    # Try mac_vendor_lookup library first
    try:
        v = mac_lookup.lookup(mac)
        if v and isinstance(v, str):
            return v
    except Exception:
        pass
    # Fallback OUI map
    prefix = mac.replace(":", "")[:6]
    return OUI_FALLBACK.get(prefix, "Unknown Vendor")

# ----------------------------
# Classification & Risk
# ----------------------------
def identify_iot(mac: str, open_ports: list[int]) -> str:
    if mac and mac != "-":
        prefix = mac[:8]
        for k, v in IOT_MAC_PREFIXES.items():
            if prefix.startswith(k):
                return v
    # Heuristics by ports
    if 554 in open_ports or any(8000 <= p <= 8090 for p in open_ports):
        return "Unknown IoT Device (Camera)"
    if 1883 in open_ports or 8883 in open_ports:
        return "Unknown IoT Device (MQTT)"
    return "-"

def assess_risk(host: dict) -> tuple[str, list[str]]:
    reasons = []
    for p in host['ports']:
        if p['state'] == 'open' and p['port'] in RISKY_PORTS:
            reasons.append(f"{RISKY_PORTS[p['port']]} port open")
    # Prioritize dangerous ones
    if any(p['state'] == 'open' and p['port'] in HIGH_RISK_PORTS for p in host['ports']):
        return "HIGH ⚠️", reasons
    elif reasons:
        return "Medium", reasons
    else:
        return "Low", reasons

# ----------------------------
# Scanning
# ----------------------------
def scan_device(device: dict) -> dict | None:
    """
    Nmap detailed scan for one IP.
    Use a per-thread PortScanner to avoid thread-safety issues.
    """
    ip = device['ip']
    mac = device.get('mac', "-")
    arp_type = device.get('arp_type', "dynamic")

    nm = nmap.PortScanner()
    try:
        # -Pn: skip ICMP host discovery (some LANs block ping)
        # -T4: faster (adjust if you want slower/more reliable)
        nm.scan(hosts=ip, arguments=f'-sS -sV -O -Pn -T4 -p{PORTS_STR}')
    except Exception as e:
        console.print(f"[red][!] Nmap scan failed for {ip}: {e}[/red]")
        nm = None  # Keep nm None for safety

    host_info = {
        'ip': ip,
        'hostname': "-",
        'mac': mac,
        'vendor': resolve_vendor(mac),
        'os': "-",
        'ports': [],
        'iot': "-",
        'risk_level': "Low",
        'risk_reasons': [],
        'lease_type': "Dynamic" if arp_type.lower() == "dynamic" else "Static",
        'lease_state': "Active/Bound"
    }

    if nm and ip in nm.all_hosts():
        # OS info
        try:
            if "osmatch" in nm[ip] and nm[ip]['osmatch']:
                best = nm[ip]['osmatch'][0]
                host_info['os'] = f"{best['name']} ({best.get('accuracy','?')}% confidence)"
        except Exception:
            pass

        # Ports info
        open_ports = []
        try:
            for proto in nm[ip].all_protocols():
                for port, svc in nm[ip][proto].items():
                    entry = {
                        'port': port,
                        'state': svc.get('state', ''),
                        'name': svc.get('name', ''),
                        'product': svc.get('product', '')
                    }
                    host_info['ports'].append(entry)
                    if entry['state'] == 'open':
                        open_ports.append(port)
        except Exception:
            pass

        # Hostname (robust)
        try:
            host_info['hostname'] = robust_hostname(ip, nm[ip])
        except Exception:
            host_info['hostname'] = robust_hostname(ip, None)

        # IoT classification
        host_info['iot'] = identify_iot(mac, open_ports)

    else:
        # Even if nmap didn't recognize, still try to resolve name
        host_info['hostname'] = robust_hostname(ip, None)

    # Risk
    host_info['risk_level'], host_info['risk_reasons'] = assess_risk(host_info)
    return host_info

def scan_network() -> list[dict]:
    """
    1) Ping sweep to populate ARP
    2) Parse ARP table for IP/MAC + arp_type
    3) Run detailed scans in parallel
    """
    prime_arp_table()
    devices = arp_scan()
    console.print(f"[blue]Discovered {len(devices)} devices via ARP. Running detailed scans...[/blue]")

    all_devices = []
    if not devices:
        return all_devices

    # Tune parallelism for speed vs reliability
    with ThreadPoolExecutor(max_workers=32) as pool:
        futures = {pool.submit(scan_device, dev): dev['ip'] for dev in devices}
        for future in track(as_completed(futures), total=len(futures), description="[green]Scanning devices...[/green]"):
            try:
                host = future.result()
                if host:
                    all_devices.append(host)
            except Exception as e:
                console.print(f"[red][!] Error scanning device: {e}[/red]")
    return all_devices

# ----------------------------
# Reporting
# ----------------------------
def generate_report(all_devices: list[dict]):
    filename = f"network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w', encoding="utf-8") as f:
        for h in all_devices:
            f.write("="*27 + "\n")
            f.write(f"Device: {h['ip']}\n")
            f.write("="*27 + "\n")
            f.write(f"Hostname: {h['hostname']}\n")
            f.write(f"MAC Address: {h['mac']}\n")
            f.write(f"Vendor: {h['vendor']}\n")
            f.write(f"Lease Type: {h['lease_type']}\n")
            f.write(f"Lease State: {h['lease_state']}\n")
            f.write(f"Operating System: {h['os']}\n")
            if h['ports']:
                f.write("Open Ports:\n")
                for p in h['ports']:
                    name = f"({p['name']})" if p.get('name') else ""
                    product = f"{p['product']}" if p.get('product') else ""
                    state = p.get('state', '')
                    if state == 'open':
                        f.write(f"  - {p['port']}/tcp {name} {product}\n")
            f.write(f"Device Type / IoT: {h['iot']}\n")
            f.write(f"Risk Level: {h['risk_level']}\n")
            if h['risk_reasons']:
                f.write("Reasons:\n")
                for r in h['risk_reasons']:
                    f.write(f"  - {r}\n")
            f.write("\n---------------------------\n\n")
    console.print(f"[green]Detailed scan report saved as {filename}[/green]")

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    console.print("[blue]Detecting network, discovering devices, and running deep scans...[/blue]")
    devices = scan_network()
    generate_report(devices)


'''

'''
import scapy.all as scapy
import socket
import ipaddress
import nmap
from rich.console import Console
from rich.table import Table
from collections import defaultdict

console = Console()

# ----------------------
# Phase 1 - Device Discovery & Scan
# ----------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def arp_scan(network):
    console.print(f"[cyan]Running ARP scan on {network}...[/cyan]")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def scan_device(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="-sV --host-timeout 20s")
        if ip in nm.all_hosts():
            return nm[ip]
    except Exception as e:
        console.print(f"[red]Error scanning {ip}: {e}[/red]")
    return None

def scan_network():
    local_ip = get_local_ip()
    network = str(ipaddress.ip_network(local_ip + "/24", strict=False))
    devices = arp_scan(network)
    results = []
    for device in devices:
        info = scan_device(device["ip"])
        if info:
            results.append({"ip": device["ip"], "mac": device["mac"], "info": info})
    return results

# ----------------------
# Phase 2 - Traffic Capture
# ----------------------
def capture_traffic(duration=60):
    console.print(f"[cyan]Sniffing network traffic for {duration} seconds...[/cyan]")
    packets = scapy.sniff(timeout=duration)
    communications = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            communications[src].add(dst)
            communications[dst].add(src)
    return communications

# ----------------------
# Risk Analysis Helpers
# ----------------------
def is_iot_device(info):
    if not info: return False
    for proto in info.all_protocols():
        if proto in ["http", "rtsp", "mqtt"]:
            return True
    return False

def analyze_risks(info):
    risks = []
    if not info:
        return ["No data"]
    for proto in info.all_protocols():
        for port in info[proto].keys():
            state = info[proto][port]["state"]
            service = info[proto][port].get("name", "?")
            if state == "open":
                if port in [23, 21]:
                    risks.append(f"Weak service: {service} (port {port})")
                elif port in [80, 443]:
                    risks.append("Web interface exposed")
    if not risks:
        risks.append("No obvious risks detected")
    return risks

# ----------------------
# Report Generation
# ----------------------
def generate_report(devices, communications):
    table = Table(title="ZeroTrace Network Report")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Open Ports / Services", style="green")
    table.add_column("IoT?", style="yellow")
    table.add_column("Risk Analysis", style="red")
    table.add_column("Communications", style="blue")

    for dev in devices:
        ip = dev["ip"]
        mac = dev["mac"]
        info = dev["info"]
        ports = []
        if info:
            for proto in info.all_protocols():
                for port in info[proto].keys():
                    service = info[proto][port].get("name", "?")
                    ports.append(f"{port}/{proto} ({service})")
        iot = "Yes" if is_iot_device(info) else "No"
        risks = "\n".join(analyze_risks(info))

        # Communications section
        comms = []
        if ip in communications:
            for peer in communications[ip]:
                try:
                    socket.inet_aton(peer)
                    peer_type = "Internal" if peer.startswith("192.168.") or peer.startswith("10.") or peer.startswith("172.") else "External"
                    comms.append(f"{peer} [{peer_type}]")
                except:
                    continue
        comms_str = "\n".join(comms) if comms else "No traffic observed"

        table.add_row(ip, mac, "\n".join(ports) if ports else "None", iot, risks, comms_str)

    console.print(table)

# ----------------------
# Main Entry
# ----------------------
if __name__ == "__main__":
    console.print("[blue]Detecting network, discovering devices, and running deep scans...[/blue]")
    devices = scan_network()
    communications = capture_traffic(duration=60)
    generate_report(devices, communications)
'''
'''

import scapy.all as scapy
import socket
import ipaddress
import nmap
from rich.console import Console
from rich.table import Table
from rich.progress import track, Progress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

console = Console()

# ----------------------
# Phase 1 - Device Discovery & Scan
# ----------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def arp_scan(network):
    console.print(f"[cyan]Running ARP scan on {network}...[/cyan]")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def scan_device(ip):
    nm = nmap.PortScanner()
    try:
        # Use faster scanning with reduced service detection
        nm.scan(
            ip, 
            arguments="-sS -F --host-timeout 10s -T4",  # Faster TCP SYN scan with fast mode
            timeout=20
        )
        if ip in nm.all_hosts():
            return nm[ip]
    except Exception as e:
        console.print(f"[yellow][!] {ip} did not respond or scan timed out. Error: {e}[/yellow]")
    return None

def scan_network():
    local_ip = get_local_ip()
    network = str(ipaddress.ip_network(local_ip + "/24", strict=False))
    devices = arp_scan(network)
    
    results = []
    console.print(f"[cyan]Discovered {len(devices)} devices, beginning fast scans...[/cyan]")
    
    # Use thread pool for parallel scanning
    with Progress() as progress:
        task = progress.add_task("[blue]Scanning devices...", total=len(devices))
        
        with ThreadPoolExecutor(max_workers=20) as executor:  # Limit threads to avoid overwhelming network
            future_to_device = {
                executor.submit(scan_device, device["ip"]): device 
                for device in devices
            }
            
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    info = future.result(timeout=30)  # Add timeout to prevent hanging
                    results.append({"ip": device["ip"], "mac": device["mac"], "info": info})
                except Exception as e:
                    console.print(f"[red][!] Error scanning {device['ip']}: {e}[/red]")
                    results.append({"ip": device["ip"], "mac": device["mac"], "info": None})
                
                progress.update(task, advance=1)
    
    return results

# ----------------------
# Phase 2 - Traffic Capture
# ----------------------
def capture_traffic(duration=60):
    console.print(f"[cyan]Sniffing network traffic for {duration} seconds...[/cyan]")
    packets = scapy.sniff(timeout=duration)
    communications = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            communications[src].add(dst)
            communications[dst].add(src)
    return communications

# ----------------------
# Risk Analysis Helpers
# ----------------------
def is_iot_device(info):
    if not info: return False
    for proto in info.all_protocols():
        if proto in ["http", "rtsp", "mqtt"]:
            return True
    return False

def analyze_risks(info):
    risks = []
    if not info:
        return ["Unreachable"]
    for proto in info.all_protocols():
        for port in info[proto].keys():
            state = info[proto][port]["state"]
            service = info[proto][port].get("name", "?")
            if state == "open":
                if port in [23, 21]:
                    risks.append(f"Weak service: {service} (port {port})")
                elif port in [80, 443]:
                    risks.append("Web interface exposed")
    if not risks:
        risks.append("No obvious risks detected")
    return risks

# ----------------------
# Report Generation
# ----------------------
def generate_report(devices, communications):
    table = Table(title="ZeroTrace Network Report")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Open Ports / Services", style="green")
    table.add_column("IoT?", style="yellow")
    table.add_column("Risk Analysis", style="red")
    table.add_column("Communications", style="blue")

    for dev in devices:
        ip = dev["ip"]
        mac = dev["mac"]
        info = dev["info"]
        ports = []
        if info:
            for proto in info.all_protocols():
                for port in info[proto].keys():
                    service = info[proto][port].get("name", "?")
                    ports.append(f"{port}/{proto} ({service})")
        iot = "Yes" if is_iot_device(info) else "No"
        risks = "\n".join(analyze_risks(info))

        # Communications section
        comms = []
        if ip in communications:
            for peer in communications[ip]:
                try:
                    socket.inet_aton(peer)
                    peer_type = "Internal" if peer.startswith("192.168.") or peer.startswith("10.") or peer.startswith("172.") else "External"
                    comms.append(f"{peer} [{peer_type}]")
                except:
                    continue
        comms_str = "\n".join(comms) if comms else "No traffic observed"

        table.add_row(ip, mac, "\n".join(ports) if ports else "None", iot, risks, comms_str)

    console.print(table)

# ----------------------
# Main Entry
# ----------------------
if __name__ == "__main__":
    console.print("[blue]Detecting network, discovering devices, and running fast scans...[/blue]")
    devices = scan_network()
    communications = capture_traffic(duration=60)
    console.print("[green]\n✔ Scan complete. Generating report...[/green]")
    generate_report(devices, communications)
'''
'''
import scapy.all as scapy
import socket
import ipaddress
import nmap
from rich.console import Console
from rich.table import Table
from rich.progress import track, Progress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import requests

console = Console()

# ----------------------
# Phase 1 - Device Discovery & Scan
# ----------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def get_external_ip():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except:
        return None

def arp_scan(network):
    console.print(f"[cyan]Running ARP scan on {network}...[/cyan]")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def scan_device(ip):
    nm = nmap.PortScanner()
    try:
        # Use faster scanning with reduced service detection
        nm.scan(
            ip, 
            arguments="-sS -F --host-timeout 10s -T4",  # Faster TCP SYN scan with fast mode
            timeout=20
        )
        if ip in nm.all_hosts():
            return nm[ip]
    except Exception as e:
        console.print(f"[yellow][!] {ip} did not respond or scan timed out. Error: {e}[/yellow]")
    return None

def scan_network():
    local_ip = get_local_ip()
    network = str(ipaddress.ip_network(local_ip + "/24", strict=False))
    devices = arp_scan(network)
    
    results = []
    console.print(f"[cyan]Discovered {len(devices)} devices, beginning fast scans...[/cyan]")
    
    # Use thread pool for parallel scanning
    with Progress() as progress:
        task = progress.add_task("[blue]Scanning devices...", total=len(devices))
        
        with ThreadPoolExecutor(max_workers=20) as executor:  # Limit threads to avoid overwhelming network
            future_to_device = {
                executor.submit(scan_device, device["ip"]): device 
                for device in devices
            }
            
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    info = future.result(timeout=30)  # Add timeout to prevent hanging
                    results.append({"ip": device["ip"], "mac": device["mac"], "info": info})
                except Exception as e:
                    console.print(f"[red][!] Error scanning {device['ip']}: {e}[/red]")
                    results.append({"ip": device["ip"], "mac": device["mac"], "info": None})
                
                progress.update(task, advance=1)
    
    return results

# ----------------------
# Phase 2 - Traffic Capture
# ----------------------
def get_network_range():
    local_ip = get_local_ip()
    return ipaddress.ip_network(local_ip + "/24", strict=False)

def capture_traffic(duration=60):
    console.print(f"[cyan]Sniffing network traffic for {duration} seconds...[/cyan]")
    packets = scapy.sniff(timeout=duration)
    communications = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            communications[src].add(dst)
            communications[dst].add(src)
    return communications

# ----------------------
# Risk Analysis Helpers
# ----------------------
def is_iot_device(info):
    if not info: return False
    for proto in info.all_protocols():
        if proto in ["http", "rtsp", "mqtt"]:
            return True
    return False

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        return response.text
    except:
        return None

def is_internal_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback
    except:
        return False

def is_external_ip(ip, local_network):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Check if it's in our local network
        if ip_obj in local_network:
            return False
        # Check if it's a private address (not external)
        if ip_obj.is_private or ip_obj.is_loopback:
            return False
        return True
    except:
        return False

def analyze_risks(info):
    risks = []
    if not info:
        return ["Unreachable"]
    
    # Check for common vulnerable services
    vulnerable_ports = {
        21: "FTP (potentially insecure)",
        23: "Telnet (plaintext credentials)",
        53: "DNS (potential DNS tunneling)",
        111: "RPC (potential remote code execution)",
        135: "RPC (potential remote code execution)",
        139: "NetBIOS (potential remote code execution)",
        445: "SMB (potential remote code execution)",
        515: "LPD (potential printer exploitation)",
        993: "IMAPS (unencrypted SSL/TLS incompatibility)",
        995: "POP3S (unencrypted SSL/TLS incompatibility)"
    }
    
    for proto in info.all_protocols():
        for port in info[proto].keys():
            state = info[proto][port]["state"]
            service = info[proto][port].get("name", "?")
            if state == "open":
                # Check for vulnerable ports
                if port in vulnerable_ports:
                    risks.append(f"Vulnerable service: {vulnerable_ports[port]} (port {port})")
                
                # Check for common weak services
                if port in [80, 443]:
                    risks.append("Web interface exposed")
                elif port == 22:
                    risks.append("SSH accessible (check authentication strength)")
                elif port == 53:
                    risks.append("DNS service exposed (potential DNS tunneling)")
                elif port == 110 or port == 143:
                    risks.append("Email services exposed (potential credential harvesting)")
                elif port == 135 or port == 139 or port == 445:
                    risks.append("SMB/NetBIOS services exposed (potential remote code execution)")
                elif port in [21, 23, 25]:
                    risks.append(f"Potentially insecure service: {service} (port {port})")
    
    # Add general risk categories
    if not risks:
        risks.append("No obvious risks detected")
    
    return risks

# ----------------------
# Report Generation
# ----------------------
def generate_report(devices, communications):
    table = Table(title="ZeroTrace Network Report")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Open Ports / Services", style="green")
    table.add_column("IoT?", style="yellow")
    table.add_column("Risk Analysis", style="red")
    table.add_column("Communications", style="blue")

    local_network = get_network_range()
    external_ip = get_public_ip()

    for dev in devices:
        ip = dev["ip"]
        mac = dev["mac"]
        info = dev["info"]
        ports = []
        if info:
            for proto in info.all_protocols():
                for port in info[proto].keys():
                    service = info[proto][port].get("name", "?")
                    ports.append(f"{port}/{proto} ({service})")
        iot = "Yes" if is_iot_device(info) else "No"
        risks = "\n".join(analyze_risks(info))

        # Communications section
        comms = []
        if ip in communications:
            for peer in communications[ip]:
                try:
                    socket.inet_aton(peer)
                    if peer == ip:  # Skip self-communication
                        continue
                    elif is_internal_ip(peer):
                        comms.append(f"{peer} [Internal]")
                    elif is_external_ip(peer, local_network):
                        comms.append(f"{peer} [External]")
                    else:
                        comms.append(f"{peer} [Unknown]")
                except:
                    continue
        comms_str = "\n".join(comms) if comms else "No traffic observed"

        table.add_row(ip, mac, "\n".join(ports) if ports else "None", iot, risks, comms_str)

    console.print(table)

# ----------------------
# Main Entry
# ----------------------
if __name__ == "__main__":
    console.print("[blue]Detecting network, discovering devices, and running fast scans...[/blue]")
    devices = scan_network()
    communications = capture_traffic(duration=60)
    console.print("[green]\n✔ Scan complete. Generating report...[/green]")
    generate_report(devices, communications)

'''
import scapy.all as scapy
import socket
import ipaddress
import nmap
from rich.console import Console
from rich.table import Table
from rich.progress import track, Progress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import re

console = Console()

# ----------------------
# Phase 1 - Device Discovery & Scan
# ----------------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def get_network_info():
    local_ip = get_local_ip()
    # Determine network based on IP address
    if local_ip.startswith("192.168."):
        network = str(ipaddress.ip_network(local_ip + "/24", strict=False))
    elif local_ip.startswith("10."):
        network = str(ipaddress.ip_network(local_ip + "/16", strict=False))
    elif local_ip.startswith("172."):
        network = str(ipaddress.ip_network(local_ip + "/12", strict=False))
    else:
        # Fallback to default /24 subnet
        network = str(ipaddress.ip_network(local_ip + "/24", strict=False))
    return local_ip, network

def arp_scan(network):
    console.print(f"[cyan]Running ARP scan on {network}...[/cyan]")
    arp_request = scapy.ARP(pdst=network)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    devices = []
    for sent, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
    return devices

def scan_device(ip):
    nm = nmap.PortScanner()
    try:
        # Use faster scanning with reduced service detection
        nm.scan(
            ip, 
            arguments="-sS -F --host-timeout 10s -T4",  # Faster TCP SYN scan with fast mode
            timeout=20
        )
        if ip in nm.all_hosts():
            return nm[ip]
    except Exception as e:
        console.print(f"[yellow][!] {ip} did not respond or scan timed out. Error: {e}[/yellow]")
    return None

def scan_network():
    local_ip, network = get_network_info()
    devices = arp_scan(network)
    
    results = []
    console.print(f"[cyan]Discovered {len(devices)} devices, beginning fast scans...[/cyan]")
    
    # Use thread pool for parallel scanning
    with Progress() as progress:
        task = progress.add_task("[blue]Scanning devices...", total=len(devices))
        
        with ThreadPoolExecutor(max_workers=20) as executor:  # Limit threads to avoid overwhelming network
            future_to_device = {
                executor.submit(scan_device, device["ip"]): device 
                for device in devices
            }
            
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    info = future.result(timeout=30)  # Add timeout to prevent hanging
                    results.append({"ip": device["ip"], "mac": device["mac"], "info": info})
                except Exception as e:
                    console.print(f"[red][!] Error scanning {device['ip']}: {e}[/red]")
                    results.append({"ip": device["ip"], "mac": device["mac"], "info": None})
                
                progress.update(task, advance=1)
    
    return results

# ----------------------
# Phase 2 - Traffic Capture
# ----------------------
def capture_traffic(duration=60):
    console.print(f"[cyan]Sniffing network traffic for {duration} seconds...[/cyan]")
    packets = scapy.sniff(timeout=duration)
    communications = defaultdict(set)
    local_ip, _ = get_network_info()
    
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            
            # Only track internal traffic patterns (exclude external IPs)
            if is_internal_ip(src) and is_internal_ip(dst):
                communications[src].add(dst)
                communications[dst].add(src)
            elif is_internal_ip(src) and not is_internal_ip(dst):
                # Internal to external communication
                communications[src].add(dst)
            elif not is_internal_ip(src) and is_internal_ip(dst):
                # External to internal communication
                communications[dst].add(src)
    
    return communications

def is_internal_ip(ip):
    """Check if IP address is in private network ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

# ----------------------
# Risk Analysis Helpers
# ----------------------
def is_iot_device(info):
    if not info: return False
    # Common IoT service names
    iot_services = ["http", "https", "mqtt", "coap", "modbus", "iec-104"]
    for proto in info.all_protocols():
        if proto in iot_services:
            return True
        for port in info[proto].keys():
            service = info[proto][port].get("name", "").lower()
            if any(iot_service in service for iot_service in iot_services):
                return True
    return False

def analyze_risks(info):
    risks = []
    if not info:
        return ["Unreachable device or scan failed"]
    
    # Check for weak services
    weak_services = {
        21: "FTP (unencrypted)",
        23: "Telnet (unencrypted)",
        53: "DNS (potential enumeration risk)",
        110: "POP3 (unencrypted)",
        143: "IMAP (unencrypted)",
        993: "IMAPS (unencrypted)",
        995: "POP3S (unencrypted)"
    }
    
    # Check for common vulnerable services
    vulnerable_services = {
        80: "HTTP",
        443: "HTTPS",
        22: "SSH",
        139: "NetBIOS",
        445: "SMB",
        161: "SNMP",
        515: "LPD",
        587: "SMTP (unencrypted)",
        990: "FTPS",
        1433: "MSSQL",
        1521: "Oracle DB",
        3306: "MySQL",
        5432: "PostgreSQL"
    }
    
    # Check protocols and ports
    for proto in info.all_protocols():
        for port in info[proto].keys():
            state = info[proto][port].get("state", "unknown")
            service = info[proto][port].get("name", "?").lower()
            
            if state == "open":
                # Check for weak services
                if port in weak_services:
                    risks.append(f"Critical Risk: {weak_services[port]} on port {port}")
                
                # Check for common vulnerable services
                if port in vulnerable_services:
                    risks.append(f"Security Risk: {vulnerable_services[port]} on port {port} (potential attack surface)")
                
                # Check for default/known vulnerable services
                if service in ["http", "https"] and port not in [80, 443]:
                    risks.append(f"Potential Web Service Misconfiguration on port {port}")
                
                # Check for unauthenticated services
                if port in [139, 445, 161, 515] and service in ["smb", "netbios-ns", "snmp"]:
                    risks.append(f"Potential Authentication Bypass: {service} on port {port}")
                
                # Check for services that might indicate IoT devices
                if service in ["mqtt", "coap", "modbus"] or any(keyword in service for keyword in ["iot", "smart", "homekit"]):
                    risks.append(f"Potential IoT Device: Service {service} found on port {port}")
                
                # Check for open ports that should be closed
                if service in ["unknown", "tcpwrapped"] and port not in [80, 443, 22, 53]:
                    risks.append(f"Suspicious Unidentified Port: {port} may indicate unauthorized services")
    
    # Additional risk analysis
    if len(risks) == 0:
        # Check for open ports that are likely indicators of potential issues
        open_ports = []
        for proto in info.all_protocols():
            for port in info[proto].keys():
                if info[proto][port].get("state", "unknown") == "open":
                    open_ports.append(port)
        
        if len(open_ports) > 0:
            risks.append(f"Security Risk: {len(open_ports)} open ports detected (potential attack surface)")
        else:
            risks.append("No obvious security risks detected")
    
    return risks

# ----------------------
# Enhanced Communication Analysis
# ----------------------
def classify_communication(peer_ip, local_ip):
    """Classify communication as internal or external"""
    try:
        # Handle special cases
        if peer_ip == "127.0.0.1" or peer_ip == "::1":
            return "Local Loopback"
        elif peer_ip.startswith("169.254.") or peer_ip.startswith("fe80:"):
            return "Link-local"
        
        # Check if it's an internal IP
        if is_internal_ip(peer_ip):
            return "Internal"
        
        # Check for known external service ranges
        if peer_ip.startswith(("172.217.", "104.", "35.")):  # Google services
            return "External (Google)"
        elif peer_ip.startswith("8.8."):
            return "External (Google DNS)"
        elif peer_ip.startswith("1.1."):
            return "External (Cloudflare)"
        
        # Default to external for other IPs
        return "External"
    except:
        return "Unknown"

# ----------------------
# Report Generation
# ----------------------
def generate_report(devices, communications):
    table = Table(title="ZeroTrace Network Report")
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("MAC Address", style="magenta")
    table.add_column("Open Ports / Services", style="green")
    table.add_column("IoT?", style="yellow")
    table.add_column("Risk Analysis", style="red")
    table.add_column("Communications", style="blue")

    local_ip, _ = get_network_info()
    
    for dev in devices:
        ip = dev["ip"]
        mac = dev["mac"]
        info = dev["info"]
        ports = []
        
        if info:
            for proto in info.all_protocols():
                for port in info[proto].keys():
                    service = info[proto][port].get("name", "?")
                    ports.append(f"{port}/{proto} ({service})")
        
        iot = "Yes" if is_iot_device(info) else "No"
        risks = "\n".join(analyze_risks(info))

        # Communications section
        comms = []
        if ip in communications:
            for peer in communications[ip]:
                try:
                    comm_type = classify_communication(peer, local_ip)
                    comms.append(f"{peer} [{comm_type}]")
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not classify communication {peer}: {e}[/yellow]")
                    continue
        comms_str = "\n".join(comms) if comms else "No traffic observed"

        table.add_row(ip, mac, "\n".join(ports) if ports else "None", iot, risks, comms_str)

    console.print(table)

# ----------------------
# Main Entry
# ----------------------
if __name__ == "__main__":
    console.print("[blue]Detecting network, discovering devices, and running fast scans...[/blue]")
    devices = scan_network()
    communications = capture_traffic(duration=60)
    console.print("[green]\n✔ Scan complete. Generating report...[/green]")
    generate_report(devices, communications)

