import scapy.all as scapy
import socket
import ipaddress
import nmap
import os
import ctypes
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import openpyxl

console = Console()

# ----------------------
# OUI Vendor Map (common IoT vendors)
# ----------------------
OUI_VENDOR_MAP = {
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Amazon Technologies",
    "AC:63:BE": "Amazon Echo",
    "3C:5A:B4": "Wyze Labs",
    "F4:F5:D8": "Google Nest",
    "D0:73:D5": "Google Smart Hub",
    "00:1A:11": "Philips Hue",
    "F0:27:2D": "TP-Link Technologies",
    "60:01:94": "Xiaomi Communications",
    "28:6D:97": "Samsung Electronics",
    "00:16:6C": "Sony Corporation"
}

# ----------------------
# Utility: Check admin privileges
# ----------------------
def is_admin():
    try:
        return os.getuid() == 0  # Linux / macOS
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows

# ----------------------
# MAC Vendor Lookup
# ----------------------
def mac_vendor_lookup(mac):
    if not mac:
        return "Unknown Vendor"
    mac_norm = mac.upper().replace(":", "").replace("-", "")
    oui = mac_norm[:6]
    prefix = ":".join([oui[i:i+2] for i in range(0, 6, 2)])
    vendor = OUI_VENDOR_MAP.get(prefix) or OUI_VENDOR_MAP.get(oui)
    return vendor if vendor else "Unknown Vendor"

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
        devices.append({"ip": received.psrc, "mac": received.hwsrc.upper()})
    return devices

def scan_device(ip, mode="quick"):
    nm = nmap.PortScanner()
    try:
        if mode == "quick":
            args = "-sS -T4 --top-ports 20"
        else:  # deep
            args = "-sS -sV -O --top-ports 100 --osscan-guess --script vuln --max-retries 3"
        nm.scan(ip, arguments=args, timeout=30)
        if ip in nm.all_hosts():
            return nm[ip]
    except Exception as e:
        console.print(f"[yellow][!] {ip} scan failed. Error: {e}[/yellow]")
    return None

def scan_network(mode="quick"):
    local_ip = get_local_ip()
    network = str(ipaddress.ip_network(local_ip + "/24", strict=False))
    devices = arp_scan(network)

    results = []
    console.print(f"[cyan]Discovered {len(devices)} devices, running {mode} scans...[/cyan]")

    with Progress() as progress:
        task = progress.add_task("[blue]Scanning devices...", total=len(devices))
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_device = {executor.submit(scan_device, d["ip"], mode): d for d in devices}
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    info = future.result(timeout=40)
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
# Risk & Device Analysis
# ----------------------
def is_iot_device(mac, info):
    prefix = mac[:8]
    if prefix in OUI_VENDOR_MAP:
        return True
    if info:
        for proto in info.all_protocols():
            for port in info[proto]:
                if port in [1900, 5353, 554, 1883, 8883, 49152]:
                    return True
    return False

def get_device_type(info):
    if not info:
        return "Unknown"
    try:
        if "osclass" in info:
            return info["osclass"][0]["type"]
        for proto in info.all_protocols():
            if 9100 in info[proto]:
                return "Printer"
            elif 554 in info[proto]:
                return "Camera"
            elif 80 in info[proto] or 443 in info[proto]:
                return "Web Server"
    except:
        pass
    return "Generic Device"

def analyze_risks(info):
    risks = []
    if not info:
        return ["Unreachable"]

    risky_ports = {
        21: "FTP (insecure)",
        23: "Telnet (plaintext)",
        25: "SMTP exposed",
        53: "DNS tunneling risk",
        111: "RPC service exploit",
        135: "MS RPC risk",
        139: "NetBIOS exploit",
        445: "SMB vulnerability",
        3389: "RDP exposed",
        5900: "VNC exposed"
    }

    for proto in info.all_protocols():
        for port, svc in info[proto].items():
            if svc["state"] == "open":
                if port in risky_ports:
                    risks.append(f"Critical: {risky_ports[port]}")
                elif port in [80, 8080, 8443]:
                    risks.append("Medium: Web interface exposed")
                elif port == 22:
                    risks.append("Medium: SSH exposed")
                elif port in [1900, 5353]:
                    risks.append("IoT protocol exposed")
    if not risks:
        risks.append("No major risks detected")
    return risks

# ----------------------
# Report Generation
# ----------------------
def generate_report(devices, communications):
    table = Table(title="ZeroTrace Network Report")
    table.add_column("IP", style="cyan")
    table.add_column("MAC", style="magenta")
    table.add_column("Vendor", style="green")
    table.add_column("Type", style="yellow")
    table.add_column("OS", style="cyan")
    table.add_column("IoT?", style="blue")
    table.add_column("Risks", style="red")

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Scan Report"
    ws.append(["IP", "MAC", "Vendor", "Device Type", "OS", "IoT?", "Open Ports", "Risks", "Communications"])

    for dev in devices:
        ip = dev["ip"]
        mac = dev["mac"]
        info = dev["info"]

        vendor = mac_vendor_lookup(mac)
        dtype = get_device_type(info)
        os_name = "Unknown"
        if info and "osmatch" in info and info["osmatch"]:
            os_name = info["osmatch"][0]["name"]

        iot = "Yes" if is_iot_device(mac, info) else "No"
        risks = analyze_risks(info)
        risks_str = "; ".join(risks)

        ports = []
        if info:
            for proto in info.all_protocols():
                for port in info[proto]:
                    svc = info[proto][port].get("name", "?")
                    ports.append(f"{port}/{proto} ({svc})")

        comms = []
        if ip in communications:
            for peer in communications[ip]:
                if peer == ip:
                    continue
                elif ipaddress.ip_address(peer).is_private:
                    comms.append(f"{peer} [Internal]")
                else:
                    comms.append(f"{peer} [External]")

        comms_str = ", ".join(comms) if comms else "No traffic observed"

        # Console
        table.add_row(str(ip), str(mac), vendor, dtype, os_name, iot, risks_str)

        # Excel (force everything to str)
        ws.append([
            str(ip),
            str(mac),
            str(vendor),
            str(dtype),
            str(os_name),
            str(iot),
            str(", ".join(ports) if ports else "None"),
            str(risks_str),
            str(comms_str)
        ])

    console.print(table)
    filename = "zerotrace_report.xlsx"
    wb.save(filename)
    console.print(f"[green]✔ Report saved to {filename}[/green]")

# ----------------------
# Main Entry
# ----------------------
if __name__ == "__main__":
    if is_admin():
        console.print("[green]✔ Running with administrator privileges[/green]")
    else:
        console.print("[red]✖ Not running as administrator (some features may fail)[/red]")

    mode = console.input("[cyan]Choose scan mode ([b]quick[/b]/[b]deep[/b]): ").strip().lower()
    if mode not in ["quick", "deep"]:
        mode = "quick"

    console.print(f"[blue]Detecting network, discovering devices, and running {mode} scans...[/blue]")
    devices = scan_network(mode)
    communications = capture_traffic(duration=60)
    console.print("[green]\n✔ Scan complete. Generating report...[/green]")
    generate_report(devices, communications)
