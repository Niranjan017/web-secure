# backend/scanners/advanced_port_scanner.py

import sys
import socket
import concurrent.futures
import json
from datetime import datetime
from colorama import init, Fore
import argparse
import platform
import os
import time
from urllib.parse import urlparse

init(autoreset=True)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-Alt", 5900: "VNC", 8443: "HTTPS-Alt", 139: "NetBIOS", 445: "SMB"
}

RISK_LEVELS = {
    "Critical": {21, 22, 23, 139, 445, 3306, 3389},
    "High": {80, 443, 8080, 5900, 8443},
    "Medium": {25, 53, 110, 143},
    "Low": set()
}

def get_risk_level(port):
    for level, ports in RISK_LEVELS.items():
        if port in ports:
            return level
    return "Low"

def get_banner(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, port))
            s.sendall(b'\r\n')
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner.split('\n')[0] if banner else "Unknown"
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "Unknown"

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            s.connect((host, port))
            service = COMMON_PORTS.get(port, get_banner(host, port))
            risk = get_risk_level(port)
            return {
                "port": port,
                "status": "open",
                "service": service,
                "risk": risk
            }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None

def scan_ports(host, start, end, threads):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_port, host, port) for port in range(start, end + 1)]
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)
                color = {
                    "Critical": Fore.RED,
                    "High": Fore.LIGHTRED_EX,
                    "Medium": Fore.YELLOW,
                    "Low": Fore.GREEN
                }.get(result['risk'], Fore.WHITE)
                print(f"{color}[+] Port {result['port']} OPEN - {result['service']} (Risk: {result['risk']})")
    return open_ports

def validate_target(host):
    try:
        socket.gethostbyname(host)
        return True
    except socket.gaierror:
        return False

def ping_host(host):
    print(f"{Fore.BLUE}[↪] Pinging {host} to check availability...")
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    redirect = '> nul 2>&1' if platform.system().lower() == 'windows' else '> /dev/null 2>&1'
    response = os.system(f"ping {param} 1 {host} {redirect}")
    return response == 0

def summarize_risks(ports):
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for p in ports:
        counts[p['risk']] += 1
    return counts

def overall_grade(counts):
    if counts["Critical"] > 0:
        return "CRITICAL"
    elif counts["High"] > 0:
        return "HIGH"
    elif counts["Medium"] > 0:
        return "MEDIUM"
    elif counts["Low"] > 0:
        return "LOW"
    else:
        return "NONE"

def save_report(host, ports, file, start_port, end_port, duration):
    counts = summarize_risks(ports)
    grade = overall_grade(counts)
    report = {
        "host": host,
        "os": platform.system(),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "open_ports": ports,
        "risk_summary": counts,
        "overall_grade": grade,
        "scan_type": "TCP connect",
        "scanned_range": f"{start_port}-{end_port}",
        "scan_duration_seconds": round(duration, 2)
    }
    with open(file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n{Fore.MAGENTA}[📄] Report saved to {file}")

def parse_host(input_str):
    parsed = urlparse(input_str)
    if parsed.scheme and parsed.hostname:
        return parsed.hostname
    return input_str

def print_final_report(host, ports, counts, grade, duration, start_port, end_port):
    print("\n" + "="*60)
    print(f"Advanced Port Scanner Report for: {host}")
    print("="*60)
    print(f"OS: {platform.system()}")
    print(f"Scan range: {start_port}-{end_port}")
    print(f"Scan duration: {duration:.2f} seconds")
    print(f"Open Ports Found: {len(ports)}")
    print("-"*60)
    print(f"{'Port':<7} | {'Service':<15} | {'Risk Level':<8}")
    print("-"*60)
    for p in sorted(ports, key=lambda x: x['port']):
        risk_color = {
            "Critical": Fore.RED,
            "High": Fore.LIGHTRED_EX,
            "Medium": Fore.YELLOW,
            "Low": Fore.GREEN
        }.get(p['risk'], Fore.WHITE)
        print(f"{risk_color}{p['port']:<7} | {p['service']:<15} | {p['risk']:<8}{Fore.RESET}")
    print("-"*60)
    print(f"Risk Summary: Critical: {counts['Critical']}, High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}")
    print(f"Overall Security Grade: {grade}")
    print("="*60)

def main():
    parser = argparse.ArgumentParser(description="Advanced Port Scanner with Risk Grading")
    parser.add_argument("target", help="Target IP, hostname, or full URL")
    parser.add_argument("--json", help="Save output to JSON file", metavar="file.json")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default 100)")
    parser.add_argument("--range", type=str, default="1-1024", help="Port range to scan, e.g. 1-1024")
    args = parser.parse_args()

    host = parse_host(args.target)

    if not validate_target(host):
        print(f"{Fore.RED}[-] Invalid target host: {host}")
        sys.exit(1)

    if not ping_host(host):
        print(f"{Fore.YELLOW}[!] Host {host} seems down or not responding to ping.")
        sys.exit(1)

    try:
        start_port, end_port = map(int, args.range.split("-"))
        if not (0 < start_port <= end_port <= 65535):
            raise ValueError
    except ValueError:
        print(f"{Fore.RED}[-] Invalid port range format or values. Use start-end with ports between 1 and 65535 (e.g. 1-1024)")
        sys.exit(1)

    print(f"\n{Fore.CYAN}[🔍] Scanning {host} ports {start_port} to {end_port} with {args.threads} threads...")
    start_time = time.time()
    results = scan_ports(host, start_port, end_port, args.threads)
    duration = time.time() - start_time

    if results:
        counts = summarize_risks(results)
        grade = overall_grade(counts)

        print(f"\n{Fore.CYAN}[✔] Scan complete: {len(results)} open ports found in {duration:.2f} seconds.")
        print(f"{Fore.RED if grade=='CRITICAL' else Fore.YELLOW if grade=='HIGH' else Fore.GREEN}[!] Overall Security Grade: {grade}")
        print(f"    Critical: {counts['Critical']}, High: {counts['High']}, Medium: {counts['Medium']}, Low: {counts['Low']}")

        print_final_report(host, results, counts, grade, duration, start_port, end_port)

        if args.json:
            save_report(host, results, args.json, start_port, end_port, duration)
    else:
        print(f"\n{Fore.YELLOW}[!] No open ports found.")

if __name__ == "__main__":
    main()
