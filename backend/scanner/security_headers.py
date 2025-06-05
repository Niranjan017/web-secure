# backend/scanners/security_headers.py
import sys
import requests
from urllib.parse import urlparse
from colorama import Fore, Style, init
import json

init(autoreset=True)

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "desc": "Mitigates XSS by restricting resource loads.",
        "required": True,
        "validate": lambda v: "default-src" in v and "unsafe-inline" not in v and "unsafe-eval" not in v
    },
    "Strict-Transport-Security": {
        "desc": "Enforces HTTPS with HSTS.",
        "required": True,
        "validate": lambda v: "max-age=" in v and "includeSubDomains" in v
    },
    "X-Content-Type-Options": {
        "desc": "Prevents MIME type sniffing.",
        "required": True,
        "validate": lambda v: v.lower().strip() == "nosniff"
    },
    "X-Frame-Options": {
        "desc": "Prevents clickjacking.",
        "required": True,
        "validate": lambda v: v.upper() in ["DENY", "SAMEORIGIN"]
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS protection.",
        "required": False,
        "validate": lambda v: "1" in v and "mode=block" in v
    },
    "Referrer-Policy": {
        "desc": "Controls referrer information.",
        "required": True,
        "validate": lambda v: any(p in v for p in ["no-referrer", "strict-origin", "same-origin"])
    },
    "Permissions-Policy": {
        "desc": "Restricts browser features.",
        "required": True,
        "validate": lambda v: "geolocation" in v or "camera" in v or "microphone" in v
    },
    "Cache-Control": {
        "desc": "Controls client-side caching.",
        "required": False,
        "validate": lambda v: "no-store" in v or "no-cache" in v
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "Blocks cross-origin resource leaks.",
        "required": False,
        "validate": lambda v: "require-corp" in v
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Isolates top-level browsing context.",
        "required": False,
        "validate": lambda v: "same-origin" in v
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Restricts cross-origin loads.",
        "required": False,
        "validate": lambda v: v in ["same-origin", "same-site"]
    }
}

GRADES = {
    100: "A+",
    90: "A",
    80: "B",
    70: "C",
    60: "D",
    0: "F"
}

def grade(score):
    for threshold in sorted(GRADES.keys(), reverse=True):
        if score >= threshold:
            return GRADES[threshold]

def print_result(header, result_type, message):
    color = {
        "ok": Fore.GREEN,
        "warn": Fore.YELLOW,
        "fail": Fore.RED
    }.get(result_type, "")
    print(f"{color}{header:<35} {message}{Style.RESET_ALL}")

def analyze_headers(headers):
    report = []
    score = 0
    total = sum(1 for h in SECURITY_HEADERS if SECURITY_HEADERS[h]['required'])

    for header, config in SECURITY_HEADERS.items():
        value = headers.get(header)
        if value is None:
            if config['required']:
                print_result(header, "fail", "❌ Missing! - " + config['desc'])
                report.append({"header": header, "status": "missing", "desc": config["desc"]})
        else:
            if config['validate'](value):
                print_result(header, "ok", "✅ Secure")
                report.append({"header": header, "status": "secure", "value": value})
                if config['required']:
                    score += 1
            else:
                print_result(header, "warn", f"⚠️ Present but weak - {value}")
                report.append({"header": header, "status": "misconfigured", "value": value})

    percentage = int((score / total) * 100) if total else 0
    print(f"\n{Fore.CYAN}Security Grade: {grade(percentage)} ({percentage}%)\n")
    return report, percentage

def fetch_headers(url):
    try:
        res = requests.get(url, timeout=10, allow_redirects=True)
        print(f"{Fore.BLUE}Final URL: {res.url} — Status: {res.status_code}{Style.RESET_ALL}")
        return res.headers
    except Exception as e:
        print(f"{Fore.RED}❌ Failed to fetch: {e}{Style.RESET_ALL}")
        sys.exit(1)

def export_report(report, grade, output_file="header_report.json"):
    output = {
        "report": report,
        "grade": grade
    }
    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"{Fore.MAGENTA}📄 Report exported to {output_file}{Style.RESET_ALL}")

def print_final_report(report, grade, url):
    print("="*50)
    print(f"Security Headers Report for: {url}")
    print("="*50)
    print(f"{'Header':<35} | {'Status':<12} | Description / Value")
    print("-"*50)
    for entry in report:
        header = entry.get("header", "")
        status = entry.get("status", "")
        desc_or_val = entry.get("desc", entry.get("value", ""))
        print(f"{header:<35} | {status:<12} | {desc_or_val}")
    print("-"*50)
    print(f"Overall Security Grade: {grade}")
    print("="*50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python security_headers.py <url> [--json-report]")
        sys.exit(1)

    target = sys.argv[1]
    export_json = "--json-report" in sys.argv

    if not target.startswith("http"):
        target = "http://" + target

    headers = fetch_headers(target)
    report, percent = analyze_headers(headers)

    print_final_report(report, grade(percent), target)

    if export_json:
        export_report(report, percent)
