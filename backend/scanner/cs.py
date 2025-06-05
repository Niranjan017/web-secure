import requests
from bs4 import BeautifulSoup
import argparse
from urllib.parse import urljoin
from colorama import init, Fore
import threading
import math
import json
import re
import logging

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

COMMON_CSRF_NAMES = [
    "csrf", "token", "authenticity_token", "xsrf", "anticsrf",
    "csrfmiddlewaretoken", "__requestverificationtoken", "csrf_token", "nonce"
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; UltraCSRFChecker/2.0; +https://github.com/YourRepo)"
}

def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    prob = [data.count(c) / len(data) for c in set(data)]
    return -sum(p * math.log2(p) for p in prob)

def is_token_predictable(token: str) -> bool:
    if not token:
        return True
    if token.isdigit():
        return True
    if re.match(r'^\d{10,}$', token):
        return True
    if len(set(token)) <= 2:
        return True
    if token.lower() in ('token', 'csrf', '123456', 'abcdef'):
        return True
    return False

def extract_csrf_candidates(soup, cookies, response):
    tokens = {}

    for form in soup.find_all("form"):
        for inp in form.find_all("input", type="hidden"):
            name = inp.get("name", "").lower()
            val = inp.get("value", "")
            if any(tok in name for tok in COMMON_CSRF_NAMES) and val.strip():
                tokens[f"form_input:{name}"] = val.strip()

    for meta in soup.find_all("meta"):
        name = meta.get("name", "").lower()
        content = meta.get("content", "")
        if any(tok in name for tok in COMMON_CSRF_NAMES) and content.strip():
            tokens[f"meta:{name}"] = content.strip()

    for cookie in cookies:
        name = cookie.name.lower()
        if any(tok in name for tok in COMMON_CSRF_NAMES) and cookie.value.strip():
            tokens[f"cookie:{name}"] = cookie.value.strip()

    for h, v in response.headers.items():
        if any(tok in h.lower() for tok in COMMON_CSRF_NAMES):
            tokens[f"header:{h.lower()}"] = v

    scripts = soup.find_all("script")
    js_pattern = re.compile(r"(?i)(?:var|let|const)?\s*(\w*csrf\w*|csrfToken|csrf_token|token)\s*=\s*['\"]([^'\"]+)['\"]")
    for script in scripts:
        if script.string:
            for match in js_pattern.findall(script.string):
                tokens[f"js:{match[0]}"] = match[1]

    return tokens

def check_token_session_binding(token_val, cookies):
    for cookie in cookies:
        if cookie.value == token_val:
            return True
    return False

def test_post_requests(url, session, form, tokens, realistic_data=None):
    data = {}
    inputs = form.find_all("input")
    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        lname = name.lower()
        matched_token = next((v for k,v in tokens.items() if k.endswith(lname)), None)
        if matched_token:
            data[name] = matched_token
        else:
            if realistic_data and name in realistic_data:
                data[name] = realistic_data[name]
            else:
                input_type = inp.get("type", "text").lower()
                if input_type == "email":
                    data[name] = "test@example.com"
                elif input_type == "number":
                    data[name] = "123"
                else:
                    data[name] = "test"

    action = form.get("action") or url
    full_url = urljoin(url, action)
    method = (form.get("method") or "POST").upper()

    try:
        if method == "POST":
            res = session.post(full_url, data=data, headers=HEADERS, timeout=7)
            if res.status_code in (401,403):
                return "🟢 Server rejects invalid/missing token"
            elif 200 <= res.status_code < 400:
                return "🔴 Server accepts post without valid token"
            else:
                return f"⚠️ POST returned status {res.status_code}"
        else:
            return "⚪ Not a POST form, skipping POST test"
    except Exception as e:
        return f"❓ POST test error: {e}"

def analyze_form(url, session, form, idx, page_soup, page_response):
    method = (form.get("method") or "GET").upper()
    action = form.get("action") or url
    full_action = urljoin(url, action)

    if method != "POST":
        return {
            "form_index": idx,
            "action": full_action,
            "method": method,
            "token_status": "⚪ Not POST form - CSRF less relevant",
            "token_entropy": 0.0,
            "token_predictable": None,
            "session_binding": False,
            "token_freshness": None,
            "post_test": None,
            "security_grade": "Low"
        }

    tokens = extract_csrf_candidates(page_soup, session.cookies, page_response)

    if not tokens:
        status = "🔴 No CSRF token detected"
        entropy_score = 0
        predictable = True
    else:
        entropy_scores = [shannon_entropy(t) for t in tokens.values()]
        entropy_score = max(entropy_scores)
        predictable = any(is_token_predictable(t) for t in tokens.values())
        status = f"🟢 CSRF tokens found: {', '.join(tokens.keys())}"

    session_binding = any(check_token_session_binding(val, session.cookies) for val in tokens.values()) if tokens else False

    try:
        new_response = session.get(url, headers=HEADERS, timeout=7)
        new_soup = BeautifulSoup(new_response.text, "html.parser")
        new_tokens = extract_csrf_candidates(new_soup, session.cookies, new_response)
        freshness = "🟢 Token changes on reload (good)" if tokens and new_tokens and tokens != new_tokens else "🔴 Token does not change on reload"
    except Exception:
        freshness = "🟡 Token freshness check not implemented"

    realistic_data = {"username": "testuser", "password": "testpass", "email": "test@example.com"}
    post_test_result = test_post_requests(full_action, session, form, tokens, realistic_data)

    if not tokens:
        grade = "Critical"
    elif predictable:
        grade = "High"
    elif entropy_score >= 3.5 and freshness.startswith("🟢") and "rejects" in post_test_result:
        grade = "Low"
    else:
        grade = "Medium"

    return {
        "form_index": idx,
        "action": full_action,
        "method": method,
        "token_status": status,
        "token_entropy": entropy_score,
        "token_predictable": predictable,
        "session_binding": session_binding,
        "token_freshness": freshness,
        "post_test": post_test_result,
        "security_grade": grade
    }

def analyze_forms_concurrent(url):
    session = requests.Session()
    res = session.get(url, headers=HEADERS, timeout=7)
    if res.status_code != 200:
        logging.error(f"Failed to fetch URL: {url} with status {res.status_code}")
        return []

    soup = BeautifulSoup(res.text, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        logging.info("No forms found on the page.")
        return []

    results = []
    threads = []

    def worker(form_idx, form):
        result = analyze_form(url, session, form, form_idx, soup, res)
        results.append(result)

    for idx, form in enumerate(forms, 1):
        t = threading.Thread(target=worker, args=(idx, form))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    return results

def print_report(results):
    print("\n" + "="*70)
    print("🛡️  CSRF Security Audit Report")
    print("="*70)
    for res in sorted(results, key=lambda r: r['form_index']):
        color = {
            "Critical": Fore.RED,
            "High": Fore.LIGHTRED_EX,
            "Medium": Fore.YELLOW,
            "Low": Fore.GREEN
        }.get(res.get("security_grade"), Fore.WHITE)

        print(f"\n{color}[Form #{res['form_index']}] {res['method']} => {res['action']}")
        print(f"  🔍 Token Detection: {res['token_status']}")
        print(f"  🔢 Entropy Score: {res['token_entropy']:.2f}")
        print(f"  🔐 Predictable Token: {res['token_predictable']}")
        print(f"  🔗 Session Binding: {'Yes' if res['session_binding'] else 'No'}")
        print(f"  🔄 Token Freshness: {res['token_freshness']}")
        print(f"  📬 POST Behavior: {res['post_test']}")
        print(f"  🚦 Security Grade: {res['security_grade']}")
    print("\n" + "="*70)

def main():
    parser = argparse.ArgumentParser(description="Ultra Advanced CSRF Token Checker v2")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--json", help="Output JSON report file")
    args = parser.parse_args()

    results = analyze_forms_concurrent(args.url)
    print_report(results)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.CYAN}📁 Report saved to {args.json}")

if __name__ == "__main__":
    main()
