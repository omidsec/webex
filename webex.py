# webex.py ver.1.1
# Author: Idea: omid nasiri pouya Programmer: my nigga chatgpt-4o & 5
# web: omidsec.ir
# linkedin: https://linkedin.com/in/omidsec
# youtube: https://youtube.com/@omidnasiri
# telegram: https://t.me/omidsec
# email: omid.nasirip+webex@gmail.com

import argparse
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from bs4 import XMLParsedAsHTMLWarning
from concurrent.futures import ThreadPoolExecutor
import re
import threading
import queue
from colorama import Fore, init
import socks
import socket
import sys
import os
import time
import warnings
import tempfile
import shutil
import signal
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# -------------------- Meta / Banner --------------------
AUTHOR = "Omid Nasiri pouya (OmidSec)"
TOOL_NAME = "webex"
VERSION = "1.0"  # <-- for release a new version
REPO = "omidsec/webex"
GITHUB_API_RELEASES_LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
GITHUB_RAW_MAIN = f"https://raw.githubusercontent.com/{REPO}/refs/heads/main/webex.py"
GITHUB_RAW_MASTER = f"https://raw.githubusercontent.com/{REPO}/refs/heads/master/webex.py"

# Suppress SSL warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

init(autoreset=True)

visited = set()
found = set()
visited_lock = threading.Lock()
found_lock = threading.Lock()
url_queue = queue.Queue()
stop_event = threading.Event()

DEFAULT_SKIP_WORDS = ['logout', 'exit', 'خروج']

# counters for fsync milestones
crawled_counter = 0
crawled_lock = threading.Lock()

# Single shared session (helps Ctrl+C responsiveness on Windows/Termux/WSL)
sess = requests.Session()
adapter = HTTPAdapter(max_retries=0, pool_connections=100, pool_maxsize=100)
sess.mount("http://", adapter)
sess.mount("https://", adapter)
sess.headers["Connection"] = "close"

# ------------------------------------------------------
# Utility & UI
# ------------------------------------------------------

# Clears the console/terminal screen in a cross‑platform way (Windows/Linux/macOS).
def clear_console():
    cmd = 'cls' if os.name == 'nt' else 'clear'
    os.system(cmd)

# Prints a colorful ASCII banner with tool metadata.
def print_banner():
    bar = f"{Fore.MAGENTA}{'=' * 58}{Fore.RESET}"
    title = f"{Fore.CYAN}{TOOL_NAME.upper()} {Fore.RESET}- Regex Web Crawler  {Fore.YELLOW}Version:{Fore.RESET} {VERSION}"
    meta = f"{Fore.YELLOW}Author:{Fore.RESET} {AUTHOR}"
    repo = f"{Fore.YELLOW}GitHub:{Fore.RESET} https://github.com/{REPO}"
    print(bar)
    print(title)
    print(meta)
    print(repo)
    print(bar)

# Global SIGINT (Ctrl+C) handler: set stop flag and close session to abort in-flight requests immediately.
def handle_sigint(signum, frame):
    print(f"\n{Fore.RED}[!] Ctrl+C detected. Stopping workers...")
    stop_event.set()
    try:
        sess.close()
    except Exception:
        pass

signal.signal(signal.SIGINT, handle_sigint)

# ------------------------------------------------------
# Networking / Proxy / Headers
# ------------------------------------------------------

# Configures proxy support. Supports SOCKS5 via PySocks and HTTP(S) proxies via requests.
def setup_proxy(proxy):
    if proxy and proxy.startswith("socks5://"):
        host, port = proxy.replace("socks5://", "").split(":")
        socks.set_default_proxy(socks.SOCKS5, host, int(port))
        socket.socket = socks.socksocket
        return None
    return {"http": proxy, "https": proxy} if proxy else None

# Parses -H headers and optional user-agent into a dict for requests.
def parse_headers(header_string, user_agent):
    headers = {}
    if header_string:
        if isinstance(header_string, list):
            parts = header_string
        else:
            parts = header_string.split(",")
        for part in parts:
            if ':' in part:
                key, value = part.split(":", 1)
                headers[key.strip()] = value.strip()

    # Default User-Agent
    if not user_agent:
        user_agent = "WebEX Crawler/1.0 (+https://github.com/omidsec/webex)"

    headers["User-Agent"] = user_agent
    return headers

# ------------------------------------------------------
# URL helpers
# ------------------------------------------------------

# Quick URL sanity check (has scheme and netloc).
def is_valid(url):
    parsed = urlparse(url)
    return bool(parsed.scheme) and bool(parsed.netloc)

# Returns True if URL should be skipped based on provided skip words.
def should_skip(url, skip_words):
    url_lower = url.lower()
    return any(skip in url_lower for skip in skip_words)

# Checks whether test_url is the same domain or a subdomain of base_url (port-safe, lowercase, no trailing dot).
def is_same_domain(base_url, test_url):
    base_host = (urlparse(base_url).hostname or '').lower().rstrip('.')
    test_host = (urlparse(test_url).hostname or '').lower().rstrip('.')
    return test_host == base_host or test_host.endswith('.' + base_host)

# Extracts relevant links (href/src from a/link/script/iframe) and normalizes them. XML/HTML aware.
def extract_links(html, base_url, skip_words, content_type="", current_url=""):
    content_type = (content_type or "").lower()
    if "xml" in content_type or (current_url or "").endswith((".xml", "/feed", "/feed/")):
        soup = BeautifulSoup(html, features="xml")
    else:
        soup = BeautifulSoup(html, 'html.parser')

    urls = set()
    for tag in soup.find_all(['a', 'link', 'script', 'iframe']):
        href = tag.get('href') or tag.get('src')
        if href:
            joined = urljoin(base_url, href.strip())
            if is_valid(joined) and not should_skip(joined, skip_words):
                urls.add(joined)
    return urls

# ------------------------------------------------------
# Regex compile & matching
# ------------------------------------------------------

# Compile all patterns once for performance (supports hundreds/thousands of regexes).
def compile_patterns(patterns):
    compiled = []
    for p in patterns:
        try:
            cp = re.compile(p, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)
            compiled.append(cp)
        except re.error as e:
            print(f"{Fore.RED}[REGEX ERROR] cannot compile: {p} -> {e}")
    return compiled

# Build plain text for matching (HTML/XML → visible text).
def build_text_for_matching(html, content_type="", current_url=""):
    content_type = (content_type or "").lower()
    try:
        if "xml" in content_type or (current_url or "").endswith((".xml", "/feed", "/feed/")):
            soup = BeautifulSoup(html, features="xml")
        else:
            soup = BeautifulSoup(html, 'html.parser')
        # CHANGED: preserve newlines for line-anchored regexes (^…$)
        return soup.get_text("\n")
    except Exception:
        return html

# NEW: Build concatenated attributes text (href/src/value/data-* etc.) for regex pass on attributes.
def build_attributes_text(html, content_type="", current_url=""):
    content_type = (content_type or "").lower()
    try:
        if "xml" in content_type or (current_url or "").endswith((".xml", "/feed", "/feed/")):
            soup = BeautifulSoup(html, features="xml")
        else:
            soup = BeautifulSoup(html, 'html.parser')
        chunks = []
        for tag in soup.find_all(True):
            for k, v in (tag.attrs or {}).items():
                if isinstance(v, (list, tuple)):
                    v = " ".join(str(x) for x in v)
                elif v is None:
                    continue
                chunks.append(str(v))
        return "\n".join(chunks)
    except Exception:
        return ""

# Run all compiled regexes over provided text and return unique normalized matches.
def run_compiled_regexes(text, compiled_regexes):
    matches = set()
    for rx in compiled_regexes:
        try:
            for m in rx.findall(text):
                if isinstance(m, tuple):
                    m = next((x for x in m if x), "")
                if m:
                    matches.add(m.strip())
        except Exception as e:
            print(f"{Fore.RED}[REGEX RUNTIME ERROR] {e}")
    return matches

# Appends a set of strings to a file, creating directories as needed. Flush & optional fsync.
def save_to_file(filename, data_set, do_fsync=False):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'a', encoding='utf-8') as f:
        for item in data_set:
            f.write(item + '\n')
        f.flush()
        if do_fsync:
            try:
                os.fsync(f.fileno())
            except Exception:
                pass

# ------------------------------------------------------
# Core crawling
# ------------------------------------------------------

# Crawls a single URL: fetch, log, regex match, enqueue in-scope links.
def crawl(url, compiled_regexes, proxy, headers, max_count, mode, timeout, allow_redirects, delay, output_dir, skip_words, base_url):
    if stop_event.is_set():
        return
    if should_skip(url, skip_words):
        return

    with visited_lock:
        if url in visited:
            return
        visited.add(url)

    try:
        if stop_event.is_set():
            return

        # Map single int timeout to (connect, read) tuple for responsiveness
        to = timeout if isinstance(timeout, (int, float)) else 10
        response = sess.get(
            url,
            timeout=(to, to),
            verify=False,
            proxies=proxy,
            headers=headers,
            allow_redirects=allow_redirects
        )

        # Prefer server charset; otherwise apparent_encoding
        try:
            if not response.encoding:
                response.encoding = response.apparent_encoding
        except Exception:
            pass

        html = response.text
        content_type = response.headers.get("Content-Type", "")

    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e} - {url}")
        return

    print(f"{Fore.CYAN}[CRAWLED] {url}")

    # save URL immediately; fsync every 100
    global crawled_counter
    with crawled_lock:
        crawled_counter += 1
        fsync_milestone = (crawled_counter % 100 == 0)
    save_to_file(os.path.join(output_dir, "crawled_urls.txt"), {url}, do_fsync=fsync_milestone)

    # regex match on visible text + raw html + attributes
    if compiled_regexes:
        text_for_matching = build_text_for_matching(html, content_type=content_type, current_url=url)
        matches_text = run_compiled_regexes(text_for_matching, compiled_regexes)

        matches_html = run_compiled_regexes(html, compiled_regexes)

        attrs_text = build_attributes_text(html, content_type=content_type, current_url=url)
        matches_attrs = run_compiled_regexes(attrs_text, compiled_regexes)

        matches = set().union(matches_text, matches_html, matches_attrs)

        if matches:
            with found_lock:
                new_matches = matches - found
                if new_matches:
                    found.update(new_matches)
                    for m in new_matches:
                        print(f"{Fore.YELLOW}[MATCH] {m}")
                    # save immediately and fsync to avoid loss
                    save_to_file(os.path.join(output_dir, "regex_results.txt"), new_matches, do_fsync=True)

            if max_count and mode == 'regex' and len(found) >= max_count:
                return

    # cooperative sleep for quick stop
    if delay:
        slept = 0.0
        while slept < delay and not stop_event.is_set():
            t = min(0.1, delay - slept)
            time.sleep(t)
            slept += t

    if stop_event.is_set():
        return

    for link in extract_links(html, url, skip_words, content_type=content_type, current_url=url):
        if stop_event.is_set():
            break
        if not is_same_domain(base_url, link):
            continue
        with visited_lock:
            if link not in visited:
                try:
                    url_queue.put(link, timeout=0.1)
                except queue.Full:
                    pass

# Worker thread loop: pulls URLs from queue and crawls them until limits or stop.
def worker(compiled_regexes, proxy, headers, max_count, mode, timeout, allow_redirects, delay, output_dir, skip_words, base_url):
    while not stop_event.is_set():
        try:
            url = url_queue.get(timeout=1)
        except queue.Empty:
            if stop_event.is_set():
                break
            else:
                continue

        # hard stop if limits reached
        if max_count:
            if mode == 'regex' and len(found) >= max_count:
                url_queue.task_done()
                break
            elif mode == 'url' and len(visited) >= max_count:
                url_queue.task_done()
                break

        if stop_event.is_set():
            url_queue.task_done()
            break

        crawl(url, compiled_regexes, proxy, headers, max_count, mode, timeout, allow_redirects, delay, output_dir, skip_words, base_url)
        url_queue.task_done()

# ------------------------------------------------------
# Version / Update
# ------------------------------------------------------

# Parses a VERSION string like "1.2.3" into a comparable tuple of ints.
def parse_version(v):
    parts = []
    for p in re.split(r'[.\-+]', v.strip()):
        if p.isdigit():
            parts.append(int(p))
        else:
            num = re.findall(r'\d+', p)
            parts.append(int(num[0]) if num else 0)
    return tuple(parts) if parts else (0,)

# Extracts VERSION assignment from a python source string.
def extract_version_from_source(source_text):
    m = re.search(r'^\s*VERSION\s*=\s*["\'](.+?)["\']\s*$', source_text, re.MULTILINE)
    return m.group(1).strip() if m else None

# Fetches the latest version string from GitHub (releases API or raw file fallback).
def fetch_latest_version_and_source(proxy=None, timeout=8):
    sess_local = requests.Session()
    if proxy:
        sess_local.proxies = proxy
    try:
        r = sess_local.get(GITHUB_API_RELEASES_LATEST, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            tag = data.get("tag_name") or data.get("name") or ""
            latest_ver = tag.lstrip('vV').strip() if tag else None
            for raw_url in (GITHUB_RAW_MAIN, GITHUB_RAW_MASTER):
                rr = sess_local.get(raw_url, timeout=timeout)
                if rr.status_code == 200:
                    return latest_ver, rr.text
        for raw_url in (GITHUB_RAW_MAIN, GITHUB_RAW_MASTER):
            rr = sess_local.get(raw_url, timeout=timeout)
            if rr.status_code == 200:
                src = rr.text
                latest_ver = extract_version_from_source(src)
                return latest_ver, src
    except requests.RequestException:
        raise
    return None, None

# Checks for updates and prints status.
# If auto_update=True and newer exists, replaces current script with latest source.
def check_and_maybe_update(current_version, auto_update=False, proxy=None):
    try:
        latest_version, latest_source = fetch_latest_version_and_source(proxy=proxy)
    except requests.RequestException:
        print(f"{Fore.RED}Update check failed")
        return

    if not latest_version:
        print(f"{Fore.RED}Update check failed")
        return

    cv = parse_version(current_version)
    lv = parse_version(latest_version)

    if lv > cv:
        print(f"{Fore.YELLOW}New version available: {latest_version} (current: {current_version})")
        if auto_update:
            if not latest_source:
                print(f"{Fore.RED}Update check failed")
                return
            try:
                # Write to temp file then atomically replace current file
                current_path = os.path.abspath(sys.argv[0])
                dir_name = os.path.dirname(current_path)
                fd, tmp_path = tempfile.mkstemp(prefix="webex_update_", suffix=".py", dir=dir_name)
                with os.fdopen(fd, 'w', encoding='utf-8') as f:
                    f.write(latest_source)
                # Preserve executable bit on *nix if set
                try:
                    st = os.stat(current_path)
                    os.chmod(tmp_path, st.st_mode)
                except Exception:
                    pass
                # Replace
                shutil.move(tmp_path, current_path)
                print(f"{Fore.GREEN}Updated to version {latest_version}. Please re-run the tool.")
                sys.exit(0)
            except Exception as e:
                print(f"{Fore.RED}Update failed: {e}")
        else:
            print(f"{Fore.CYAN}Run with --update to auto-update.")
    else:
        print(f"{Fore.GREEN}webex up-to-date (v{current_version}).")

# ------------------------------------------------------
# CLI / Main
# ------------------------------------------------------

# Entry point: parses args, clears screen, prints banner, checks updates, then runs the crawler.
def main():
    parser = argparse.ArgumentParser(description="webex.py by omidsec")
    parser.add_argument("-u", "--url", required=True, help="Start URL (http or https)")
    parser.add_argument("-p", "--proxy", help="Proxy (http:// or socks5://)")
    parser.add_argument("-r", "--regex", action="append",
                        help="Regex pattern (repeatable, use -r multiple times)")
    parser.add_argument("--regex-file", help="Path to a file with one regex per line (# comments allowed)")
    parser.add_argument("-t", "--thread", type=int, default=1, help="Thread count (default=1)")
    parser.add_argument("-m", "--max", type=int, help="Max matches or max crawled URLs")
    parser.add_argument("-H", "--header", action="append", help='Custom header (e.g. -H "Key: Value")')
    parser.add_argument("-a", "--agent", help="Custom User-Agent string")
    parser.add_argument("--delay", type=float, default=0, help="Delay in seconds between requests")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout (seconds) for both connect/read")
    parser.add_argument("--redirect", choices=["TRUE", "FALSE"], default="TRUE", help="Follow redirects")
    parser.add_argument("--no", help="Comma-separated strings to skip in URLs")
    parser.add_argument("--update", action="store_true", help="Check GitHub and auto-update if a newer version exists")

    args = parser.parse_args()

    clear_console()
    print_banner()

    proxy = setup_proxy(args.proxy)

    check_and_maybe_update(VERSION, auto_update=args.update, proxy=proxy)

    if not args.url.startswith("http"):
        print(f"{Fore.RED}[-] URL must start with http:// or https://")
        sys.exit(1)

    start_url = args.url
    parsed = urlparse(start_url)
    target_host = parsed.netloc.replace(":", "_")
    output_dir = os.path.join("webex_targets", target_host)

    headers = parse_headers(args.header, args.agent)

    # Load regex patterns: from -r (repeatable) and optional --regex-file
    cli_patterns = [p for p in (args.regex or []) if p and p.strip()]
    file_patterns = []
    if args.regex_file:
        try:
            with open(args.regex_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    file_patterns.append(s)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] reading --regex-file: {e}")

    all_patterns = cli_patterns + file_patterns
    compiled_regexes = compile_patterns(all_patterns)

    mode = 'regex' if compiled_regexes else 'url'
    allow_redirects = args.redirect.upper() == "TRUE"

    extra_skips = [s.strip().lower() for s in (args.no.split(",") if args.no else [])]
    skip_words = list(set(DEFAULT_SKIP_WORDS + extra_skips))

    # prime the queue
    url_queue.put(start_url)

    executor = None
    try:
        executor = ThreadPoolExecutor(max_workers=args.thread)
        for _ in range(args.thread):
            executor.submit(
                worker,
                compiled_regexes,
                proxy,
                headers,
                args.max,
                mode,
                args.timeout,
                allow_redirects,
                args.delay,
                output_dir,
                skip_words,
                start_url
            )

        # Wait cooperatively; don't block forever if Ctrl+C pressed
        while not stop_event.is_set():
            if url_queue.empty():
                break
            time.sleep(0.1)
        if not stop_event.is_set():
            url_queue.join()

    except KeyboardInterrupt:
        handle_sigint(None, None)
        # quick drain so threads exit
        while not url_queue.empty():
            try:
                url_queue.get_nowait()
                url_queue.task_done()
            except Exception:
                break
    finally:
        if executor:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    print(f"{Fore.GREEN}Done. Total URLs crawled: {len(visited)}. Total matches: {len(found)}.")
    print(f"{Fore.GREEN}Results saved in: {output_dir}")

if __name__ == "__main__":
    main()
