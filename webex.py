# webex.py ver.1.0
# Author: omid nasiri pouya + my nigga chatgpt-4o
# web: omidsec.ir
# linkedin: https://linkedin.com/in/omidsec
# youtube: https://youtube.com/@omidnasiri
# telegram: https://t.me/omidsec
# email: omid.nasirip+webex@gmail.com

import argparse
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
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
from urllib3.exceptions import InsecureRequestWarning

# -------------------- Meta / Banner --------------------
AUTHOR = "Omid Nasiri pouya (OmidSec)"
TOOL_NAME = "webex"
VERSION = "1.0" # <-- for release a new version
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
        user_agent = "WebexCrawler/1.0 (+https://github.com/omidsec/webex)"
    
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

# Checks whether test_url is the same domain or a subdomain of base_url.
def is_same_domain(base_url, test_url):
    base_domain = urlparse(base_url).netloc
    test_domain = urlparse(test_url).netloc
    return test_domain == base_domain or test_domain.endswith('.' + base_domain)

# Extracts relevant links (href/src from a/link/script/iframe) and normalizes them.
def extract_links(html, base_url, skip_words):
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
# Regex & File I/O
# ------------------------------------------------------

# Applies a list of regex patterns to HTML content (case-insensitive) and returns unique matches.
def apply_regex(html, regexes):
    matches = set()
    for pattern in regexes:
        for match in re.findall(pattern, html, re.IGNORECASE):
            matches.add(match)
    return matches

# Appends a set of strings to a file, creating directories as needed.
def save_to_file(filename, data_set):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'a', encoding='utf-8') as f:
        for item in data_set:
            f.write(item + '\n')

# ------------------------------------------------------
# Core crawling
# ------------------------------------------------------

# Crawls a single URL: fetch, log, regex match, enqueue in-scope links.
def crawl(url, regexes, proxy, headers, max_count, mode, timeout, allow_redirects, delay, output_dir, skip_words, base_url):
    if should_skip(url, skip_words):
        return

    with visited_lock:
        if url in visited:
            return
        visited.add(url)

    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            proxies=proxy,
            headers=headers,
            allow_redirects=allow_redirects
        )
        html = response.text
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e} - {url}")
        return

    print(f"{Fore.CYAN}[CRAWLED] {url}")
    save_to_file(os.path.join(output_dir, "crawled_urls.txt"), {url})

    if regexes:
        matches = apply_regex(html, regexes)
        if matches:
            with found_lock:
                new_matches = matches - found
                if new_matches:
                    found.update(new_matches)
                    for m in new_matches:
                        print(f"{Fore.YELLOW}[MATCH] {m}")
                    save_to_file(os.path.join(output_dir, "regex_results.txt"), new_matches)

            if max_count and mode == 'regex' and len(found) >= max_count:
                return

    time.sleep(delay)

    for link in extract_links(html, url, skip_words):
        if not is_same_domain(base_url, link):
            continue
        with visited_lock:
            if link not in visited:
                url_queue.put(link)

# Worker thread loop: pulls URLs from queue and crawls them until limits or stop.
def worker(regexes, proxy, headers, max_count, mode, timeout, allow_redirects, delay, output_dir, skip_words, base_url):
    while not stop_event.is_set():
        try:
            url = url_queue.get(timeout=1)
        except queue.Empty:
            break

        if max_count:
            if mode == 'regex' and len(found) >= max_count:
                break
            elif mode == 'url' and len(visited) >= max_count:
                break

        crawl(url, regexes, proxy, headers, max_count, mode, timeout, allow_redirects, delay, output_dir, skip_words, base_url)
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
            # handle tags like v1 or rc1
            num = re.findall(r'\d+', p)
            parts.append(int(num[0]) if num else 0)
    return tuple(parts) if parts else (0,)

# Extracts VERSION assignment from a python source string.
def extract_version_from_source(source_text):
    m = re.search(r'^\s*VERSION\s*=\s*["\'](.+?)["\']\s*$', source_text, re.MULTILINE)
    return m.group(1).strip() if m else None

# Fetches the latest version string from GitHub (releases API or raw file fallback).
def fetch_latest_version_and_source(proxy=None, timeout=8):
    sess = requests.Session()
    if proxy:
        sess.proxies = proxy

    # Try releases/latest
    try:
        r = sess.get(GITHUB_API_RELEASES_LATEST, timeout=timeout)
        if r.status_code == 200:
            data = r.json()
            tag = data.get("tag_name") or data.get("name") or ""
            latest_ver = tag.lstrip('vV').strip() if tag else None
            # Try to also fetch source from raw main/master for updating
            for raw_url in (GITHUB_RAW_MAIN, GITHUB_RAW_MASTER):
                rr = sess.get(raw_url, timeout=timeout)
                if rr.status_code == 200:
                    return latest_ver, rr.text
        # Fallback to raw main/master only
        for raw_url in (GITHUB_RAW_MAIN, GITHUB_RAW_MASTER):
            rr = sess.get(raw_url, timeout=timeout)
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
                # After updating, it's safer to exit to avoid running mixed code.
                sys.exit(0)
            except Exception as e:
                print(f"{Fore.RED}Update failed: {e}")
        else:
            print(f"{Fore.CYAN}Run with --update to auto-update.")
    else:
        print(f"{Fore.GREEN}You are up-to-date (v{current_version}).")

# ------------------------------------------------------
# CLI / Main
# ------------------------------------------------------

# Entry point: parses args, clears screen, prints banner, checks updates, then runs the crawler.
def main():
    parser = argparse.ArgumentParser(description="webex.py by omidsec")
    parser.add_argument("-u", "--url", required=True, help="Start URL (http or https)")
    parser.add_argument("-p", "--proxy", help="Proxy (http:// or socks5://)")
    parser.add_argument("-r", "--regex", help="Comma-separated regex patterns")
    parser.add_argument("-t", "--thread", type=int, default=1, help="Thread count (default=1)")
    parser.add_argument("-m", "--max", type=int, help="Max matches or max crawled URLs")
    parser.add_argument("-H", "--header", action="append", help="Custom header (e.g. -H \"Key: Value\")")
    parser.add_argument("-a", "--agent", help="Custom User-Agent string")
    parser.add_argument("--delay", type=float, default=0, help="Delay in seconds between requests")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds for each request")
    parser.add_argument("--redirect", choices=["TRUE", "FALSE"], default="TRUE", help="Follow redirects")
    parser.add_argument("--no", help="Comma-separated strings to skip in URLs")
    parser.add_argument("--update", action="store_true", help="Check GitHub and auto-update if a newer version exists")

    args = parser.parse_args()

    # Clear screen and show banner immediately
    clear_console()
    print_banner()

    # Prepare proxy for requests & update check
    proxy = setup_proxy(args.proxy)

    # Always check for a new version BEFORE doing anything else
    check_and_maybe_update(VERSION, auto_update=args.update, proxy=proxy)

    if not args.url.startswith("http"):
        print(f"{Fore.RED}[-] URL must start with http:// or https://")
        sys.exit(1)

    start_url = args.url
    parsed = urlparse(start_url)
    target_host = parsed.netloc.replace(":", "_")
    output_dir = os.path.join("webex_targets", target_host)

    headers = parse_headers(args.header, args.agent)
    regexes = [r.strip() for r in args.regex.split(",")] if args.regex else []
    mode = 'regex' if regexes else 'url'
    allow_redirects = args.redirect.upper() == "TRUE"

    extra_skips = [s.strip().lower() for s in (args.no.split(",") if args.no else [])]
    skip_words = list(set(DEFAULT_SKIP_WORDS + extra_skips))

    url_queue.put(start_url)

    try:
        with ThreadPoolExecutor(max_workers=args.thread) as executor:
            for _ in range(args.thread):
                executor.submit(
                    worker,
                    regexes,
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
            url_queue.join()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Ctrl+C detected. Exiting gracefully...")
        stop_event.set()
        while not url_queue.empty():
            try:
                url_queue.get_nowait()
                url_queue.task_done()
            except:
                continue

    print(f"{Fore.GREEN}Done. Total URLs crawled: {len(visited)}. Total matches: {len(found)}.")
    print(f"{Fore.GREEN}Results saved in: {output_dir}")

if __name__ == "__main__":
    main()
