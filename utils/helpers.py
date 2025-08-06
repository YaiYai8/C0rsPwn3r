import os
import re
import json
import requests
from typing import Optional, Dict, Tuple, List
from urllib.parse import urlparse
from ten import msg_success, msg_warning, msg_failure

def check_url_reachable(url: str, proxies=None, verify=True) -> bool:
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True, proxies=proxies, verify=verify)
        if resp.status_code >= 200 and resp.status_code < 400:
            msg_success(f"Target URL is reachable: {url} ({resp.status_code})")
            return True
        else:
            msg_failure(f"Target responded with status code {resp.status_code}.")
            return False
    except requests.exceptions.RequestException as e:
        msg_failure(f"Failed to reach target URL {url}: {e}")
        return False

def extract_domain(url: str) -> str:
    """
    Extracts the domain from a full URL.
    Removes protocol, port, and path.
    """
    parsed = urlparse(url)
    return str(parsed.scheme + '://' + parsed.netloc)

def load_endpoints(endpoint: Optional[str], list_file: Optional[str]) -> List[str]:
    """
    Loads endpoints from either a single one or a file of endpoints.
    Ensures:
      - Each endpoint starts with '/'
      - No special characters other than '/', letters, digits
      - Removes trailing slash (e.g., /api/ -> /api)
    Returns a list of clean, unique endpoints to scan.
    """
    endpoints = []

    def clean(ep: str) -> Optional[str]:
        ep = ep.strip()
        if not ep:
            return None
        if not ep.startswith("/"):
            ep = "/" + ep
        if ep.endswith("/") and len(ep) > 1:
            ep = ep[:-1]
        if re.fullmatch(r"[/a-zA-Z0-9_-]+", ep):
            return ep
        return None

    if endpoint:
        cleaned = clean(endpoint)
        if cleaned:
            endpoints.append(cleaned)
    elif list_file:
        if not os.path.isfile(list_file):
            msg_failure(f"File '{list_file}' not found.")
            return []
        with open(list_file, 'r') as f:
            for line in f:
                cleaned = clean(line)
                if cleaned:
                    endpoints.append(cleaned)

    return sorted(set(endpoints))  # remove duplicates

def save_findings_to_file(findings: List[Dict], output_file: str = "cors_findings.json") -> None:
    try:
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=4)
        msg_success(f"Saved findings to {output_file}")
    except Exception as e:
        msg_failure(f"Failed to save findings: {e}")

def get_origins_to_test(base_origin: str, url: str, extended: bool = False) -> List[str]:
    """
    Builds a list of crafted origins to test against the target.
    Includes reflected, null, wildcard-bypass, parser tricks, etc.
    """

    #print(base_origin,random_count,url)
    origins = []
    # User input (Reflected)
    origins.append(base_origin) 
    # Classic evil origins
    origins += [ 
        "https://evil.com","http://evil.com","https://evil321.ru",'http://bulila.bul:8000'
    ]
    # For null Attacks (Null Origin)
    origins.append("null") 
    parsed = urlparse(url)
    target_domain = parsed.netloc or "target.com"
    target_protocol = parsed.scheme or "https"

    # Suffix bypass / prefix confusion (Improper Origin Whitelist Matching)
    origins.append(f"{target_protocol}://{target_domain}.evil.com") # Suffix
    origins.append(f"{target_protocol}://evil.{target_domain}") # Prefix
    origins.append(f"{target_protocol}://attacker.{target_domain}.evil.net")
    origins.append(f"{target_protocol}://attacker{target_domain}")

    # Parser Confusion
    origins.append(f"{target_protocol}://{target_domain}%60.attacker.net")     # backtick
    origins.append(f"{target_protocol}://{target_domain}%2e.attacker.net")     # encoded dot

    # Non-existent subdomain (blind trust test)
    origins.append(f"{target_protocol}://YshachaR.{target_domain}")

    if extended:
        origins += [
            "file://",                          # local file origin
            "chrome-extension://abc123",        # Chrome extensions
            "moz-extension://abc123",           # Firefox extensions
            "https://localhost",                # Localhost
            "https://127.0.0.1",                # Loopback
            f"https://{target_domain}.",        # Extra dot at end
        ]
    return sorted(set(origins))
