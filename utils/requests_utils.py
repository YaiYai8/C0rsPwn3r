import requests
from typing import Optional, Dict, Tuple, List
from utils.helpers import msg_warning

def send_cors_request(url: str,origin: str,headers: Optional[List[str]] = None, proxies: Optional[Dict[str, str]] = None, verify_ssl: bool = True,method: str = "GET") -> Tuple[int, Dict[str, str], str]:
    """
    Sends a CORS request with the specified Origin header.
    
    :param url: The full target URL (including endpoint)
    :param origin: The Origin to spoof in the request
    :param headers: List of custom headers (["Header: value"])
    :param proxies: Dict of proxy settings, or None
    :param verify_ssl: Whether to verify SSL cert
    :param method: HTTP method (default is GET)
    :return: Tuple of (status_code, response_headers, response_body)
    """
    
    req_headers = {
        "Origin": origin,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36"
    }
    # Add custom headers from CLI
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                req_headers[k.strip()] = v.strip()
    
    try:
        resp = requests.request(method=method, url=url, headers=req_headers, timeout=10, allow_redirects=False, verify=verify_ssl, proxies=proxies)
        return resp.status_code, resp.headers, resp.text
    except requests.exceptions.RequestException as e:
        msg_warning(f"Request to {url} with origin {origin} failed: {e}")
        return 0, {}, ''