from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse
import validators


def is_valid_originUrl(origin: str) -> bool:
    """
    Validates the user-supplied Origin string.
    Accepts standard formats like https://example.com, http://localhost:3000, null, file://
    Rejects malformed or incomplete values (e.g., 'oooo', 'http:/example')
    """

    if origin.lower() == "null":
        return True
    parsed = urlparse(origin)
    if parsed.scheme not in ["http", "https", "file", "chrome-extension", "moz-extension"]:
        return False
    if not validators.url(origin):
        return False
    parts = parsed.path.split('/')
    if len(parts) != 1:
        return False
    return True
