from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit


_URL_MAX = 2048


def normalize_http_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("URL is required")
    if len(value) > _URL_MAX:
        raise ValueError("URL is too long")

    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"}:
        raise ValueError("Only http:// or https:// URLs are allowed")
    if not parts.netloc:
        raise ValueError("URL must include a hostname")
    if parts.username or parts.password:
        raise ValueError("URLs with embedded credentials are not allowed")

    host = parts.hostname or ""
    if host.lower() in {"localhost"}:
        pass
    elif re.match(r"^[A-Za-z0-9.-]+$", host) is None and ":" not in host:
        raise ValueError("Hostname contains invalid characters")

    normalized = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))
    if len(normalized) > _URL_MAX:
        raise ValueError("URL is too long")
    return normalized


def severity_rank(sev: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get((sev or "").lower(), 0)
