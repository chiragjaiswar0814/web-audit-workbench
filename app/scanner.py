from __future__ import annotations

import datetime as dt
import socket
import ssl
from dataclasses import dataclass
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx


SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


@dataclass
class ScanObservation:
    http_status: int | None
    final_url: str | None
    server_header: str | None
    security_headers: dict[str, str]
    missing_security_headers: list[str]
    cookies: list[dict[str, Any]]
    forms: list[dict[str, Any]]
    options_allow: list[str]
    robots_present: bool | None
    security_txt_present: bool | None
    https: bool
    tls: dict[str, Any] | None


@dataclass
class FindingDraft:
    severity: str
    category: str
    title: str
    description: str
    recommendation: str | None = None


class PassiveScanner:
    def __init__(self, timeout_seconds: float = 10.0):
        self.timeout_seconds = timeout_seconds

    async def scan(self, base_url: str) -> tuple[ScanObservation, list[FindingDraft], int, str, str | None]:
        findings: list[FindingDraft] = []
        error_detail: str | None = None

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(self.timeout_seconds),
            headers={"User-Agent": "WebSecurityReviewWorkbench/1.0"},
        ) as client:
            resp = None
            try:
                try:
                    resp = await client.head(base_url)
                except httpx.RequestError:
                    resp = None

                if resp is None or resp.status_code in {405, 501}:
                    resp = await client.get(base_url)
            except httpx.TimeoutException:
                error_detail = "timeout"
                obs = ScanObservation(
                    http_status=None,
                    final_url=None,
                    server_header=None,
                    security_headers={},
                    missing_security_headers=SECURITY_HEADERS.copy(),
                    cookies=[],
                    forms=[],
                    options_allow=[],
                    robots_present=None,
                    security_txt_present=None,
                    https=base_url.lower().startswith("https://"),
                    tls=None,
                )
                findings.append(
                    FindingDraft(
                        severity="high",
                        category="connectivity",
                        title="Request timed out",
                        description="The target did not respond within the configured timeout.",
                        recommendation="Verify the hostname, network path, and consider increasing the timeout for slower environments.",
                    )
                )
                score, sev = score_findings(findings)
                return obs, findings, score, sev, error_detail
            except httpx.HTTPError as e:
                error_detail = _safe_error_string(e)
                obs = ScanObservation(
                    http_status=None,
                    final_url=None,
                    server_header=None,
                    security_headers={},
                    missing_security_headers=SECURITY_HEADERS.copy(),
                    cookies=[],
                    forms=[],
                    options_allow=[],
                    robots_present=None,
                    security_txt_present=None,
                    https=base_url.lower().startswith("https://"),
                    tls=None,
                )

                title = "Request failed"
                desc = f"The request could not be completed: {type(e).__name__}."
                if isinstance(e, httpx.ConnectError):
                    title = "Connection failed"
                elif isinstance(e, httpx.ReadError):
                    title = "Read error"
                elif isinstance(e, httpx.RemoteProtocolError):
                    title = "Protocol error"
                elif isinstance(e, httpx.ConnectTimeout):
                    title = "Connection timed out"
                elif isinstance(e, httpx.ReadTimeout):
                    title = "Read timed out"

                findings.append(
                    FindingDraft(
                        severity="high",
                        category="connectivity",
                        title=title,
                        description=desc,
                        recommendation="Check DNS resolution, network access, and TLS settings. Review the error details in the scan record.",
                    )
                )
                score, sev = score_findings(findings)
                return obs, findings, score, sev, error_detail

            content_type = (resp.headers.get("content-type") or "").lower() if resp else ""
            body = ""
            if resp is not None and "text/html" in content_type:
                try:
                    body = resp.text
                    if len(body) > 1024 * 1024:
                        body = body[: 1024 * 1024]
                except Exception:
                    body = ""

            sec_headers: dict[str, str] = {}
            missing: list[str] = []
            for h in SECURITY_HEADERS:
                v = resp.headers.get(h) if resp else None
                if v:
                    sec_headers[h] = v
                else:
                    missing.append(h)

            server_header = resp.headers.get("server") if resp else None

            cookies = _parse_set_cookie_headers(resp.headers.get_list("set-cookie")) if resp else []
            forms = _discover_forms(body) if body else []

            options_allow: list[str] = []
            try:
                opt = await client.options(resp.url if resp else base_url)
                allow = opt.headers.get("allow") or ""
                options_allow = [m.strip().upper() for m in allow.split(",") if m.strip()]
            except Exception:
                options_allow = []

            robots_present = await _check_simple_path(client, resp.url if resp else base_url, "/robots.txt")
            security_txt_present = await _check_security_txt(client, resp.url if resp else base_url)

            https = str(resp.url).lower().startswith("https://") if resp else base_url.lower().startswith("https://")
            tls = None
            if https:
                try:
                    tls = _tls_metadata(str(resp.url) if resp else base_url)
                except Exception:
                    tls = None

            obs = ScanObservation(
                http_status=resp.status_code if resp else None,
                final_url=str(resp.url) if resp else None,
                server_header=server_header,
                security_headers=sec_headers,
                missing_security_headers=missing,
                cookies=cookies,
                forms=forms,
                options_allow=options_allow,
                robots_present=robots_present,
                security_txt_present=security_txt_present,
                https=https,
                tls=tls,
            )

        findings.extend(_header_findings(obs))
        findings.extend(_cookie_findings(obs))
        findings.extend(_misc_findings(obs))

        score, sev = score_findings(findings)
        return obs, findings, score, sev, error_detail


def _safe_error_string(e: Exception) -> str:
    s = str(e) or type(e).__name__
    s = s.replace("\n", " ").strip()
    if len(s) > 500:
        s = s[:500] + "..."
    return s


def _parse_set_cookie_headers(values: list[str]) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for raw in values:
        c = SimpleCookie()
        try:
            c.load(raw)
        except Exception:
            continue
        for name, morsel in c.items():
            attrs = {k.lower(): morsel[k] for k in morsel.keys()}
            flags = raw.lower()
            parsed.append(
                {
                    "name": name,
                    "secure": "secure" in flags,
                    "httponly": "httponly" in flags,
                    "samesite": (attrs.get("samesite") or "").strip() or None,
                }
            )
    return parsed


def _discover_forms(html: str) -> list[dict[str, Any]]:
    forms: list[dict[str, Any]] = []
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return []

    soup = BeautifulSoup(html, "html.parser")
    for f in soup.find_all("form"):
        method = (f.get("method") or "GET").upper()
        action = f.get("action") or ""
        inputs = len(f.find_all("input"))
        forms.append({"method": method, "action": action, "inputs": inputs})
    return forms[:50]


async def _check_simple_path(client: httpx.AsyncClient, base_url: str, path: str) -> bool | None:
    parts = urlsplit(str(base_url))
    url = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    try:
        r = await client.get(url)
        return r.status_code == 200
    except Exception:
        return None


async def _check_security_txt(client: httpx.AsyncClient, base_url: str) -> bool | None:
    res1 = await _check_simple_path(client, base_url, "/.well-known/security.txt")
    if res1 is True:
        return True
    res2 = await _check_simple_path(client, base_url, "/security.txt")
    if res2 is True:
        return True
    if res1 is None and res2 is None:
        return None
    return False


def _tls_metadata(url: str) -> dict[str, Any] | None:
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        return None
    port = parts.port or 443

    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()

    def _name(seq):
        return ", ".join([f"{k}={v}" for item in seq for k, v in item])

    not_before = cert.get("notBefore")
    not_after = cert.get("notAfter")
    return {
        "subject": _name(cert.get("subject", [])),
        "issuer": _name(cert.get("issuer", [])),
        "not_before": not_before,
        "not_after": not_after,
        "retrieved_at": dt.datetime.utcnow().isoformat() + "Z",
    }


def _header_findings(obs: ScanObservation) -> list[FindingDraft]:
    out: list[FindingDraft] = []

    if not obs.https:
        out.append(
            FindingDraft(
                severity="high",
                category="transport",
                title="Target is not using HTTPS",
                description="The target was accessed over HTTP. Transport encryption is not in use.",
                recommendation="Prefer HTTPS for all environments where credentials, session cookies, or sensitive data may be present.",
            )
        )

    for h in obs.missing_security_headers:
        sev = "medium" if h in {"content-security-policy", "strict-transport-security"} else "low"
        out.append(
            FindingDraft(
                severity=sev,
                category="headers",
                title=f"Missing security header: {h}",
                description="The response did not include this recommended security header.",
                recommendation="Add the header at the edge (reverse proxy/CDN) or application layer with a policy appropriate to the application.",
            )
        )

    if obs.server_header:
        out.append(
            FindingDraft(
                severity="low",
                category="headers",
                title="Server banner is exposed",
                description=f"The response included a Server header: {obs.server_header}",
                recommendation="Consider minimizing server banner detail where feasible.",
            )
        )

    return out


def _cookie_findings(obs: ScanObservation) -> list[FindingDraft]:
    out: list[FindingDraft] = []
    for c in obs.cookies:
        name = c.get("name") or "(cookie)"
        if not c.get("secure") and obs.https:
            out.append(
                FindingDraft(
                    severity="medium",
                    category="cookies",
                    title=f"Cookie missing Secure flag: {name}",
                    description="A cookie was set without the Secure attribute, which allows it to be sent over HTTP.",
                    recommendation="Set Secure on session and sensitive cookies.",
                )
            )
        if not c.get("httponly"):
            out.append(
                FindingDraft(
                    severity="low",
                    category="cookies",
                    title=f"Cookie missing HttpOnly flag: {name}",
                    description="A cookie was set without HttpOnly, which can increase impact of XSS.",
                    recommendation="Set HttpOnly on session cookies unless the application requires JavaScript access.",
                )
            )
        samesite = (c.get("samesite") or "").lower()
        if not samesite:
            out.append(
                FindingDraft(
                    severity="low",
                    category="cookies",
                    title=f"Cookie missing SameSite attribute: {name}",
                    description="A cookie was set without SameSite, which can increase CSRF exposure.",
                    recommendation="Consider SameSite=Lax or SameSite=Strict based on application behavior.",
                )
            )
    return out


def _misc_findings(obs: ScanObservation) -> list[FindingDraft]:
    out: list[FindingDraft] = []

    if obs.robots_present is False:
        out.append(
            FindingDraft(
                severity="low",
                category="discovery",
                title="robots.txt not detected",
                description="No robots.txt was found at /robots.txt.",
                recommendation="If the environment uses robots.txt conventions, consider adding one to document crawler behavior.",
            )
        )

    if obs.security_txt_present is False:
        out.append(
            FindingDraft(
                severity="low",
                category="discovery",
                title="security.txt not detected",
                description="No security.txt was found at /.well-known/security.txt or /security.txt.",
                recommendation="Consider adding security.txt to publish a security contact and disclosure policy.",
            )
        )

    if obs.forms:
        out.append(
            FindingDraft(
                severity="low",
                category="application",
                title="HTML forms detected",
                description=f"The scanner detected {len(obs.forms)} HTML form(s) on the fetched page.",
                recommendation="Ensure forms are protected with CSRF controls and input validation.",
            )
        )

    return out


def score_findings(findings: list[FindingDraft]) -> tuple[int, str]:
    score = 100
    for f in findings:
        sev = (f.severity or "").lower()
        if sev == "high":
            score -= 20
        elif sev == "medium":
            score -= 10
        elif sev == "low":
            score -= 3

    score = max(0, min(100, score))
    if score < 50:
        return score, "high"
    if score < 80:
        return score, "medium"
    return score, "low"
