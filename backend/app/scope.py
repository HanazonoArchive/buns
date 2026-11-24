"""Scope enforcement.

Every outbound request the platform makes (cURL probes, URLs handed to ZAP,
alerts pulled back from ZAP) passes through :func:`check`. A request is
allowed only when:

1. the scheme is http or https,
2. the host is in ``BUNS_ALLOWED_HOSTS`` (loopback and the Juice Shop
   container by default),
3. the scheme, host and port match the registered target exactly,
4. the path starts with one of the target's in-scope prefixes (or the
   in-scope list is empty, meaning the whole origin), and
5. the path does not start with any out-of-scope prefix.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from .config import settings


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Origin:
    scheme: str
    host: str
    port: int

    @property
    def base(self) -> str:
        default = 443 if self.scheme == "https" else 80
        port = "" if self.port == default else f":{self.port}"
        return f"{self.scheme}://{self.host}{port}"


def parse_origin(url: str) -> Origin:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise ScopeError(f"Only http and https URLs can be tested, got '{parts.scheme or url}'.")
    if not parts.hostname:
        raise ScopeError("The URL has no host.")
    if parts.username or parts.password:
        raise ScopeError("Credentials in the URL are not allowed.")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError as exc:
        raise ScopeError(f"Invalid port in '{url}'.") from exc
    return Origin(parts.scheme, parts.hostname.lower(), port)


def validate_target_url(url: str, allowed_hosts: list[str] | None = None) -> str:
    """Return the normalised base URL or raise ScopeError."""
    allowed = allowed_hosts if allowed_hosts is not None else settings.allowed_hosts
    origin = parse_origin(url)
    if origin.host not in allowed:
        raise ScopeError(
            f"Host '{origin.host}' is not on the authorised list ({', '.join(allowed)}). "
            "Only the local lab environment may be registered."
        )
    return origin.base


def normalise_prefixes(prefixes: list[str]) -> list[str]:
    out: list[str] = []
    for raw in prefixes:
        p = raw.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        if p not in out:
            out.append(p)
    return out


def _path(url: str) -> str:
    parts = urlsplit(url)
    path = parts.path or "/"
    # Juice Shop is a SPA: hash routes like /#/administration are part of
    # what the assessor scoped, so include the fragment in the comparison.
    if parts.fragment:
        path = path + "#" + parts.fragment
    return path


def check(
    url: str,
    base_url: str,
    in_scope: list[str],
    out_of_scope: list[str],
    allowed_hosts: list[str] | None = None,
) -> None:
    """Raise ScopeError unless ``url`` may be requested for this target."""
    allowed = allowed_hosts if allowed_hosts is not None else settings.allowed_hosts
    origin = parse_origin(url)
    target = parse_origin(base_url)

    if origin.host not in allowed:
        raise ScopeError(f"{url}: host '{origin.host}' is not authorised.")
    if origin != target:
        raise ScopeError(f"{url}: outside the target origin {target.base}.")

    path = _path(url)
    for prefix in out_of_scope:
        if path.startswith(prefix):
            raise ScopeError(f"{url}: excluded by out-of-scope rule '{prefix}'.")
    if in_scope and not any(path.startswith(prefix) for prefix in in_scope):
        raise ScopeError(f"{url}: not under any in-scope path.")


def is_allowed(url: str, base_url: str, in_scope: list[str], out_of_scope: list[str]) -> bool:
    try:
        check(url, base_url, in_scope, out_of_scope)
    except ScopeError:
        return False
    return True


def zap_regexes(base_url: str, in_scope: list[str], out_of_scope: list[str]) -> tuple[list[str], list[str]]:
    """Translate scope rules into ZAP context include/exclude regexes."""
    import re

    base = re.escape(base_url.rstrip("/"))
    includes = (
        [f"{base}{re.escape(p)}.*" for p in in_scope if "#" not in p]
        if in_scope
        else [f"{base}/.*", f"{base}"]
    )
    # A SPA hash route is served from "/", so make sure the root is reachable.
    if in_scope and any("#" in p for p in in_scope):
        includes.append(f"{base}/?")
    excludes = [f"{base}{re.escape(p)}.*" for p in out_of_scope if "#" not in p]
    return includes, excludes
