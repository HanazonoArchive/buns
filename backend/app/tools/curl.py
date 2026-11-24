"""Thin wrapper around the curl binary.

cURL runs as a subprocess with an argument list (never through a shell), no
redirect following and a hard timeout. The raw request is reconstructed so
it can be shown as evidence next to the raw response.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..config import settings

USER_AGENT = "buns-assessment/0.1 (+authorised lab testing)"


class CurlError(RuntimeError):
    pass


@dataclass
class HttpExchange:
    method: str
    url: str
    request_headers: dict[str, str]
    request_body: str
    status: int
    reason: str
    headers: dict[str, str]
    body: str
    command: list[str] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None

    @property
    def request_raw(self) -> str:
        parts = urlsplit(self.url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"{self.method} {path} HTTP/1.1", f"Host: {parts.netloc}"]
        lines += [f"{k}: {v}" for k, v in self.request_headers.items()]
        raw = "\r\n".join(lines) + "\r\n\r\n"
        return raw + (self.request_body or "")

    @property
    def response_raw(self) -> str:
        lines = [f"HTTP/1.1 {self.status} {self.reason}".rstrip()]
        lines += [f"{k}: {v}" for k, v in self.headers.items()]
        return "\r\n".join(lines) + "\r\n\r\n" + self.body

    @property
    def command_line(self) -> str:
        import shlex

        return " ".join(shlex.quote(part) for part in self.command)


def _split_response(raw: str) -> tuple[int, str, dict[str, str], str]:
    text = raw.replace("\r\n", "\n")
    # Skip interim responses (100 Continue) that curl -i prints first.
    while True:
        head, sep, rest = text.partition("\n\n")
        if not sep:
            head, rest = text, ""
        status_line = head.split("\n", 1)[0]
        if status_line.startswith("HTTP/") and " 100" in status_line[:13] and rest.startswith("HTTP/"):
            text = rest
            continue
        break
    lines = head.split("\n")
    status_line = lines[0]
    bits = status_line.split(" ", 2)
    if len(bits) < 2 or not bits[0].startswith("HTTP/"):
        raise CurlError(f"Unexpected response line: {status_line[:80]!r}")
    status = int(bits[1])
    reason = bits[2] if len(bits) > 2 else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            key = k.strip()
            if key in headers:
                headers[key] = headers[key] + ", " + v.strip()
            else:
                headers[key] = v.strip()
    return status, reason, headers, rest


def available() -> bool:
    return shutil.which(settings.curl_bin) is not None


def request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    timeout: int | None = None,
    max_body: int = 200_000,
) -> HttpExchange:
    req_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    req_headers.update(headers or {})
    cmd = [
        settings.curl_bin,
        "--silent",
        "--show-error",
        "--include",
        "--path-as-is",
        "--globoff",
        "--max-time",
        str(timeout or settings.curl_timeout_s),
        "--request",
        method,
    ]
    for k, v in req_headers.items():
        cmd += ["--header", f"{k}: {v}"]
    if body is not None:
        cmd += ["--data-raw", body]
    cmd += ["--", url]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=(timeout or settings.curl_timeout_s) + 5)
    except FileNotFoundError as exc:
        raise CurlError(f"curl binary '{settings.curl_bin}' not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise CurlError(f"curl timed out on {url}") from exc
    # 18 = "partial file": the server sent less than its Content-Length
    # promised (Juice Shop's /ftp listing does this). The bytes received are
    # still valid evidence, so keep them.
    if proc.returncode != 0 and not (proc.returncode == 18 and proc.stdout):
        raise CurlError(proc.stderr.decode(errors="replace").strip() or f"curl exited {proc.returncode}")

    raw = proc.stdout.decode("utf-8", errors="replace")
    status, reason, resp_headers, resp_body = _split_response(raw)
    if len(resp_body) > max_body:
        resp_body = resp_body[:max_body] + f"\n[... {len(resp_body) - max_body} more bytes not stored]"
    return HttpExchange(
        method=method,
        url=url,
        request_headers=req_headers,
        request_body=body or "",
        status=status,
        reason=reason,
        headers=resp_headers,
        body=resp_body,
        command=cmd,
    )
