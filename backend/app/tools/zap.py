"""Client for the OWASP ZAP JSON API (daemon mode)."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx

from ..config import settings


class ZapError(RuntimeError):
    pass


class ZapClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: float = 30.0):
        self.base_url = (base_url or settings.zap_url).rstrip("/")
        self.api_key = api_key if api_key is not None else settings.zap_api_key
        self._http = httpx.Client(timeout=timeout)

    # -- transport -------------------------------------------------------
    def _call(self, component: str, kind: str, name: str, **params: Any) -> dict[str, Any]:
        query = {k: v for k, v in params.items() if v is not None}
        if self.api_key:
            query["apikey"] = self.api_key
        url = f"{self.base_url}/JSON/{component}/{kind}/{name}/"
        try:
            resp = self._http.get(url, params=query)
        except httpx.HTTPError as exc:
            raise ZapError(f"Cannot reach ZAP at {self.base_url}: {exc}") from exc
        try:
            data = resp.json()
        except ValueError as exc:
            raise ZapError(f"ZAP returned non-JSON ({resp.status_code}) for {component}/{name}") from exc
        if resp.status_code >= 400 or data.get("code") in ("bad_api_key", "no_access", "bad_view", "bad_action"):
            raise ZapError(f"ZAP {component}/{name} failed: {data.get('message') or data}")
        return data

    def view(self, component: str, name: str, **params: Any) -> dict[str, Any]:
        return self._call(component, "view", name, **params)

    def action(self, component: str, name: str, **params: Any) -> dict[str, Any]:
        return self._call(component, "action", name, **params)

    def close(self) -> None:
        self._http.close()

    # -- helpers ---------------------------------------------------------
    def version(self) -> str:
        return self.view("core", "version")["version"]

    def setup_context(self, name: str, includes: list[str], excludes: list[str]) -> str:
        try:
            self.action("context", "removeContext", contextName=name)
        except ZapError:
            pass
        ctx_id = self.action("context", "newContext", contextName=name)["contextId"]
        for rx in includes:
            self.action("context", "includeInContext", contextName=name, regex=rx)
        for rx in excludes:
            self.action("context", "excludeFromContext", contextName=name, regex=rx)
            # Also keep the spider and scanner away from excluded paths globally.
            self.action("spider", "excludeFromScan", regex=rx)
            self.action("ascan", "excludeFromScan", regex=rx)
        return str(ctx_id)

    def access(self, url: str) -> None:
        self.action("core", "accessUrl", url=url, followRedirects="false")

    def _wait(
        self,
        poll: Callable[[], int],
        on_progress: Callable[[int], None] | None,
        timeout_s: int,
        label: str,
    ) -> None:
        start = time.monotonic()
        last = -1
        while True:
            pct = poll()
            if pct != last and on_progress:
                on_progress(pct)
                last = pct
            if pct >= 100:
                return
            if time.monotonic() - start > timeout_s:
                raise ZapError(f"{label} did not finish within {timeout_s}s")
            time.sleep(2)

    def send_raw(self, request: str) -> None:
        self.action("core", "sendRequest", request=request, followRedirects="false")

    def spider(self, url: str, context: str, on_progress=None, max_children: int = 0) -> list[str]:
        scan_id = self.action(
            "spider", "scan", url=url, contextName=context, recurse="true", maxChildren=max_children or None
        )["scan"]
        self._wait(
            lambda: int(self.view("spider", "status", scanId=scan_id)["status"]),
            on_progress,
            settings.zap_timeout_s,
            "Spider",
        )
        return list(self.view("spider", "results", scanId=scan_id).get("results", []))

    def ajax_spider(self, url: str, context: str, max_minutes: int = 3) -> int:
        self.action("ajaxSpider", "setOptionMaxDuration", Integer=str(max_minutes))
        self.action("ajaxSpider", "scan", url=url, contextName=context, inScope="true")
        deadline = time.monotonic() + max_minutes * 60 + 60
        while time.monotonic() < deadline:
            if self.view("ajaxSpider", "status")["status"] != "running":
                break
            time.sleep(3)
        else:
            self.action("ajaxSpider", "stop")
        return int(self.view("ajaxSpider", "numberOfResults")["numberOfResults"])

    def wait_passive(self, timeout_s: int = 300) -> None:
        start = time.monotonic()
        while int(self.view("pscan", "recordsToScan")["recordsToScan"]) > 0:
            if time.monotonic() - start > timeout_s:
                raise ZapError("Passive scan backlog did not drain in time")
            time.sleep(2)

    def make_policy(self, name: str, scanner_ids: list[int]) -> list[int]:
        try:
            self.action("ascan", "removeScanPolicy", scanPolicyName=name)
        except ZapError:
            pass
        self.action("ascan", "addScanPolicy", scanPolicyName=name)
        self.action("ascan", "disableAllScanners", scanPolicyName=name)
        enabled: list[int] = []
        for sid in scanner_ids:
            try:
                self.action("ascan", "enableScanners", ids=str(sid), scanPolicyName=name)
                enabled.append(sid)
            except ZapError:
                # Rule not installed in this ZAP build; skip it.
                continue
        return enabled

    def active_scan(self, url: str, context_id: str, policy: str, on_progress=None) -> None:
        scan_id = self.action(
            "ascan",
            "scan",
            url=url,
            recurse="true",
            inScopeOnly="false",
            scanPolicyName=policy,
            contextId=context_id,
        )["scan"]
        self._wait(
            lambda: int(self.view("ascan", "status", scanId=scan_id)["status"]),
            on_progress,
            settings.zap_timeout_s,
            "Active scan",
        )

    def alerts(self, base_url: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        start = 0
        while True:
            batch = self.view("alert", "alerts", baseurl=base_url, start=start, count=500).get("alerts", [])
            out.extend(batch)
            if len(batch) < 500:
                return out
            start += 500

    def message(self, message_id: str | int) -> dict[str, str]:
        return self.view("core", "message", id=str(message_id)).get("message", {})
