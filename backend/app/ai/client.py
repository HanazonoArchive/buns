"""DeepSeek chat client (OpenAI-compatible API).

Only this module talks to the external AI service. Callers pass payloads
that have already been through :mod:`app.sanitize`.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx

from ..config import settings


class AIError(RuntimeError):
    pass


_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _parse_json(text: str) -> dict[str, Any]:
    cleaned = _FENCE_RE.sub("", text.strip())
    try:
        data = json.loads(cleaned)
    except ValueError:
        # Last resort: the outermost {...} block.
        start, end = cleaned.find("{"), cleaned.rfind("}")
        if start == -1 or end <= start:
            raise AIError("Model did not return JSON.") from None
        try:
            data = json.loads(cleaned[start : end + 1])
        except ValueError as exc:
            raise AIError("Model returned malformed JSON.") from exc
    if not isinstance(data, dict):
        raise AIError("Model returned JSON that is not an object.")
    return data


class DeepSeekClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        timeout: float = 90.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.api_key = api_key if api_key is not None else settings.deepseek_api_key
        self.base_url = (base_url or settings.deepseek_base_url).rstrip("/")
        self.model = model or settings.deepseek_model
        self._http = httpx.Client(timeout=timeout, transport=transport)

    def complete_json(self, system: str, user: str, retries: int = 2) -> dict[str, Any]:
        if not self.api_key:
            raise AIError("DEEPSEEK_API_KEY is not set.")
        body = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "max_tokens": 1800,
        }
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        last_exc: Exception | None = None
        for attempt in range(retries + 1):
            try:
                resp = self._http.post(f"{self.base_url}/chat/completions", json=body, headers=headers)
            except httpx.HTTPError as exc:
                last_exc = AIError(f"Cannot reach DeepSeek: {exc}")
            else:
                if resp.status_code == 200:
                    try:
                        content = resp.json()["choices"][0]["message"]["content"]
                    except (KeyError, IndexError, ValueError) as exc:
                        raise AIError("Unexpected response shape from DeepSeek.") from exc
                    return _parse_json(content or "")
                if resp.status_code in (401, 402, 403):
                    raise AIError(f"DeepSeek refused the request ({resp.status_code}): {resp.text[:200]}")
                last_exc = AIError(f"DeepSeek returned {resp.status_code}: {resp.text[:200]}")
            if attempt < retries:
                time.sleep(2 * (attempt + 1))
        raise last_exc or AIError("DeepSeek call failed.")

    def close(self) -> None:
        self._http.close()
