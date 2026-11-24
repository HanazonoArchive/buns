"""Runtime configuration, read once from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _csv(value: str) -> list[str]:
    return [item.strip().lower() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("BUNS_DATABASE_URL", "sqlite:///./data/buns.db")
    data_dir: Path = Path(os.getenv("BUNS_DATA_DIR", "./data"))

    # Hosts a target may point at. Anything else is refused at registration
    # and again before every outbound request.
    allowed_hosts: list[str] = field(
        default_factory=lambda: _csv(
            os.getenv("BUNS_ALLOWED_HOSTS", "localhost,127.0.0.1,juice-shop")
        )
    )

    zap_url: str = os.getenv("ZAP_URL", "http://localhost:8080")
    zap_api_key: str = os.getenv("ZAP_API_KEY", "")
    zap_timeout_s: int = int(os.getenv("ZAP_TIMEOUT_S", "900"))

    curl_bin: str = os.getenv("CURL_BIN", "curl")
    curl_timeout_s: int = int(os.getenv("CURL_TIMEOUT_S", "10"))

    deepseek_api_key: str = os.getenv("DEEPSEEK_API_KEY", "")
    deepseek_base_url: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    deepseek_model: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
    ai_concurrency: int = int(os.getenv("BUNS_AI_CONCURRENCY", "3"))

    cors_origins: list[str] = field(
        default_factory=lambda: _csv(
            os.getenv("BUNS_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
        )
    )

    @property
    def ai_mode(self) -> str:
        return "deepseek" if self.deepseek_api_key else "offline"


settings = Settings()
