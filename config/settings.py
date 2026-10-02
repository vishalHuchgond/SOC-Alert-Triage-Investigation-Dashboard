"""Application settings loaded from environment variables (.env)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

CONFIG_DIR = Path(__file__).resolve().parent


@dataclass
class Settings:
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    mongo_db: str = os.getenv("MONGO_DB", "soc_platform")
    vt_api_key: str | None = os.getenv("VT_API_KEY") or None
    analyst_name: str = os.getenv("ANALYST_NAME", "analyst")
    syslog_year: int = int(os.getenv("SYSLOG_YEAR", "2026"))
    max_file_size_mb: int = int(os.getenv("MAX_FILE_SIZE_MB", "50"))
    max_rows: int = int(os.getenv("MAX_ROWS", "200000"))
    ioc_cache_ttl_hours: int = int(os.getenv("IOC_CACHE_TTL_HOURS", "24"))
    vt_rate_per_minute: int = 4       # VirusTotal free tier
    vt_daily_quota: int = 500         # VirusTotal free tier
    app_version: str = "1.0.0"

    @property
    def vt_configured(self) -> bool:
        return bool(self.vt_api_key)

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024


def get_settings() -> Settings:
    return Settings()
