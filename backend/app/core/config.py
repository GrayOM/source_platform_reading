from functools import lru_cache
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Application
    app_name: str = "SSS Platform"
    environment: str = "development"
    debug: bool = False
    api_prefix: str = "/api/v1"

    # Security
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7
    fernet_key: str  # for session cookie encryption

    # Database
    database_url: str

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Storage
    scan_data_path: Path = Path("/data/scans")

    # Crawler settings
    max_crawl_depth: int = 5
    max_crawl_pages: int = 500
    max_resource_size_mb: int = 10
    crawl_concurrency: int = 5
    crawl_timeout_seconds: int = 30
    allow_external_resources: bool = False
    allow_private_targets: bool = False
    ssrf_allowed_hosts: str = ""

    # AI
    anthropic_api_key: str = ""
    gemini_api_key: str = ""
    ai_model: str = "claude-sonnet-4-6"
    ai_max_tokens: int = 8192

    # CORS
    allowed_origins: str = "http://localhost:3000"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",")]

    @property
    def ssrf_allowed_hosts_list(self) -> list[str]:
        return [h.strip().lower() for h in self.ssrf_allowed_hosts.split(",") if h.strip()]

    @property
    def max_resource_size_bytes(self) -> int:
        return self.max_resource_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
