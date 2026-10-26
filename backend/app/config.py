from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings. Loaded from environment (prefix SHIELD_) or a .env file.

    Secrets (SECRET_KEY, CREDENTIAL_KEY) must come from a root-owned 0600 env file
    in production (see deploy/env/shield.env.example).
    """

    model_config = SettingsConfigDict(env_prefix="SHIELD_", env_file=".env", extra="ignore")

    env: str = Field("development", pattern="^(development|test|production)$")
    database_url: str = "postgresql+psycopg://shield@127.0.0.1/shield"

    # JWT signing key (>= 32 chars). Rotating it invalidates all access tokens.
    secret_key: str = Field(..., min_length=32)
    # Fernet key (urlsafe base64, 32 bytes) used to encrypt router/notification secrets at rest.
    credential_key: str | None = None

    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 8 * 3600
    jwt_issuer: str = "crapplet-shield"

    # Login protection
    login_max_failures: int = 5
    login_lockout_seconds: int = 900
    login_rate_per_minute: int = 20

    # Global API write rate limit per user
    write_rate_per_minute: int = 120

    # Trusted reverse proxy addresses whose X-Forwarded-For we honour
    trusted_proxies: list[str] = ["127.0.0.1", "::1"]

    expose_docs: bool = False
    cors_origins: list[str] = []

    # Live telemetry (Phase 3). Both are optional: the API degrades to "unavailable" without them.
    redis_url: str = "redis://127.0.0.1:6379/0"
    clickhouse_url: str = "http://127.0.0.1:8123"
    clickhouse_database: str = Field("shield", pattern=r"^[A-Za-z0-9_]+$")
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    # Snapshots older than this are reported as unavailable rather than shown as current.
    live_stale_seconds: int = 5
    iface_stale_seconds: int = 60
    # IP-to-ASN database (iptoasn.com ip2asn-combined.tsv.gz, public domain), refreshed weekly by
    # shield-asn-update.timer. Without it, attack sources show AS numbers only if routers export them.
    asn_db_path: str = "/var/lib/crapplet-shield/ip2asn-combined.tsv.gz"
    asn_db_url: str = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

    @field_validator("secret_key")
    @classmethod
    def _no_placeholder(cls, v: str) -> str:
        if "CHANGE_ME" in v:
            raise ValueError("SHIELD_SECRET_KEY still contains the CHANGE_ME placeholder")
        return v

    @property
    def docs_enabled(self) -> bool:
        return self.env != "production" or self.expose_docs


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
