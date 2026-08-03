import secrets
import warnings

from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Any SECRET_KEY at or below this length is trivially brute-forceable.
MIN_SECRET_KEY_LENGTH = 32

# Values shipped in docker-compose / examples. Refuse them outside development.
INSECURE_SECRET_KEYS = {
    "supersecretjwtkeychangeitinproduction1234567890",
    "changeme",
    "secret",
}


class Settings(BaseSettings):
    PROJECT_NAME: str = "TVM Platform"
    API_V1_STR: str = "/api/v1"
    ENVIRONMENT: str = "development"  # development | staging | production

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Login throttling. Disabled in the test suite, which drives the endpoint
    # far past these thresholds on purpose.
    RATE_LIMIT_ENABLED: bool = True
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_WINDOW_SECONDS: int = 300
    LOGIN_LOCKOUT_SECONDS: int = 900

    DATABASE_URL: str = "postgresql://tvm_user:tvm_password@localhost:5432/tvm_platform"
    REDIS_URL: str = "redis://localhost:6379/0"
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
    ]

    # 50 MB — large enough for a real enterprise Nessus export, small enough
    # that a single upload cannot exhaust worker memory.
    MAX_SCAN_UPLOAD_BYTES: int = 50 * 1024 * 1024

    # Uploads are staged here and only the path is handed to Celery: passing a
    # 50 MB payload through the broker would serialise it into Redis in full.
    # Must be a volume shared between the API and the worker.
    SCAN_UPLOAD_DIR: str = "/var/lib/vigie/scans"

    # Subnet -> business criticality, applied to newly discovered assets.
    # The most specific matching prefix wins. Example:
    #   {"10.0.0.0/8": "Low", "10.0.5.0/24": "Critical"}
    CRITICALITY_RULES: dict[str, str] = {}

    # Consecutive scans of a source in which a finding may go unseen before it
    # is closed as remediated. 0 disables automatic closure entirely.
    AUTO_REMEDIATE_AFTER_MISSES: int = 3

    LOG_LEVEL: str = "INFO"

    # All three required together: bootstraps (or promotes) the first admin
    # account on startup. Left unset, no admin is created automatically.
    ADMIN_USERNAME: str | None = None
    ADMIN_EMAIL: str | None = None
    ADMIN_PASSWORD: str | None = None

    # CrowdStrike Falcon Spotlight. The base URL is region-specific — check
    # your tenant (api.eu-1, api.us-2, …) rather than assuming the default.
    CROWDSTRIKE_CLIENT_ID: str | None = None
    CROWDSTRIKE_CLIENT_SECRET: str | None = None
    CROWDSTRIKE_BASE_URL: str = "https://api.crowdstrike.com"
    CROWDSTRIKE_SYNC_ENABLED: bool = False
    # Minutes between scheduled pulls, when the sync is enabled.
    CROWDSTRIKE_SYNC_INTERVAL_MINUTES: int = 360

    @property
    def crowdstrike_configured(self) -> bool:
        return bool(self.CROWDSTRIKE_CLIENT_ID and self.CROWDSTRIKE_CLIENT_SECRET)

    model_config = SettingsConfigDict(
        case_sensitive=True, env_file=".env", extra="ignore"
    )

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT.lower() == "production"

    @field_validator("BACKEND_CORS_ORIGINS")
    @classmethod
    def reject_wildcard_origin(cls, v: list[str]) -> list[str]:
        # "*" combined with allow_credentials=True is rejected by browsers and
        # would silently break every authenticated request.
        if "*" in v:
            raise ValueError(
                "BACKEND_CORS_ORIGINS cannot contain '*' because credentials are "
                "allowed; list the exact origins instead."
            )
        return v

    @model_validator(mode="after")
    def validate_secret_key(self) -> "Settings":
        weak = (
            len(self.SECRET_KEY) < MIN_SECRET_KEY_LENGTH
            or self.SECRET_KEY in INSECURE_SECRET_KEYS
        )
        if not weak:
            return self

        message = (
            "SECRET_KEY is weak or is a known default value. Generate one with: "
            "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
        if self.is_production:
            raise ValueError(message)
        warnings.warn(f"{message} (allowed because ENVIRONMENT is not 'production')")
        return self


def generate_secret_key() -> str:
    """Convenience helper for bootstrapping a local .env file."""
    return secrets.token_urlsafe(48)


settings = Settings()
