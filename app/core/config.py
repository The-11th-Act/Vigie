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

    DATABASE_URL: str = "postgresql://tvm_user:tvm_password@localhost:5432/tvm_platform"
    REDIS_URL: str = "redis://localhost:6379/0"
    BACKEND_CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
    ]

    # 50 MB — large enough for a real enterprise Nessus export, small enough
    # that a single upload cannot exhaust worker memory.
    MAX_SCAN_UPLOAD_BYTES: int = 50 * 1024 * 1024

    LOG_LEVEL: str = "INFO"

    # All three required together: bootstraps (or promotes) the first admin
    # account on startup. Left unset, no admin is created automatically.
    ADMIN_USERNAME: str | None = None
    ADMIN_EMAIL: str | None = None
    ADMIN_PASSWORD: str | None = None

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
        warnings.warn(
            f"{message} (allowed because ENVIRONMENT is not 'production')",
            stacklevel=2,
        )
        return self


def generate_secret_key() -> str:
    """Convenience helper for bootstrapping a local .env file."""
    return secrets.token_urlsafe(48)


settings = Settings()
