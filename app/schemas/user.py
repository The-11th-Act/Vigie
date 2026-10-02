from datetime import datetime
from typing import Annotated

from pydantic import AfterValidator, BaseModel, EmailStr, Field, field_validator

VALID_ROLES = {"admin", "analyst", "remediator"}

MIN_PASSWORD_LENGTH = 12
# bcrypt silently truncates beyond 72 bytes; reject rather than mislead.
MAX_PASSWORD_LENGTH = 72


def _strong(v: str) -> str:
    if len(v.encode("utf-8")) > MAX_PASSWORD_LENGTH:
        raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} bytes long")
    if not any(c.isalpha() for c in v):
        raise ValueError("password must contain at least one letter")
    if not any(c.isdigit() for c in v):
        raise ValueError("password must contain at least one digit")
    return v


# The same rule wherever a password is set: creation, reset, change.
Password = Annotated[
    str,
    Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH),
    AfterValidator(_strong),
]


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: Password

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.strip().lower()


class UserLogin(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def normalize_username(cls, v: str) -> str:
        return v.strip().lower()


class Token(BaseModel):
    # Absent in cookie mode: the tokens then travel only as HttpOnly cookies.
    access_token: str | None = None
    refresh_token: str | None = None
    # "bearer" is the OAuth2 scheme name, not a credential.
    token_type: str = "bearer"  # noqa: S105
    role: str
    username: str


class RefreshRequest(BaseModel):
    refresh_token: str


class TokenPayload(BaseModel):
    sub: str | None = None
    role: str | None = None
    exp: int | None = None


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    role: str
    is_active: bool = True
    created_at: datetime | None = None
    # The teams whose hosts the user sees ("__none__": hosts without a team);
    # empty: the whole estate.
    teams: list[str] = []

    model_config = {"from_attributes": True}


class UserTeamsUpdate(BaseModel):
    """A user's scope; an empty list gives back the whole estate."""

    teams: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=50
    )


class UserRoleUpdate(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
        return v


class UserAdminCreate(UserCreate):
    """An account an administrator creates: the only way in, self-registration
    being closed. The password is the initial one, to hand over."""

    role: str = "analyst"
    teams: list[Annotated[str, Field(min_length=1, max_length=128)]] = Field(
        default_factory=list, max_length=50
    )

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
        return v


class UserActiveUpdate(BaseModel):
    active: bool


class PasswordReset(BaseModel):
    """An administrator sets a new password, for a user who lost theirs."""

    password: Password


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=MAX_PASSWORD_LENGTH * 4)
    new_password: Password
