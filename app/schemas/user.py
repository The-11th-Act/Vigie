from pydantic import BaseModel, EmailStr, Field, field_validator

VALID_ROLES = {"admin", "analyst"}

MIN_PASSWORD_LENGTH = 12
# bcrypt silently truncates beyond 72 bytes; reject rather than mislead.
MAX_PASSWORD_LENGTH = 72


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(
        ..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_PASSWORD_LENGTH:
            raise ValueError(f"password must be at most {MAX_PASSWORD_LENGTH} bytes long")
        if not any(c.isalpha() for c in v):
            raise ValueError("password must contain at least one letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("password must contain at least one digit")
        return v

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
    access_token: str
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

    model_config = {"from_attributes": True}


class UserRoleUpdate(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {sorted(VALID_ROLES)}")
        return v
