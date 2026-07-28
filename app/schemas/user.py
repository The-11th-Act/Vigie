from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

VALID_ROLES = {"admin", "analyst"}

MIN_PASSWORD_LENGTH = 12
# bcrypt silently truncates beyond 72 bytes; reject rather than mislead.
MAX_PASSWORD_LENGTH = 72


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_PASSWORD_LENGTH:
            raise ValueError(
                f"password must be at most {MAX_PASSWORD_LENGTH} bytes long"
            )
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
    token_type: str = "bearer"
    role: str
    username: str


class TokenPayload(BaseModel):
    sub: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[int] = None


class UserResponse(BaseModel):
    id: int
    email: str
    username: str
    role: str

    model_config = {"from_attributes": True}
