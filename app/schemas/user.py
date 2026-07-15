from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional


VALID_ROLES = {"admin", "analyst"}


class UserCreate(BaseModel):
    email: EmailStr
    username: str
    password: str
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        v = v.lower()
        if v not in VALID_ROLES:
            raise ValueError(f"role must be one of {VALID_ROLES}")
        return v


class UserLogin(BaseModel):
    username: str
    password: str


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