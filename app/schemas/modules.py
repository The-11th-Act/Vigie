from pydantic import BaseModel, Field, field_validator

from app.core.modules import MODULES_BY_KEY


def _known_modules(keys: list[str]) -> list[str]:
    unknown = [key for key in keys if key not in MODULES_BY_KEY]
    if unknown:
        raise ValueError(f"unknown module(s): {', '.join(sorted(set(unknown)))}")
    if len(set(keys)) != len(keys):
        raise ValueError("a module is listed twice")
    return keys


class ModuleEntry(BaseModel):
    key: str
    label: str
    hidden: bool = False


class MyModulesResponse(BaseModel):
    """The signed-in user's modules, in their order; hidden ones included, so
    the preferences screen can bring them back."""

    role: str
    modules: list[ModuleEntry]
    # The teams whose hosts this user sees ("__none__": hosts without a
    # team); None: the whole estate.
    teams: list[str] | None = None


class PreferencesUpdate(BaseModel):
    order: list[str] = Field(default_factory=list, max_length=len(MODULES_BY_KEY))
    hidden: list[str] = Field(default_factory=list, max_length=len(MODULES_BY_KEY))

    @field_validator("order", "hidden")
    @classmethod
    def known_modules(cls, v: list[str]) -> list[str]:
        return _known_modules(v)


class AdminModule(BaseModel):
    key: str
    label: str
    enabled: bool
    # Cannot be switched off, nor granted to anyone but administrators.
    admin_only: bool


class AdminModulesResponse(BaseModel):
    modules: list[AdminModule]
    # Current profile of every role, and the default it falls back to.
    profiles: dict[str, list[str]]
    defaults: dict[str, list[str]]
    customized: list[str]


class ModuleToggle(BaseModel):
    enabled: bool


class RoleProfileUpdate(BaseModel):
    modules: list[str] = Field(max_length=len(MODULES_BY_KEY))

    @field_validator("modules")
    @classmethod
    def known_modules(cls, v: list[str]) -> list[str]:
        return _known_modules(v)
