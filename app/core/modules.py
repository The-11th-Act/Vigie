"""Modules: the sections of the application, and who may use each.

A user's modules are those of their role's profile, minus any an administrator
switched off for the instance, in the order the user chose. The server checks
them on every request (``require_module``): taking a tab out of the sidebar
would otherwise protect nothing, since the API behind it stays reachable.
"""

from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import decode_token
from app.db.database import get_db
from app.models.preferences import ModuleSetting, RoleProfile, UserPreference
from app.models.user import User

ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
# Fixes what the backlog asks for, without deciding what is an acceptable risk.
ROLE_REMEDIATOR = "remediator"
ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_REMEDIATOR)


@dataclass(frozen=True)
class Module:
    key: str
    label: str
    # Reserved to administrators whatever the profiles say.
    admin_only: bool = False


# Registry order is the default order of the sidebar.
MODULES = (
    Module("dashboard", "Dashboard"),
    Module("backlog", "Risk Backlog"),
    Module("remediation", "Remediation"),
    Module("assets", "Assets"),
    Module("vulnerabilities", "Vulnerabilities"),
    Module("scans", "Scans"),
    Module("admin", "Administration", admin_only=True),
)
MODULES_BY_KEY = {module.key: module for module in MODULES}
ADMIN_MODULE = "admin"

DEFAULT_PROFILES: dict[str, list[str]] = {
    ROLE_ADMIN: [module.key for module in MODULES],
    ROLE_ANALYST: [
        "dashboard",
        "backlog",
        "remediation",
        "assets",
        "vulnerabilities",
        "scans",
    ],
    # Their work starts from what to deploy, not from the CVE list.
    ROLE_REMEDIATOR: ["remediation", "dashboard", "backlog", "assets"],
}


@dataclass(frozen=True)
class ModuleAccess:
    """A user's modules, in their order, and the ones they keep out of sight."""

    allowed: list[str]
    hidden: frozenset[str]

    @property
    def visible(self) -> list[str]:
        return [key for key in self.allowed if key not in self.hidden]


def disabled_modules(db: Session) -> set[str]:
    rows = db.query(ModuleSetting.module).filter(ModuleSetting.enabled.is_(False))
    return {row.module for row in rows}


def role_profile(db: Session, role: str) -> list[str]:
    """The role's modules as stored, or its default profile."""
    row = db.get(RoleProfile, role)
    if row is None:
        return list(DEFAULT_PROFILES.get(role, []))
    return [key for key in row.modules if key in MODULES_BY_KEY]


def module_access(db: Session, user: User) -> ModuleAccess:
    disabled = disabled_modules(db)
    is_admin = user.role == ROLE_ADMIN

    allowed = [
        key
        for key in dict.fromkeys(role_profile(db, user.role))
        if key in MODULES_BY_KEY
        and key not in disabled
        and (is_admin or not MODULES_BY_KEY[key].admin_only)
    ]
    # Whatever the profiles say, an administrator can always reach the screen
    # that edits them: otherwise one wrong click locks everybody out.
    if is_admin and ADMIN_MODULE not in allowed:
        allowed.append(ADMIN_MODULE)

    preference = db.get(UserPreference, user.id)
    if preference is None:
        return ModuleAccess(allowed=allowed, hidden=frozenset())

    rank = {key: index for index, key in enumerate(preference.module_order or [])}
    # Modules missing from the user's order (new ones) keep their profile rank,
    # after the ones the user placed.
    ordered = sorted(
        allowed, key=lambda key: (rank.get(key, len(rank)), allowed.index(key))
    )
    hidden = frozenset(preference.hidden_modules or []) & set(allowed)
    return ModuleAccess(allowed=ordered, hidden=hidden)


def current_user(
    token_data: dict = Depends(decode_token), db: Session = Depends(get_db)
) -> User:
    """The signed-in user as the database knows them now (see require_admin)."""
    try:
        user_id = int(token_data["sub"])
    except (KeyError, TypeError, ValueError):
        user_id = None
    user = db.get(User, user_id) if user_id is not None else None
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Not enough permissions"
        )
    return user


def require_module(key: str):
    """Dependency admitting only a user whose modules include ``key``."""
    if key not in MODULES_BY_KEY:
        raise ValueError(f"Unknown module: {key}")

    def dependency(
        user: User = Depends(current_user), db: Session = Depends(get_db)
    ) -> User:
        if key not in module_access(db, user).allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"The '{key}' module is not available to you",
            )
        return user

    dependency.__name__ = f"require_module_{key}"
    return dependency


def require_risk_decision(user: User = Depends(current_user)) -> User:
    """Admit a user allowed to change what a finding's risk is.

    A remediator fixes what the backlog asks for; accepting a risk, dismissing a
    finding or lowering an asset's criticality are decisions about the backlog
    itself, and belong to analysts.
    """
    if user.role == ROLE_REMEDIATOR:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Risk decisions are reserved to analysts and administrators",
        )
    return user
