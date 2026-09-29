"""Administration of modules: instance switches and role profiles."""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.modules import (
    ADMIN_MODULE,
    DEFAULT_PROFILES,
    MODULES,
    MODULES_BY_KEY,
    ROLE_ADMIN,
    ROLES,
    disabled_modules,
    role_profile,
)
from app.core.security import require_admin
from app.db.database import get_db
from app.models.preferences import ModuleSetting, RoleProfile
from app.schemas.modules import (
    AdminModule,
    AdminModulesResponse,
    ModuleToggle,
    RoleProfileUpdate,
)

logger = logging.getLogger(__name__)

router = APIRouter()


def _overview(db: Session) -> AdminModulesResponse:
    disabled = disabled_modules(db)
    customized = {row.role for row in db.query(RoleProfile.role)}
    return AdminModulesResponse(
        modules=[
            AdminModule(
                key=module.key,
                label=module.label,
                enabled=module.key not in disabled,
                admin_only=module.admin_only,
            )
            for module in MODULES
        ],
        profiles={role: role_profile(db, role) for role in ROLES},
        defaults={role: list(DEFAULT_PROFILES[role]) for role in ROLES},
        customized=sorted(customized & set(ROLES)),
    )


def _known_role(role: str) -> str:
    if role not in ROLES:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown role")
    return role


@router.get("/modules", response_model=AdminModulesResponse)
def get_modules(db: Session = Depends(get_db), admin: dict = Depends(require_admin)):
    return _overview(db)


@router.patch("/modules/{key}", response_model=AdminModulesResponse)
def toggle_module(
    key: str,
    toggle: ModuleToggle,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Switch a module on or off for everybody, whatever their role grants."""
    module = MODULES_BY_KEY.get(key)
    if module is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown module"
        )
    if module.admin_only and not toggle.enabled:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The administration module cannot be switched off",
        )

    setting = db.get(ModuleSetting, key)
    if setting is None:
        setting = ModuleSetting(module=key)
        db.add(setting)
    setting.enabled = toggle.enabled
    db.commit()
    logger.info(
        "Module '%s' %s by %s",
        key,
        "enabled" if toggle.enabled else "disabled",
        admin.get("username"),
    )
    return _overview(db)


@router.put("/roles/{role}/modules", response_model=AdminModulesResponse)
def set_role_profile(
    role: str,
    profile_in: RoleProfileUpdate,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Grant a role its modules, in the order its users see them by default."""
    _known_role(role)
    admin_only = [key for key in profile_in.modules if MODULES_BY_KEY[key].admin_only]
    if admin_only and role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Reserved to administrators: {', '.join(admin_only)}",
        )
    modules = list(profile_in.modules)
    if role == ROLE_ADMIN and ADMIN_MODULE not in modules:
        # Granted to administrators anyway (see module_access); stored so the
        # profile says what they actually get.
        modules.append(ADMIN_MODULE)

    profile = db.get(RoleProfile, role)
    if profile is None:
        profile = RoleProfile(role=role, modules=modules)
        db.add(profile)
    else:
        profile.modules = modules
    db.commit()
    logger.info(
        "Profile of role '%s' set to %s by %s", role, modules, admin.get("username")
    )
    return _overview(db)


@router.delete("/roles/{role}/modules", response_model=AdminModulesResponse)
def reset_role_profile(
    role: str,
    db: Session = Depends(get_db),
    admin: dict = Depends(require_admin),
):
    """Return a role to its default profile."""
    _known_role(role)
    profile = db.get(RoleProfile, role)
    if profile is not None:
        db.delete(profile)
        db.commit()
        logger.info("Profile of role '%s' reset by %s", role, admin.get("username"))
    return _overview(db)
