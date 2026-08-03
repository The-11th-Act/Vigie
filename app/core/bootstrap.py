"""First-admin bootstrap.

Runs on application startup so a fresh deployment always has at least one
admin account, without an HTTP endpoint that could be abused to self-elevate.
Configured via ``ADMIN_USERNAME`` / ``ADMIN_EMAIL`` / ``ADMIN_PASSWORD``; if
any of the three is missing, this is a no-op.
"""

import logging

from pydantic import ValidationError
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import get_password_hash
from app.models.user import User
from app.schemas.user import UserCreate

logger = logging.getLogger(__name__)


def bootstrap_admin_user(db: Session) -> None:
    if not (settings.ADMIN_USERNAME and settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD):
        logger.info(
            "Admin bootstrap skipped: ADMIN_USERNAME, ADMIN_EMAIL and "
            "ADMIN_PASSWORD must all be set."
        )
        return

    try:
        # Reuses the same validation self-registration enforces (email
        # format, password length/complexity) rather than duplicating it.
        credentials = UserCreate(
            email=settings.ADMIN_EMAIL,
            username=settings.ADMIN_USERNAME,
            password=settings.ADMIN_PASSWORD,
        )
    except ValidationError as exc:
        logger.error("Admin bootstrap skipped: invalid credentials: %s", exc)
        return

    existing = (
        db.query(User)
        .filter(
            or_(User.username == credentials.username, User.email == credentials.email)
        )
        .first()
    )

    if existing:
        if existing.role != "admin":
            existing.role = "admin"
            db.commit()
            logger.info("Promoted existing user '%s' to admin.", existing.username)
        else:
            logger.info("Admin bootstrap: '%s' is already an admin.", existing.username)
        return

    admin = User(
        email=credentials.email,
        username=credentials.username,
        hashed_password=get_password_hash(credentials.password),
        role="admin",
    )
    db.add(admin)
    db.commit()
    logger.info("Created admin user '%s'.", admin.username)
