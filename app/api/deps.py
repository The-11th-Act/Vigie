"""Shared API dependencies and helpers.

These live in the API layer rather than in ``app.db`` so the persistence layer
stays free of HTTP concerns.
"""

from collections.abc import Callable
from typing import TypeVar

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import Base

ModelT = TypeVar("ModelT", bound=Base)


def get_or_404(db: Session, model: type[ModelT], obj_id: int) -> ModelT:
    """Fetch a row by primary key or raise a 404."""
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{model.__name__} not found",
        )
    return obj


def get_in_scope_or_404(
    db: Session,
    model: type[ModelT],
    obj_id: int,
    scope,
    team_of: Callable[[ModelT], str | None],
) -> ModelT:
    """Fetch a row the caller's scope covers, or the same 404 as a missing one.

    A 403 would confirm that the id exists in another team's estate.
    """
    obj = get_or_404(db, model, obj_id)
    if not scope.allows(team_of(obj)):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{model.__name__} not found",
        )
    return obj
