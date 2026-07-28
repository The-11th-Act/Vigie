"""Shared API dependencies and helpers.

These live in the API layer rather than in ``app.db`` so the persistence layer
stays free of HTTP concerns.
"""
from typing import Type, TypeVar

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import Base

ModelT = TypeVar("ModelT", bound=Base)


def get_or_404(db: Session, model: Type[ModelT], obj_id: int) -> ModelT:
    """Fetch a row by primary key or raise a 404."""
    obj = db.get(model, obj_id)
    if obj is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{model.__name__} not found",
        )
    return obj
