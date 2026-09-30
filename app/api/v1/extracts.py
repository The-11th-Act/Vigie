"""Extracts: datasets as CSV or JSON, personal API tokens, saved extracts."""

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.api_tokens import MAX_TOKENS_PER_USER, new_token
from app.core.modules import current_user, module_access
from app.core.scope import scope_of
from app.db.database import get_db
from app.models.extract import ApiToken, SavedExtract
from app.models.user import User
from app.schemas.extracts import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenResponse,
    SavedExtractCreate,
    SavedExtractResponse,
)
from app.services import extracts

logger = logging.getLogger(__name__)

router = APIRouter()

# Query parameters of an extract that are not dataset filters.
RESERVED = {"format", "columns", "limit"}
MEDIA_TYPES = {"csv": "text/csv; charset=utf-8", "json": "application/json"}


def _dataset_for(db: Session, user: User, key: str) -> extracts.Dataset:
    """The dataset, if it exists and the user has the module behind it."""
    dataset = extracts.DATASETS.get(key)
    if dataset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown dataset"
        )
    if dataset.module not in module_access(db, user).allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"The '{dataset.module}' module is not available to you",
        )
    return dataset


def _invalid(exc: ValueError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
    )


def _stream(db, user, dataset, columns, filters, fmt, limit=None) -> StreamingResponse:
    # The rows of the user's scope, a personal token's pull included: the
    # token acts as its owner.
    chunks = extracts.run(db, dataset, columns, filters, fmt, scope_of(db, user), limit)
    return StreamingResponse(
        chunks,
        media_type=MEDIA_TYPES[fmt],
        headers={
            "Content-Disposition": (
                f'attachment; filename="{extracts.filename(dataset, fmt)}"'
            )
        },
    )


@router.get("/datasets")
def list_datasets(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """What this user can extract: datasets of the modules they have."""
    allowed = set(module_access(db, user).allowed)
    return [
        extracts.describe(dataset)
        for dataset in extracts.DATASETS.values()
        if dataset.module in allowed
    ]


# --- personal API tokens ------------------------------------------------------


@router.get("/tokens", response_model=list[ApiTokenResponse])
def list_tokens(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return (
        db.query(ApiToken)
        .filter(ApiToken.user_id == user.id)
        .order_by(ApiToken.created_at.desc(), ApiToken.id.desc())
        .all()
    )


@router.post(
    "/tokens", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED
)
def create_token(
    token_in: ApiTokenCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """A read-only token for scripts; its secret is in this response only."""
    now = datetime.now(UTC)
    active = [
        token
        for token in db.query(ApiToken).filter(
            ApiToken.user_id == user.id, ApiToken.revoked_at.is_(None)
        )
        if (
            token.expires_at
            if token.expires_at.tzinfo
            else token.expires_at.replace(tzinfo=UTC)
        )
        > now
    ]
    if len(active) >= MAX_TOKENS_PER_USER:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"At most {MAX_TOKENS_PER_USER} active tokens: revoke one first",
        )
    token, secret = new_token(
        db, user, token_in.name, timedelta(days=token_in.expires_in_days)
    )
    db.commit()
    db.refresh(token)
    logger.info("API token %s (%s) created by %s", token.id, token.prefix, user.username)
    return {**ApiTokenResponse.model_validate(token).model_dump(), "token": secret}


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    """Revoke one of your tokens; it stops working at once."""
    token = db.get(ApiToken, token_id)
    # Someone else's token is reported missing, not forbidden: no probing.
    if token is None or token.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown token")
    if token.revoked_at is None:
        token.revoked_at = datetime.now(UTC)
        db.commit()
        logger.info("API token %s revoked by %s", token.id, user.username)


# --- saved extracts -----------------------------------------------------------


@router.get("/saved", response_model=list[SavedExtractResponse])
def list_saved(user: User = Depends(current_user), db: Session = Depends(get_db)):
    return (
        db.query(SavedExtract)
        .filter(SavedExtract.user_id == user.id)
        .order_by(SavedExtract.name, SavedExtract.id)
        .all()
    )


@router.post(
    "/saved", response_model=SavedExtractResponse, status_code=status.HTTP_201_CREATED
)
def save_extract(
    extract_in: SavedExtractCreate,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Name an extract, to pull it again by a stable URL."""
    dataset = _dataset_for(db, user, extract_in.dataset)
    try:
        columns = extracts.parse_columns(dataset, extract_in.columns)
        extracts.parse_filters(dataset, extract_in.filters)
    except ValueError as exc:
        raise _invalid(exc) from None
    saved = SavedExtract(
        user_id=user.id,
        name=extract_in.name.strip(),
        dataset=dataset.key,
        columns=columns,
        # Stored as given (strings, booleans): parsed again at every run.
        filters={k: v for k, v in extract_in.filters.items() if v not in (None, "")},
        format=extract_in.format,
    )
    db.add(saved)
    db.commit()
    db.refresh(saved)
    return saved


def _own_saved(db: Session, user: User, saved_id: int) -> SavedExtract:
    saved = db.get(SavedExtract, saved_id)
    if saved is None or saved.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Unknown extract"
        )
    return saved


@router.delete("/saved/{saved_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_saved(
    saved_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)
):
    db.delete(_own_saved(db, user, saved_id))
    db.commit()


@router.get("/saved/{saved_id}/run", response_class=StreamingResponse)
def run_saved(
    saved_id: int,
    fmt: str | None = Query(None, alias="format"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """Pull a saved extract: the URL to give a reporting tool."""
    saved = _own_saved(db, user, saved_id)
    # Checked at every run: a module taken away since the extract was saved
    # takes its data away too.
    dataset = _dataset_for(db, user, saved.dataset)
    fmt = fmt or saved.format
    if fmt not in extracts.FORMATS:
        raise _invalid(ValueError("format must be csv or json"))
    try:
        columns = extracts.parse_columns(dataset, saved.columns)
        filters = extracts.parse_filters(dataset, saved.filters)
    except ValueError as exc:
        raise _invalid(exc) from None
    return _stream(db, user, dataset, columns, filters, fmt)


# --- one-off extract (declared last: its path would match the ones above) -----


@router.get("/{dataset_key}", response_class=StreamingResponse)
def extract(
    dataset_key: str,
    request: Request,
    fmt: str = Query("csv", alias="format"),
    columns: str | None = Query(None, max_length=2000),
    limit: int | None = Query(None, ge=1, le=extracts.MAX_ROWS),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    """A dataset as CSV or JSON. Every other query parameter is a filter of the
    dataset (see /extracts/datasets); ``limit`` makes a preview."""
    dataset = _dataset_for(db, user, dataset_key)
    if fmt not in extracts.FORMATS:
        raise _invalid(ValueError("format must be csv or json"))
    raw_filters = {
        key: value for key, value in request.query_params.items() if key not in RESERVED
    }
    try:
        chosen = extracts.parse_columns(dataset, columns)
        filters = extracts.parse_filters(dataset, raw_filters)
    except ValueError as exc:
        raise _invalid(exc) from None
    return _stream(db, user, dataset, chosen, filters, fmt, limit)
