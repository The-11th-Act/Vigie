"""KB supersedence: deploy the update that replaces the one a scanner named.

A Windows cumulative update contains every earlier one: January's replaces
December's. A scanner whose check names a fixed KB (an OpenVAS NVT, a Spotlight
remediation, a Nessus cross-reference) keeps asking for December's long after
January's is out, and the remediation plan then shows two lines for one
deployment. MSRC says which KB supersedes which (``app/parsers/msrc.py``);
here, each remediation link to a superseded KB is pointed at the latest KB
replacing it, and keeps the scanner's KB in ``reported_reference``.

Only an unambiguous replacement is applied. When a KB is superseded along
several chains that never meet again (a hotpatch replaced by two different
updates), nothing says which one this host needs: the scanner's KB stays.
"""

import logging
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import replace

from sqlalchemy import delete, insert
from sqlalchemy.orm import Session

from app.models.remediation import FindingRemediation, RemediationAction, RemediationKind
from app.models.threat_intel import KbSupersedence, MsrcDocument
from app.parsers.msrc import MsrcDocument as ParsedMsrcDocument
from app.parsers.utils import ParsedRemediation

logger = logging.getLogger(__name__)

CHUNK_SIZE = 500
CATALOG_URL = "https://catalog.update.microsoft.com/v7/site/Search.aspx?q={kb}"


def latest_kbs(edges: Iterable[tuple[str, str]]) -> dict[str, str]:
    """Each superseded KB, mapped to the one KB that finally replaces it.

    ``edges`` are (KB, the KB it supersedes). Every chain leaving a KB is
    followed to its end: one end, and that is the KB to deploy; several (a
    fork that never joins again) or none (a cycle, which would be bad data),
    and the KB is left out.
    """
    successors: dict[str, set[str]] = defaultdict(set)
    for kb, superseded in edges:
        successors[superseded].add(kb)

    latest: dict[str, str] = {}
    for kb in successors:
        ends: set[str] = set()
        seen = {kb}
        stack = [kb]
        while stack:
            node = stack.pop()
            following = successors.get(node)
            if not following:
                ends.add(node)
                continue
            for nxt in following - seen:
                seen.add(nxt)
                stack.append(nxt)
        if len(ends) == 1:
            (end,) = ends
            if end != kb:
                latest[kb] = end
    return latest


def supersedence_map(db: Session) -> dict[str, str]:
    """``latest_kbs`` over every stored MSRC document."""
    edges = db.query(KbSupersedence.kb, KbSupersedence.superseded_kb).distinct()
    return latest_kbs((row.kb, row.superseded_kb) for row in edges)


def catalog_url(kb: str) -> str:
    return CATALOG_URL.format(kb=kb)


def supersede(
    entry: ParsedRemediation, latest: dict[str, str]
) -> tuple[ParsedRemediation, str | None]:
    """The entry to record, and the KB it replaces (None when unchanged).

    The scanner's title and solution describe the KB it named, not the later
    one, so they are dropped; the family (what kind of software) still holds,
    and so do this host's versions.
    """
    if entry.kind != RemediationKind.kb.value:
        return entry, None
    later = latest.get(entry.reference)
    if later is None:
        return entry, None
    return (
        replace(
            entry, reference=later, title=None, solution=None, url=catalog_url(later)
        ),
        entry.reference,
    )


def store_documents(db: Session, documents: list[ParsedMsrcDocument], now) -> int:
    """Replace the supersedences of each document; returns how many changed.

    A document's edges replace that document's edges only. The caller has
    already refused what must not be applied; the caller commits.
    """
    changed = 0
    for document in documents:
        row = db.get(MsrcDocument, document.id)
        if row is None:
            row = MsrcDocument(id=document.id)
            db.add(row)
        row.initial_release = document.initial_release
        row.current_release = document.current_release
        row.supersedences = len(document.supersedences)
        row.applied_at = now
        db.flush()

        stored = {
            (edge.kb, edge.superseded_kb)
            for edge in db.query(KbSupersedence).filter(
                KbSupersedence.document_id == document.id
            )
        }
        if stored == set(document.supersedences):
            continue
        changed += 1
        db.execute(
            delete(KbSupersedence).where(KbSupersedence.document_id == document.id)
        )
        if document.supersedences:
            db.execute(
                insert(KbSupersedence),
                [
                    {"document_id": document.id, "kb": kb, "superseded_kb": superseded}
                    for kb, superseded in sorted(document.supersedences)
                ],
            )
    db.flush()
    return changed


def apply_supersedence(db: Session, latest: dict[str, str] | None = None) -> int:
    """Point the links to superseded KBs at the KBs replacing them.

    Covers what ingestion could not: links written before MSRC said the KB was
    superseded. A finding that already links to the later KB for the same
    source loses the redundant link. Returns the number of links moved or
    removed; the caller flushes and commits.
    """
    latest = supersedence_map(db) if latest is None else latest
    if not latest:
        return 0

    references = list(latest)
    superseded: list[RemediationAction] = []
    for i in range(0, len(references), CHUNK_SIZE):
        superseded.extend(
            db.query(RemediationAction).filter(
                RemediationAction.kind == RemediationKind.kb.value,
                RemediationAction.reference.in_(references[i : i + CHUNK_SIZE]),
            )
        )
    if not superseded:
        return 0
    old_by_id = {action.id: action for action in superseded}

    links: list[FindingRemediation] = []
    ids = list(old_by_id)
    for i in range(0, len(ids), CHUNK_SIZE):
        links.extend(
            db.query(FindingRemediation)
            .filter(FindingRemediation.action_id.in_(ids[i : i + CHUNK_SIZE]))
            .order_by(FindingRemediation.id)
        )
    if not links:
        return 0

    targets = later_actions(db, {latest[action.reference] for action in superseded})
    target_ids = [action.id for action in targets.values()]
    finding_ids = list({link.finding_id for link in links})
    taken: set[tuple[int, int, str]] = set()
    for i in range(0, len(finding_ids), CHUNK_SIZE):
        taken.update(
            (row.finding_id, row.action_id, row.source)
            for row in db.query(
                FindingRemediation.finding_id,
                FindingRemediation.action_id,
                FindingRemediation.source,
            ).filter(
                FindingRemediation.finding_id.in_(finding_ids[i : i + CHUNK_SIZE]),
                FindingRemediation.action_id.in_(target_ids),
            )
        )

    moved = 0
    for link in links:
        old = old_by_id[link.action_id]
        target = targets[latest[old.reference]]
        key = (link.finding_id, target.id, link.source)
        if key in taken:
            db.delete(link)
        else:
            # Through the relationship, so a loaded link does not keep showing
            # the old action until the session expires it.
            link.action = target
            # The scanner's KB, not an intermediate one from an earlier pass.
            link.reported_reference = link.reported_reference or old.reference
            taken.add(key)
        moved += 1
    db.flush()
    logger.info("KB supersedence: %d remediation link(s) moved to a later KB", moved)
    return moved


def later_actions(db: Session, references: set[str]) -> dict[str, RemediationAction]:
    """The action of each replacing KB, created when no scanner named it yet."""
    wanted = sorted(references)
    actions: dict[str, RemediationAction] = {}
    for i in range(0, len(wanted), CHUNK_SIZE):
        actions.update(
            (action.reference, action)
            for action in db.query(RemediationAction).filter(
                RemediationAction.reference.in_(wanted[i : i + CHUNK_SIZE])
            )
        )
    for reference in wanted:
        if reference not in actions:
            action = RemediationAction(
                reference=reference,
                kind=RemediationKind.kb.value,
                url=catalog_url(reference),
            )
            db.add(action)
            actions[reference] = action
    db.flush()
    return actions
