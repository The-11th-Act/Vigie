"""Microsoft Security Response Center (MSRC) CVRF documents: which KB replaces which.

MSRC publishes one CVRF document per month (``2024-Jan``), listed by an index
(``updates``). Each remediation of a CVE names the KB that fixes it on some
products and, in ``Supercedence`` (Microsoft's spelling), the KB it replaces:
January's cumulative update for Windows Server 2019 supersedes December's.
That edge is all Vigie keeps. Products, CVSS and the rest of the document are
read elsewhere or not at all.

Strict about structure, lenient about entries, like the KEV and EPSS parsers:
a document that is not CVRF raises ``ThreatFeedError``, a remediation without
a KB is skipped. Nothing here touches the database.
"""

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.parsers.threat_feeds import DEFAULT_MAX_FEED_BYTES, ThreatFeedError, decompress
from app.parsers.utils import kb_reference

# "2024-Jan", and the odd out-of-band "2017-May-B". Checked before an
# identifier from the index is put into a URL.
DOCUMENT_ID = re.compile(r"^\d{4}-[A-Za-z]{3}(?:-[A-Za-z0-9]{1,8})?$")
KB_NUMBERS = re.compile(r"\d{6,8}")


@dataclass(frozen=True)
class MsrcDocumentRef:
    """One entry of the index: a monthly document and when it last changed."""

    id: str
    initial_release: datetime | None
    current_release: datetime | None


@dataclass(frozen=True)
class MsrcDocument:
    id: str
    initial_release: datetime | None
    current_release: datetime | None
    # (KB, the KB it supersedes), both spelled "KB5034127".
    supersedences: frozenset[tuple[str, str]] = field(default_factory=frozenset)


def parse_msrc_index(
    raw: bytes, max_bytes: int = DEFAULT_MAX_FEED_BYTES
) -> list[MsrcDocumentRef]:
    """Parse the ``updates`` index; entries with an unusable ID are skipped."""
    document = _load_json(raw, max_bytes, "MSRC index")
    entries = document.get("value") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        raise ThreatFeedError("MSRC index lacks its list of documents")

    refs = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        doc_id = str(entry.get("ID") or "").strip()
        if not DOCUMENT_ID.match(doc_id):
            continue
        refs.append(
            MsrcDocumentRef(
                id=doc_id,
                initial_release=_parse_moment(entry.get("InitialReleaseDate")),
                current_release=_parse_moment(entry.get("CurrentReleaseDate")),
            )
        )
    if not refs:
        # MSRC has listed documents since 2016; an empty index is a broken one.
        raise ThreatFeedError("MSRC index lists no documents")
    return refs


def parse_msrc_document(
    raw: bytes, max_bytes: int = DEFAULT_MAX_FEED_BYTES
) -> MsrcDocument:
    """Parse one monthly CVRF document (the JSON form) into its supersedences."""
    document = _load_json(raw, max_bytes, "MSRC document")
    if not isinstance(document, dict):
        raise ThreatFeedError("MSRC document is not a JSON object")
    tracking = document.get("DocumentTracking")
    vulnerabilities = document.get("Vulnerability")
    if not isinstance(tracking, dict) or not isinstance(vulnerabilities, list):
        # The XML form, or something else entirely.
        raise ThreatFeedError(
            "MSRC document lacks DocumentTracking or Vulnerability: "
            "download the CVRF document as JSON"
        )
    doc_id = str(_value(_value(tracking.get("Identification"), "ID")) or "").strip()
    if not DOCUMENT_ID.match(doc_id):
        raise ThreatFeedError(f"MSRC document has no usable ID ({doc_id!r})")

    edges: set[tuple[str, str]] = set()
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            continue
        for item in vulnerability.get("Remediations") or []:
            if not isinstance(item, dict):
                continue
            kb = kb_reference(str(_value(item.get("Description")) or ""))
            superseded = str(item.get("Supercedence") or item.get("Supersedence") or "")
            if not kb or not superseded:
                continue
            # Usually one KB; occasionally a list, whatever the separator.
            for number in KB_NUMBERS.findall(superseded):
                old = f"KB{number}"
                if old != kb:
                    edges.add((kb, old))

    return MsrcDocument(
        id=doc_id,
        initial_release=_parse_moment(tracking.get("InitialReleaseDate")),
        current_release=_parse_moment(tracking.get("CurrentReleaseDate")),
        supersedences=frozenset(edges),
    )


def _load_json(raw: bytes, max_bytes: int, what: str):
    data = decompress(raw, max_bytes)
    if data.lstrip()[:1] == b"<":
        # What the API answers when the request does not ask for JSON.
        raise ThreatFeedError(
            f"{what} is XML: download the JSON form (Accept: application/json)"
        )
    try:
        return json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ThreatFeedError(f"{what} is not valid JSON: {exc}") from exc


def _value(node, key: str = "Value"):
    """CVRF wraps most scalars: ``{"ID": {"Value": "2024-Jan"}}``."""
    return node.get(key) if isinstance(node, dict) else None


def _parse_moment(value) -> datetime | None:
    """MSRC dates, with or without a zone; UTC when none is given."""
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
