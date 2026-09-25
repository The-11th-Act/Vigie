"""CISA KEV and FIRST EPSS feeds: download and parsing.

Both feeds are public, keyless, and small enough to fetch whole once a day:

- KEV, the catalogue of vulnerabilities CISA has seen exploited in the wild,
  is one JSON document.
- EPSS publishes a daily CSV (gzipped) of the probability that each CVE is
  exploited in the next 30 days. The bulk file is used rather than the per-CVE
  API: one request instead of hundreds, a consistent snapshot, and the very
  same file an administrator downloads for an offline import.

Parsing is strict about structure and lenient about individual rows: a feed
that is not what we expect raises ``ThreatFeedError`` and nothing is applied,
while a single malformed entry is dropped. Nothing here touches the database.
"""

import csv
import io
import json
import logging
import time
import zlib
from dataclasses import dataclass, field
from datetime import date

import requests

from app.core.http_retry import backoff_seconds, retry_after_seconds
from app.parsers.utils import is_valid_cve

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_MAX_FEED_BYTES = 64 * 1024 * 1024
MAX_ATTEMPTS = 4
CHUNK_BYTES = 64 * 1024

GZIP_MAGIC = b"\x1f\x8b"

# Above this share of unusable rows, the EPSS file is not a partial success but
# a sign something is wrong with it — truncated, or a format change.
MAX_INVALID_EPSS_RATIO = 0.01


class ThreatFeedError(RuntimeError):
    """A feed could not be fetched or is not in the expected shape."""


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: date | None = None
    due_date: date | None = None
    ransomware: bool = False


@dataclass(frozen=True)
class KevCatalog:
    version: str
    released: date | None
    entries: dict[str, KevEntry] = field(default_factory=dict)


@dataclass(frozen=True)
class EpssScore:
    score: float
    percentile: float | None = None


@dataclass(frozen=True)
class EpssSnapshot:
    model_version: str | None
    score_date: date | None
    scores: dict[str, EpssScore] = field(default_factory=dict)
    # Rows in the file, before filtering on the CVEs we track.
    total_rows: int = 0


class ThreatFeedClient:
    """Downloads a feed with retries and a hard size limit.

    The session is injectable so tests replay responses instead of reaching the
    network. Proxies and custom CAs come from the standard ``HTTPS_PROXY`` /
    ``REQUESTS_CA_BUNDLE`` variables, which ``requests`` already honours.
    """

    def __init__(
        self,
        session: requests.Session | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = DEFAULT_MAX_FEED_BYTES,
    ) -> None:
        self._session = session or requests.Session()
        self.timeout = timeout
        self.max_bytes = max_bytes

    def get(self, url: str) -> bytes:
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = self._session.get(url, timeout=self.timeout, stream=True)
            except requests.RequestException as exc:
                if attempt == MAX_ATTEMPTS:
                    raise ThreatFeedError(f"Could not reach {url}: {exc}") from exc
                delay = backoff_seconds(attempt)
                logger.warning(
                    "Feed %s unreachable (%s); retrying in %.1fs", url, exc, delay
                )
                time.sleep(delay)
                continue

            try:
                if response.status_code == 200:
                    return self._read_capped(response, url)
                if response.status_code == 429 or response.status_code >= 500:
                    if attempt == MAX_ATTEMPTS:
                        break
                    delay = (
                        retry_after_seconds(response, attempt)
                        if response.status_code == 429
                        else backoff_seconds(attempt)
                    )
                    logger.warning(
                        "Feed %s returned HTTP %d; retrying in %.1fs",
                        url,
                        response.status_code,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                raise ThreatFeedError(f"Feed {url} returned HTTP {response.status_code}")
            finally:
                response.close()

        raise ThreatFeedError(f"Feed {url} still failing after {MAX_ATTEMPTS} attempts")

    def _read_capped(self, response, url: str) -> bytes:
        buffer = bytearray()
        for chunk in response.iter_content(chunk_size=CHUNK_BYTES):
            buffer.extend(chunk)
            if len(buffer) > self.max_bytes:
                raise ThreatFeedError(f"Feed {url} exceeds {self.max_bytes} bytes")
        return bytes(buffer)


def decompress(raw: bytes, max_bytes: int = DEFAULT_MAX_FEED_BYTES) -> bytes:
    """Gunzip ``raw`` if it is gzip, refusing to inflate past ``max_bytes``.

    Detected by content rather than by name, so the same code reads the
    published ``.csv.gz`` and a plain CSV an administrator saved by hand. The
    limit applies after decompression: a few kilobytes can inflate to gigabytes.
    """
    if not raw.startswith(GZIP_MAGIC):
        return raw
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = inflater.decompress(raw, max_bytes + 1)
    except zlib.error as exc:
        raise ThreatFeedError(f"Corrupt gzip data: {exc}") from exc
    if len(data) > max_bytes or inflater.unconsumed_tail:
        raise ThreatFeedError(f"Feed inflates past {max_bytes} bytes")
    return data


def parse_kev(raw: bytes, max_bytes: int = DEFAULT_MAX_FEED_BYTES) -> KevCatalog:
    """Parse the CISA KEV JSON catalogue."""
    try:
        document = json.loads(decompress(raw, max_bytes))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ThreatFeedError(f"KEV catalogue is not valid JSON: {exc}") from exc

    if not isinstance(document, dict):
        raise ThreatFeedError("KEV catalogue is not a JSON object")
    version = document.get("catalogVersion")
    vulnerabilities = document.get("vulnerabilities")
    if not version or not isinstance(vulnerabilities, list):
        raise ThreatFeedError("KEV catalogue lacks catalogVersion or vulnerabilities")
    if not vulnerabilities:
        # CISA has never published an empty catalogue; applying one would
        # clear every KEV flag in the database.
        raise ThreatFeedError("KEV catalogue is empty")

    entries: dict[str, KevEntry] = {}
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID") or "").strip().upper()
        if not is_valid_cve(cve_id):
            continue
        ransomware = str(item.get("knownRansomwareCampaignUse") or "").strip()
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            date_added=_parse_date(item.get("dateAdded")),
            due_date=_parse_date(item.get("dueDate")),
            ransomware=ransomware.lower() == "known",
        )

    return KevCatalog(
        version=str(version),
        released=_parse_date(document.get("dateReleased")),
        entries=entries,
    )


def parse_epss(
    raw: bytes,
    wanted: set[str] | None = None,
    max_bytes: int = DEFAULT_MAX_FEED_BYTES,
) -> EpssSnapshot:
    """Parse the EPSS daily CSV, keeping only the CVEs in ``wanted``.

    The file lists every published CVE (a quarter of a million rows); only the
    ones present in our database are worth holding in memory.
    """
    try:
        text = decompress(raw, max_bytes).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ThreatFeedError(f"EPSS file is not UTF-8 text: {exc}") from exc

    lines = text.splitlines()
    metadata: dict[str, str] = {}
    if lines and lines[0].startswith("#"):
        metadata = _parse_epss_metadata(lines.pop(0))

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or not {"cve", "epss"} <= set(reader.fieldnames):
        raise ThreatFeedError("EPSS file lacks the cve,epss header")

    scores: dict[str, EpssScore] = {}
    total = invalid = 0
    for row in reader:
        total += 1
        cve_id = (row.get("cve") or "").strip().upper()
        try:
            score = float(row.get("epss") or "")
            percentile = float(row["percentile"]) if row.get("percentile") else None
        except ValueError:
            invalid += 1
            continue
        if not is_valid_cve(cve_id) or not 0.0 <= score <= 1.0:
            invalid += 1
            continue
        if wanted is not None and cve_id not in wanted:
            continue
        scores[cve_id] = EpssScore(score=score, percentile=percentile)

    if total == 0:
        raise ThreatFeedError("EPSS file has no rows")
    if invalid / total > MAX_INVALID_EPSS_RATIO:
        raise ThreatFeedError(f"EPSS file has {invalid} unusable rows out of {total}")

    return EpssSnapshot(
        model_version=metadata.get("model_version"),
        score_date=_parse_date(metadata.get("score_date")),
        scores=scores,
        total_rows=total,
    )


def _parse_epss_metadata(line: str) -> dict[str, str]:
    """``#model_version:v2025.03.14,score_date:2026-09-25T00:00:00+0000``"""
    metadata = {}
    for part in line.lstrip("#").split(","):
        key, _, value = part.partition(":")
        if key.strip():
            metadata[key.strip()] = value.strip()
    return metadata


def _parse_date(value) -> date | None:
    """First ten characters as an ISO date; None when absent or malformed."""
    if not value:
        return None
    try:
        return date.fromisoformat(str(value).strip()[:10])
    except ValueError:
        return None
