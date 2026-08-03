"""CrowdStrike Falcon Spotlight vulnerability client.

Spotlight is queried in the two steps the API requires: a paginated *query*
endpoint returns vulnerability ids, then an *entities* endpoint hydrates them in
batches. Findings are emitted in the same normalised shape as the Nessus and
OpenVAS parsers (see ``app.parsers.utils``) so the ingestion pipeline treats
every source identically.

The response mapping follows CrowdStrike's published schema. It has not been
exercised against a live tenant from here, so if a sync comes back empty the
field names are the first thing to re-check against your own region's API.
"""
import logging
import time
from typing import Any, Dict, Iterator, List, Optional

import requests

from app.parsers.utils import clean_text, is_valid_cve, normalize_severity, safe_float

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.crowdstrike.com"

# Spotlight accepts up to 400 ids per entities call; 100 keeps URLs and memory
# modest while still cutting the round-trip count by two orders of magnitude.
ENTITY_BATCH_SIZE = 100
QUERY_PAGE_SIZE = 400

MAX_ATTEMPTS = 5
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_MAX_SECONDS = 30.0
REQUEST_TIMEOUT = 30

# Refresh slightly before the token actually lapses, so a long sync does not
# fail midway on an expiry it could have anticipated.
TOKEN_EXPIRY_MARGIN_SECONDS = 60

# Only findings still open are worth ingesting; what happens afterwards is
# governed by the platform's own triage lifecycle.
DEFAULT_FILTER = "status:'open'"

# Hard stop, so a malformed cursor cannot send us round forever.
MAX_PAGES = 1000


class CrowdStrikeError(RuntimeError):
    """Raised when the Spotlight API remains unusable after retries."""


class CrowdstrikeClient:
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        base_url: Optional[str] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not client_id or not client_secret:
            raise CrowdStrikeError("CrowdStrike client id and secret are required")

        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self._session = session or requests.Session()
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    # ------------------------------------------------------------------ auth

    def _authenticate(self) -> str:
        response = self._session.post(
            f"{self.base_url}/oauth2/token",
            data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=REQUEST_TIMEOUT,
        )
        if response.status_code != 200:
            raise CrowdStrikeError(
                f"CrowdStrike authentication failed with HTTP {response.status_code}"
            )

        body = response.json() or {}
        token = body.get("access_token")
        if not token:
            raise CrowdStrikeError("CrowdStrike authentication returned no token")

        expires_in = int(body.get("expires_in") or 1800)
        self._token = token
        self._token_expires_at = (
            time.monotonic() + expires_in - TOKEN_EXPIRY_MARGIN_SECONDS
        )
        logger.info("Authenticated against CrowdStrike (token valid %ss)", expires_in)
        return token

    def _valid_token(self) -> str:
        """Reuse the cached token until it is close to expiring."""
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token
        return self._authenticate()

    # --------------------------------------------------------------- request

    def _request(self, path: str, params: Any = None) -> Dict[str, Any]:
        """GET with the retry policy the Falcon API expects.

        429 is honoured via ``Retry-After`` (Falcon also sends the epoch-based
        ``X-RateLimit-RetryAfter``); 5xx is retried with exponential backoff; a
        401 mid-sync triggers exactly one re-authentication, since a token can
        lapse between two calls.
        """
        url = f"{self.base_url}{path}"
        reauthenticated = False

        for attempt in range(1, MAX_ATTEMPTS + 1):
            token = self._valid_token()
            response = self._session.get(
                url,
                params=params,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 200:
                return response.json() or {}

            if response.status_code == 401 and not reauthenticated:
                logger.info("CrowdStrike token rejected; re-authenticating")
                reauthenticated = True
                self._token = None
                continue

            if response.status_code == 429:
                delay = _retry_after_seconds(response, attempt)
                logger.warning(
                    "CrowdStrike rate limit on %s; waiting %.1fs (attempt %d/%d)",
                    path,
                    delay,
                    attempt,
                    MAX_ATTEMPTS,
                )
                time.sleep(delay)
                continue

            if response.status_code >= 500:
                delay = _backoff_seconds(attempt)
                logger.warning(
                    "CrowdStrike returned HTTP %d on %s; retrying in %.1fs "
                    "(attempt %d/%d)",
                    response.status_code,
                    path,
                    delay,
                    attempt,
                    MAX_ATTEMPTS,
                )
                time.sleep(delay)
                continue

            # Any other 4xx is a request there is no point repeating.
            raise CrowdStrikeError(
                f"CrowdStrike request to {path} failed with HTTP "
                f"{response.status_code}"
            )

        raise CrowdStrikeError(
            f"CrowdStrike request to {path} still failing after {MAX_ATTEMPTS} attempts"
        )

    # ----------------------------------------------------------------- fetch

    def _iter_id_pages(self, filter_expr: str) -> Iterator[List[str]]:
        after: Optional[str] = None

        for _ in range(MAX_PAGES):
            params: Dict[str, Any] = {"filter": filter_expr, "limit": QUERY_PAGE_SIZE}
            if after:
                params["after"] = after

            body = self._request("/spotlight/queries/vulnerabilities/v1", params)
            ids = body.get("resources") or []
            if not ids:
                return

            yield ids

            after = (body.get("meta") or {}).get("pagination", {}).get("after")
            if not after:
                return

        logger.warning("CrowdStrike pagination stopped at the %d page cap", MAX_PAGES)

    def _fetch_entities(self, ids: List[str]) -> List[Dict[str, Any]]:
        entities: List[Dict[str, Any]] = []
        for start in range(0, len(ids), ENTITY_BATCH_SIZE):
            batch = ids[start : start + ENTITY_BATCH_SIZE]
            body = self._request(
                "/spotlight/entities/vulnerabilities/v2",
                [("ids", identifier) for identifier in batch],
            )
            entities.extend(body.get("resources") or [])
        return entities

    def fetch_vulnerabilities(
        self, filter_expr: str = DEFAULT_FILTER
    ) -> List[Dict[str, Any]]:
        """Return open Spotlight findings in the platform's normalised shape."""
        findings: List[Dict[str, Any]] = []
        skipped = 0

        for id_page in self._iter_id_pages(filter_expr):
            for entity in self._fetch_entities(id_page):
                finding = _normalize(entity)
                if finding is None:
                    skipped += 1
                    continue
                findings.append(finding)

        logger.info(
            "CrowdStrike sync produced %d findings (%d entries skipped as unusable)",
            len(findings),
            skipped,
        )
        return findings


def _normalize(entity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map a Spotlight entity onto the shared finding shape.

    Entries without a well-formed CVE or without an IP are dropped: the first
    cannot be deduplicated against the other sources, the second cannot be tied
    to an asset. Both would fail the insert further down anyway.
    """
    cve = entity.get("cve") or {}
    host = entity.get("host_info") or {}

    cve_id = (cve.get("id") or "").strip().upper()
    if not is_valid_cve(cve_id):
        return None

    ip_address = clean_text(host.get("local_ip"))
    if not ip_address:
        return None

    cvss_score = safe_float(cve.get("base_score"))
    description = clean_text(cve.get("description"))

    return {
        "ip_address": ip_address,
        "hostname": clean_text(host.get("hostname")),
        "operating_system": clean_text(host.get("os_version")),
        "cve_id": cve_id,
        # Spotlight carries no title field; the CVE id plus the opening of the
        # description is the most useful label available.
        "title": _title_for(cve_id, description),
        "description": description,
        "cvss_score": cvss_score,
        # Spotlight severities arrive upper-case ("HIGH"); normalize_severity
        # folds them into the enum and falls back to the CVSS band when absent.
        "severity": normalize_severity(cve.get("severity"), cvss_score),
    }


def _title_for(cve_id: str, description: Optional[str]) -> str:
    if not description:
        return cve_id
    first_sentence = description.split(". ")[0].strip()
    return f"{cve_id}: {first_sentence[:400]}"


def _retry_after_seconds(response: requests.Response, attempt: int) -> float:
    """Honour the server's own pacing whenever it states one."""
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return min(BACKOFF_MAX_SECONDS, max(0.0, float(retry_after)))
        except ValueError:
            pass

    # Falcon's own variant carries an absolute epoch rather than a delay.
    epoch = response.headers.get("X-RateLimit-RetryAfter")
    if epoch:
        try:
            return min(BACKOFF_MAX_SECONDS, max(0.0, float(epoch) - time.time()))
        except ValueError:
            pass

    return _backoff_seconds(attempt)


def _backoff_seconds(attempt: int) -> float:
    return min(BACKOFF_MAX_SECONDS, BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)))


def fetch_vulnerabilities_from_settings() -> List[Dict[str, Any]]:
    """Build a client from application settings and pull open findings."""
    from app.core.config import settings

    client = CrowdstrikeClient(
        client_id=settings.CROWDSTRIKE_CLIENT_ID or "",
        client_secret=settings.CROWDSTRIKE_CLIENT_SECRET or "",
        base_url=settings.CROWDSTRIKE_BASE_URL,
    )
    return client.fetch_vulnerabilities()
