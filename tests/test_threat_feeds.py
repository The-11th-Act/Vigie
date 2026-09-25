"""KEV and EPSS feeds: parsing and download.

Never touches the network: responses are replayed by a fake session, and any
real request fails the test outright. Fixtures are built inline — gzip included
— so no binary file lives in the repository.
"""

import gzip
import json
from datetime import date

import pytest
import requests

from app.parsers.threat_feeds import (
    ThreatFeedClient,
    ThreatFeedError,
    decompress,
    parse_epss,
    parse_kev,
)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("a test tried to reach the network")

    monkeypatch.setattr(requests.Session, "request", refuse)
    monkeypatch.setattr("app.parsers.threat_feeds.time.sleep", lambda _seconds: None)


def kev_document(*entries, version="2026.09.24"):
    return json.dumps(
        {
            "catalogVersion": version,
            "dateReleased": "2026-09-24T17:00:00.000Z",
            "vulnerabilities": list(entries),
        }
    ).encode()


def kev_entry(
    cve="CVE-2024-3400", added="2024-04-12", due="2024-04-19", ransomware="Unknown"
):
    return {
        "cveID": cve,
        "dateAdded": added,
        "dueDate": due,
        "knownRansomwareCampaignUse": ransomware,
    }


EPSS_CSV = (
    "#model_version:v2025.03.14,score_date:2026-09-25T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2024-3400,0.94321,0.99912\n"
    "CVE-2023-0001,0.00042,0.05100\n"
    "CVE-2022-1111,0.12000,0.91000\n"
)


class TestParseKev:
    def test_reads_the_catalogue(self):
        catalog = parse_kev(kev_document(kev_entry(ransomware="Known")))

        assert catalog.version == "2026.09.24"
        assert catalog.released == date(2026, 9, 24)
        entry = catalog.entries["CVE-2024-3400"]
        assert entry.date_added == date(2024, 4, 12)
        assert entry.due_date == date(2024, 4, 19)
        assert entry.ransomware is True

    def test_normalises_and_filters_cve_ids(self):
        catalog = parse_kev(
            kev_document(kev_entry(cve=" cve-2024-1111 "), kev_entry(cve="NOT-A-CVE"))
        )
        assert set(catalog.entries) == {"CVE-2024-1111"}

    def test_a_bad_date_keeps_the_entry(self):
        catalog = parse_kev(kev_document(kev_entry(added="someday")))
        assert catalog.entries["CVE-2024-3400"].date_added is None

    def test_unknown_ransomware_use_is_false(self):
        catalog = parse_kev(kev_document(kev_entry(ransomware="Unknown")))
        assert catalog.entries["CVE-2024-3400"].ransomware is False

    @pytest.mark.parametrize(
        "raw",
        [
            b"not json",
            b"[1, 2, 3]",
            json.dumps({"catalogVersion": "1"}).encode(),
            json.dumps({"vulnerabilities": [kev_entry()]}).encode(),
        ],
    )
    def test_an_unexpected_shape_is_rejected(self, raw):
        with pytest.raises(ThreatFeedError):
            parse_kev(raw)

    def test_an_empty_catalogue_is_rejected(self):
        """Applied, it would clear every KEV flag in the database."""
        with pytest.raises(ThreatFeedError, match="empty"):
            parse_kev(kev_document())

    def test_accepts_a_gzipped_copy(self):
        catalog = parse_kev(gzip.compress(kev_document(kev_entry())))
        assert "CVE-2024-3400" in catalog.entries


class TestParseEpss:
    def test_reads_scores_and_metadata(self):
        snapshot = parse_epss(gzip.compress(EPSS_CSV.encode()))

        assert snapshot.model_version == "v2025.03.14"
        assert snapshot.score_date == date(2026, 9, 25)
        assert snapshot.total_rows == 3
        assert snapshot.scores["CVE-2024-3400"].score == pytest.approx(0.94321)
        assert snapshot.scores["CVE-2024-3400"].percentile == pytest.approx(0.99912)

    def test_accepts_plain_csv(self):
        """An administrator may save the file already decompressed."""
        assert len(parse_epss(EPSS_CSV.encode()).scores) == 3

    def test_keeps_only_the_wanted_cves(self):
        snapshot = parse_epss(EPSS_CSV.encode(), wanted={"CVE-2022-1111"})
        assert set(snapshot.scores) == {"CVE-2022-1111"}
        assert snapshot.total_rows == 3

    def test_works_without_the_metadata_line(self):
        headerless = EPSS_CSV.split("\n", 1)[1]
        snapshot = parse_epss(headerless.encode())
        assert snapshot.score_date is None
        assert len(snapshot.scores) == 3

    def test_a_rare_bad_row_is_dropped(self):
        rows = "".join(f"CVE-2024-{1000 + i},0.5,0.5\n" for i in range(200))
        raw = ("cve,epss,percentile\n" + rows + "CVE-2024-9999,1.7,0.5\n").encode()

        snapshot = parse_epss(raw)

        assert "CVE-2024-9999" not in snapshot.scores
        assert len(snapshot.scores) == 200

    def test_many_bad_rows_reject_the_whole_file(self):
        raw = (EPSS_CSV + "CVE-2024-9999,oops,0.5\n").encode()
        with pytest.raises(ThreatFeedError, match="unusable"):
            parse_epss(raw)

    @pytest.mark.parametrize(
        "raw",
        [b"", b"cve,score\nCVE-2024-1,0.1\n", b"cve,epss,percentile\n", b"\xff\xfe\x00"],
    )
    def test_an_unexpected_file_is_rejected(self, raw):
        with pytest.raises(ThreatFeedError):
            parse_epss(raw)


class TestDecompress:
    def test_plain_bytes_pass_through(self):
        assert decompress(b"hello") == b"hello"

    def test_a_gzip_bomb_is_refused(self):
        bomb = gzip.compress(b"\0" * 10_000)
        with pytest.raises(ThreatFeedError, match="inflates"):
            decompress(bomb, max_bytes=1_000)

    def test_corrupt_gzip_is_refused(self):
        with pytest.raises(ThreatFeedError, match="Corrupt"):
            decompress(b"\x1f\x8b" + b"garbage")


class FakeResponse:
    def __init__(self, status_code=200, body=b"", headers=None):
        self.status_code = status_code
        self._body = body
        self.headers = headers or {}
        self.closed = False

    def iter_content(self, chunk_size):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i : i + chunk_size]

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, timeout=None, stream=False):
        self.calls.append({"url": url, "timeout": timeout, "stream": stream})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class TestThreatFeedClient:
    URL = "https://feeds.example/kev.json"

    def test_returns_the_body(self):
        session = FakeSession(FakeResponse(200, b"payload"))

        assert ThreatFeedClient(session, timeout=5).get(self.URL) == b"payload"
        assert session.calls[0] == {"url": self.URL, "timeout": 5, "stream": True}

    def test_retries_a_server_error(self):
        first = FakeResponse(503)
        session = FakeSession(first, FakeResponse(200, b"ok"))

        assert ThreatFeedClient(session).get(self.URL) == b"ok"
        assert first.closed

    def test_honours_a_rate_limit(self, monkeypatch):
        waits = []
        monkeypatch.setattr("app.parsers.threat_feeds.time.sleep", waits.append)
        session = FakeSession(
            FakeResponse(429, headers={"Retry-After": "7"}), FakeResponse(200, b"ok")
        )

        assert ThreatFeedClient(session).get(self.URL) == b"ok"
        assert waits == [7.0]

    def test_a_client_error_is_not_retried(self):
        session = FakeSession(FakeResponse(404))

        with pytest.raises(ThreatFeedError, match="404"):
            ThreatFeedClient(session).get(self.URL)
        assert len(session.calls) == 1

    def test_gives_up_after_repeated_failures(self):
        session = FakeSession(*[FakeResponse(500) for _ in range(4)])

        with pytest.raises(ThreatFeedError, match="still failing"):
            ThreatFeedClient(session).get(self.URL)

    def test_a_network_error_becomes_a_feed_error(self):
        session = FakeSession(*[requests.ConnectionError("no route") for _ in range(4)])

        with pytest.raises(ThreatFeedError, match="Could not reach"):
            ThreatFeedClient(session).get(self.URL)

    def test_recovers_from_a_transient_network_error(self):
        session = FakeSession(requests.Timeout("slow"), FakeResponse(200, b"ok"))
        assert ThreatFeedClient(session).get(self.URL) == b"ok"

    def test_an_oversized_body_is_refused(self):
        session = FakeSession(FakeResponse(200, b"x" * 200_000))

        with pytest.raises(ThreatFeedError, match="exceeds"):
            ThreatFeedClient(session, max_bytes=100_000).get(self.URL)
