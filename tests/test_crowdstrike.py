"""CrowdStrike Spotlight client.

Exercised against a simulated transport, not a live tenant: there are no Falcon
credentials here, so the request/retry logic and the response mapping are what
these tests establish. The field names themselves come from CrowdStrike's
published schema and remain unverified against a real API.
"""

import pytest

from app.parsers.crowdstrike import CrowdstrikeClient, CrowdStrikeError


class FakeResponse:
    def __init__(self, status_code=200, json_body=None, headers=None):
        self.status_code = status_code
        self._json = json_body if json_body is not None else {}
        self.headers = headers or {}

    def json(self):
        return self._json


class FakeSession:
    """Stands in for requests.Session, replaying queued responses."""

    def __init__(self, token_responses=None, get_responses=None):
        self.token_responses = list(token_responses or [])
        self.get_responses = list(get_responses or [])
        self.token_calls = 0
        self.get_calls = []

    def post(self, url, data=None, timeout=None):
        self.token_calls += 1
        if self.token_responses:
            return self.token_responses.pop(0)
        return FakeResponse(
            200, {"access_token": f"token-{self.token_calls}", "expires_in": 1800}
        )

    def get(self, url, params=None, headers=None, timeout=None):
        self.get_calls.append({"url": url, "params": params, "headers": headers})
        if not self.get_responses:
            raise AssertionError(f"unexpected GET {url}")
        return self.get_responses.pop(0)


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Retry backoff must not make the suite wait."""
    monkeypatch.setattr("app.parsers.crowdstrike.time.sleep", lambda _seconds: None)


def entity(cve_id="CVE-2023-24897", ip="10.0.2.15", **overrides):
    base = {
        "id": "vuln-1",
        "status": "open",
        "host_info": {
            "hostname": "win-prod-db-01",
            "local_ip": ip,
            "os_version": "Windows Server 2019",
        },
        "cve": {
            "id": cve_id,
            "base_score": 7.8,
            "severity": "HIGH",
            "description": "A remote code execution flaw exists. Patch promptly.",
        },
    }
    base.update(overrides)
    return base


def query_page(ids, after=None):
    return FakeResponse(200, {"resources": ids, "meta": {"pagination": {"after": after}}})


def entities_page(entities):
    return FakeResponse(200, {"resources": entities})


def client(session):
    return CrowdstrikeClient("id", "secret", session=session)


class TestCredentials:
    def test_missing_credentials_are_rejected_up_front(self):
        with pytest.raises(CrowdStrikeError):
            CrowdstrikeClient("", "")


class TestAuthentication:
    def test_token_is_reused_across_requests(self):
        session = FakeSession(
            get_responses=[query_page(["v1"]), entities_page([entity()])]
        )
        client(session).fetch_vulnerabilities()

        # One authentication, not one per call.
        assert session.token_calls == 1

    def test_token_is_sent_as_a_bearer_header(self):
        session = FakeSession(get_responses=[query_page([])])
        client(session).fetch_vulnerabilities()

        assert session.get_calls[0]["headers"]["Authorization"] == "Bearer token-1"

    def test_expired_token_triggers_one_reauthentication(self):
        session = FakeSession(
            get_responses=[
                FakeResponse(401),
                query_page(["v1"]),
                entities_page([entity()]),
            ]
        )
        findings = client(session).fetch_vulnerabilities()

        assert session.token_calls == 2
        assert len(findings) == 1

    def test_persistent_401_does_not_loop_forever(self):
        session = FakeSession(get_responses=[FakeResponse(401)] * 4)

        with pytest.raises(CrowdStrikeError):
            client(session).fetch_vulnerabilities()

    def test_failed_authentication_is_reported(self):
        session = FakeSession(token_responses=[FakeResponse(403)])

        with pytest.raises(CrowdStrikeError, match="authentication failed"):
            client(session).fetch_vulnerabilities()

    def test_authentication_without_a_token_is_reported(self):
        session = FakeSession(token_responses=[FakeResponse(200, {})])

        with pytest.raises(CrowdStrikeError, match="no token"):
            client(session).fetch_vulnerabilities()


class TestPagination:
    def test_follows_the_cursor_across_pages(self):
        session = FakeSession(
            get_responses=[
                query_page(["v1"], after="cursor-1"),
                entities_page([entity(cve_id="CVE-2023-0001", ip="10.0.0.1")]),
                query_page(["v2"], after=None),
                entities_page([entity(cve_id="CVE-2023-0002", ip="10.0.0.2")]),
            ]
        )

        findings = client(session).fetch_vulnerabilities()

        assert [f["cve_id"] for f in findings] == ["CVE-2023-0001", "CVE-2023-0002"]
        # The second query must carry the cursor returned by the first.
        assert session.get_calls[2]["params"]["after"] == "cursor-1"

    def test_stops_on_an_empty_page(self):
        session = FakeSession(get_responses=[query_page([])])
        assert client(session).fetch_vulnerabilities() == []

    def test_entities_are_requested_in_batches(self, monkeypatch):
        monkeypatch.setattr("app.parsers.crowdstrike.ENTITY_BATCH_SIZE", 2)
        session = FakeSession(
            get_responses=[
                query_page(["a", "b", "c"]),
                entities_page([entity(cve_id="CVE-2023-0001", ip="10.0.0.1")]),
                entities_page([entity(cve_id="CVE-2023-0002", ip="10.0.0.2")]),
            ]
        )

        findings = client(session).fetch_vulnerabilities()

        assert len(findings) == 2
        # ids are passed as repeated query parameters, batched.
        assert session.get_calls[1]["params"] == [("ids", "a"), ("ids", "b")]
        assert session.get_calls[2]["params"] == [("ids", "c")]


class TestRetries:
    def test_rate_limit_is_retried_after_the_stated_delay(self, monkeypatch):
        slept = []
        monkeypatch.setattr(
            "app.parsers.crowdstrike.time.sleep", lambda s: slept.append(s)
        )

        session = FakeSession(
            get_responses=[
                FakeResponse(429, headers={"Retry-After": "7"}),
                query_page(["v1"]),
                entities_page([entity()]),
            ]
        )

        assert len(client(session).fetch_vulnerabilities()) == 1
        assert slept == [7.0]

    def test_server_error_is_retried_with_backoff(self, monkeypatch):
        slept = []
        monkeypatch.setattr(
            "app.parsers.crowdstrike.time.sleep", lambda s: slept.append(s)
        )

        session = FakeSession(
            get_responses=[
                FakeResponse(503),
                FakeResponse(503),
                query_page(["v1"]),
                entities_page([entity()]),
            ]
        )

        assert len(client(session).fetch_vulnerabilities()) == 1
        assert slept == [1.0, 2.0]

    def test_gives_up_after_the_attempt_cap(self):
        session = FakeSession(get_responses=[FakeResponse(500)] * 6)

        with pytest.raises(CrowdStrikeError, match="after 5 attempts"):
            client(session).fetch_vulnerabilities()

    def test_client_error_is_not_retried(self):
        """Repeating a malformed request would just burn quota."""
        session = FakeSession(get_responses=[FakeResponse(400)])

        with pytest.raises(CrowdStrikeError, match="HTTP 400"):
            client(session).fetch_vulnerabilities()


class TestNormalisation:
    def _one(self, entity_dict):
        session = FakeSession(
            get_responses=[query_page(["v1"]), entities_page([entity_dict])]
        )
        return client(session).fetch_vulnerabilities()

    def test_maps_onto_the_shared_finding_shape(self):
        finding = self._one(entity())[0]

        assert finding["ip_address"] == "10.0.2.15"
        assert finding["hostname"] == "win-prod-db-01"
        assert finding["operating_system"] == "Windows Server 2019"
        assert finding["cve_id"] == "CVE-2023-24897"
        assert finding["cvss_score"] == 7.8
        assert finding["severity"] == "High"
        assert finding["title"].startswith("CVE-2023-24897")

    def test_upper_case_severity_is_folded_into_the_enum(self):
        finding = self._one(
            entity(cve={"id": "CVE-2023-0001", "base_score": 9.5, "severity": "CRITICAL"})
        )[0]
        assert finding["severity"] == "Critical"

    def test_missing_severity_falls_back_to_the_cvss_band(self):
        finding = self._one(entity(cve={"id": "CVE-2023-0001", "base_score": 9.5}))[0]
        assert finding["severity"] == "Critical"

    def test_entry_without_a_valid_cve_is_dropped(self):
        """It could not be deduplicated against the other sources."""
        assert self._one(entity(cve={"id": "NOCVE", "base_score": 5.0})) == []

    def test_entry_without_an_ip_is_dropped(self):
        """It could not be tied to an asset."""
        assert self._one(entity(host_info={"hostname": "ghost"})) == []

    def test_malformed_score_does_not_raise(self):
        finding = self._one(
            entity(cve={"id": "CVE-2023-0001", "base_score": "not-a-number"})
        )[0]
        assert finding["cvss_score"] == 0.0

    def test_lower_case_cve_is_normalised(self):
        finding = self._one(entity(cve={"id": "cve-2023-0001", "base_score": 5.0}))[0]
        assert finding["cve_id"] == "CVE-2023-0001"
