"""KB supersedence from the MSRC documents: parsing, chains, and their effect.

Documents are built here in the shape MSRC publishes (checked against the real
2024-Jan to 2026-Sep documents); no test reaches the network.
"""

import json
from datetime import UTC, datetime, timedelta

import pytest
import requests

from app.core.config import settings
from app.models.remediation import FindingRemediation, RemediationAction
from app.models.threat_intel import (
    FEED_MSRC,
    KbSupersedence,
    MsrcDocument,
    ThreatFeedStatus,
)
from app.models.ticket import RemediationTicket, TicketFinding
from app.models.vulnerability import AssetVulnerability
from app.parsers.msrc import parse_msrc_document, parse_msrc_index
from app.parsers.threat_feeds import ThreatFeedError
from app.parsers.utils import remediation
from app.services.ingestion import ingest_findings
from app.services.kb_supersedence import latest_kbs
from app.services.threat_intel import (
    FeedRejected,
    _refresh_one,
    apply_msrc,
    feed_freshness,
    import_feed,
    refresh_msrc,
)

NOW = datetime(2026, 10, 9, 6, 15, tzinfo=UTC)
BASE = settings.THREAT_INTEL_MSRC_URL


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise AssertionError("a test tried to reach the network")

    monkeypatch.setattr(requests.Session, "request", refuse)


def cvrf(doc_id, *remediations, current="2026-10-01T07:00:00", initial=None):
    """A monthly CVRF document; each remediation is (KB, superseded) or a dict."""
    items = [
        (
            item
            if isinstance(item, dict)
            else {
                "Description": {"Value": item[0].removeprefix("KB")},
                "Supercedence": item[1].removeprefix("KB") if item[1] else None,
                "ProductID": ["11568"],
                "Type": 2,
                "SubType": "Security Update",
            }
        )
        for item in remediations
    ]
    return json.dumps(
        {
            "DocumentTitle": {"Value": f"{doc_id} Security Updates"},
            "DocumentTracking": {
                "Identification": {"ID": {"Value": doc_id}, "Alias": {"Value": doc_id}},
                "InitialReleaseDate": initial or f"{doc_id[:4]}-01-09T08:00:00",
                "CurrentReleaseDate": current,
            },
            "ProductTree": {"FullProductName": []},
            "Vulnerability": [{"CVE": "CVE-2024-20674", "Remediations": items}],
        }
    ).encode()


def index(*entries):
    """The ``updates`` index; entries are (ID, initial, current)."""
    return json.dumps(
        {
            "value": [
                {
                    "ID": doc_id,
                    "InitialReleaseDate": initial,
                    "CurrentReleaseDate": current,
                    "CvrfUrl": f"https://elsewhere.example/{doc_id}",
                }
                for doc_id, initial, current in entries
            ]
        }
    ).encode()


def finding(cve="CVE-2024-0001", ip="10.0.0.1", **kwargs):
    base = {
        "ip_address": ip,
        "hostname": None,
        "operating_system": "Windows Server 2019",
        "cve_id": cve,
        "title": "Test vulnerability",
        "description": None,
        "cvss_score": 8.1,
        "severity": "High",
    }
    base.update(kwargs)
    return base


def kb(reference, **kwargs):
    return remediation("kb", reference, title=f"{reference}: Security Update", **kwargs)


def links(db_session):
    return sorted(
        (link.action.reference, link.reported_reference, link.source)
        for link in db_session.query(FindingRemediation)
    )


def apply(db_session, *documents, **kwargs):
    kwargs.setdefault("source", "import")
    return apply_msrc(
        db_session, [parse_msrc_document(doc) for doc in documents], now=NOW, **kwargs
    )


class TestParseDocument:
    def test_reads_which_kb_supersedes_which(self):
        document = parse_msrc_document(
            cvrf("2024-Jan", ("KB5034127", "KB5033371"), ("KB5034129", "KB5033118"))
        )

        assert document.id == "2024-Jan"
        assert document.supersedences == {
            ("KB5034127", "KB5033371"),
            ("KB5034129", "KB5033118"),
        }
        assert document.current_release == datetime(2026, 10, 1, 7, tzinfo=UTC)

    def test_skips_what_names_no_kb(self):
        document = parse_msrc_document(
            cvrf(
                "2026-Sep",
                {"Description": {"Value": "Release Notes"}, "Supercedence": "5120418"},
                {"Description": {"Value": "5122876"}},
                {"URL": "https://learn.microsoft.com/", "Type": 3},
                ("KB5122876", "KB5122876"),
            )
        )

        assert document.supersedences == frozenset()

    def test_a_list_of_superseded_kbs_gives_one_edge_each(self):
        document = parse_msrc_document(
            cvrf(
                "2026-Mar",
                {"Description": {"Value": "5079473"}, "Supercedence": "5077181; 5077212"},
            )
        )

        assert document.supersedences == {
            ("KB5079473", "KB5077181"),
            ("KB5079473", "KB5077212"),
        }

    def test_the_xml_form_is_refused_with_the_way_out(self):
        with pytest.raises(ThreatFeedError, match="Accept: application/json"):
            parse_msrc_document(b'<?xml version="1.0"?>\n<cvrf:cvrfdoc/>')

    @pytest.mark.parametrize(
        "body",
        [b"[]", b'{"Vulnerability": []}', json.dumps({"DocumentTracking": {}}).encode()],
    )
    def test_a_document_that_is_not_cvrf_is_refused(self, body):
        with pytest.raises(ThreatFeedError):
            parse_msrc_document(body)


class TestParseIndex:
    def test_keeps_the_documents_with_a_usable_id(self):
        refs = parse_msrc_index(
            index(
                ("2024-Jan", "2024-01-09T08:00:00Z", "2026-10-07T01:54:29Z"),
                ("2017-May-B", "2017-05-15T00:00:00Z", "2020-09-25T00:00:00Z"),
                ("../../admin", "2024-01-09T08:00:00Z", "2026-10-07T01:54:29Z"),
            )
        )

        assert [ref.id for ref in refs] == ["2024-Jan", "2017-May-B"]
        assert refs[0].current_release == datetime(2026, 10, 7, 1, 54, 29, tzinfo=UTC)

    def test_an_empty_index_is_an_error(self):
        with pytest.raises(ThreatFeedError, match="no documents"):
            parse_msrc_index(index())


class TestLatestKbs:
    def test_follows_a_chain_to_its_end(self):
        latest = latest_kbs([("KB2", "KB1"), ("KB3", "KB2")])

        assert latest == {"KB1": "KB3", "KB2": "KB3"}

    def test_a_fork_that_never_joins_is_left_alone(self):
        # A hotpatch replaced by two different updates (2026-Mar).
        latest = latest_kbs([("KB2a", "KB1"), ("KB2b", "KB1")])

        assert "KB1" not in latest

    def test_a_fork_that_joins_again_resolves(self):
        latest = latest_kbs(
            [("KB2a", "KB1"), ("KB2b", "KB1"), ("KB3", "KB2a"), ("KB3", "KB2b")]
        )

        assert latest["KB1"] == "KB3"

    def test_a_cycle_resolves_nothing(self):
        assert latest_kbs([("KB2", "KB1"), ("KB1", "KB2")]) == {}


class TestIngestion:
    def test_a_superseded_kb_is_recorded_as_the_later_one(self, db_session):
        apply(db_session, cvrf("2024-Feb", ("KB5034768", "KB5034127")))
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        ingest_findings(
            db_session,
            [finding(remediations=[kb("KB5033371", fixed_version="10.0.17763.5206")])],
            "openvas",
        )

        link = db_session.query(FindingRemediation).one()
        assert link.action.reference == "KB5034768"
        assert link.reported_reference == "KB5033371"
        # This host's versions still hold; the old KB's description does not.
        assert link.fixed_version == "10.0.17763.5206"
        assert link.action.title is None
        assert "KB5034768" in link.action.url

    def test_a_scanner_naming_the_later_kb_too_gets_one_link(self, db_session):
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        ingest_findings(
            db_session,
            [finding(remediations=[kb("KB5033371"), kb("KB5034127")])],
            "openvas",
        )

        assert links(db_session) == [("KB5034127", None, "openvas")]
        # The scanner named it: its own description is kept.
        assert db_session.query(RemediationAction).filter_by(
            reference="KB5034127"
        ).one().title == ("KB5034127: Security Update")

    def test_without_msrc_data_nothing_changes(self, db_session):
        ingest_findings(db_session, [finding(remediations=[kb("KB5033371")])], "nessus")

        assert links(db_session) == [("KB5033371", None, "nessus")]

    def test_a_fix_that_is_not_a_kb_is_left_alone(self, db_session):
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))
        fix = remediation("vendor_fix", "nessus:171234", title="Upgrade Apache")

        ingest_findings(db_session, [finding(remediations=[fix])], "nessus")

        assert links(db_session) == [("nessus:171234", None, "nessus")]


class TestApplyMsrc:
    def test_moves_the_links_written_before_the_document(self, db_session):
        ingest_findings(
            db_session,
            [
                finding(ip=ip, remediations=[kb("KB5033371")])
                for ip in ("10.0.0.1", "10.0.0.2")
            ],
            "crowdstrike",
        )

        result = apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        assert result.status == "applied"
        assert result.changed == 2
        assert links(db_session) == [("KB5034127", "KB5033371", "crowdstrike")] * 2

    def test_a_link_to_both_kbs_keeps_the_later_one_only(self, db_session):
        ingest_findings(
            db_session,
            [finding(remediations=[kb("KB5033371"), kb("KB5034127")])],
            "openvas",
        )

        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        assert links(db_session) == [("KB5034127", None, "openvas")]

    def test_two_superseded_kbs_on_one_finding_become_one_link(self, db_session):
        ingest_findings(
            db_session,
            [finding(remediations=[kb("KB5033371"), kb("KB5034127")])],
            "openvas",
        )

        apply(
            db_session,
            cvrf("2024-Feb", ("KB5034768", "KB5034127"), initial="2024-02-13T08:00:00"),
            cvrf("2024-Jan", ("KB5034127", "KB5033371")),
        )

        assert links(db_session) == [("KB5034768", "KB5033371", "openvas")]

    def test_keeps_the_kb_the_scanner_named_through_later_passes(self, db_session):
        ingest_findings(db_session, [finding(remediations=[kb("KB5033371")])], "openvas")
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        apply(
            db_session,
            cvrf("2024-Feb", ("KB5034768", "KB5034127"), initial="2024-02-13T08:00:00"),
        )

        assert links(db_session) == [("KB5034768", "KB5033371", "openvas")]

    def test_the_same_document_again_moves_nothing(self, db_session):
        ingest_findings(db_session, [finding(remediations=[kb("KB5033371")])], "openvas")
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        result = apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        assert result.changed == 0

    def test_a_moved_finding_joins_the_ticket_of_the_later_kb(self, db_session):
        ingest_findings(
            db_session,
            [
                finding(ip="10.0.0.1", remediations=[kb("KB5034127")]),
                finding(ip="10.0.0.2", remediations=[kb("KB5033371")]),
            ],
            "openvas",
        )
        later = db_session.query(RemediationAction).filter_by(reference="KB5034127").one()
        first = db_session.query(FindingRemediation).filter_by(action_id=later.id).one()
        ticket = RemediationTicket(
            action_id=later.id, owner_team=None, title="Deploy KB5034127", status="open"
        )
        db_session.add(ticket)
        db_session.flush()
        db_session.add(TicketFinding(ticket_id=ticket.id, finding_id=first.finding_id))
        db_session.commit()

        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        held = {
            row.finding_id
            for row in db_session.query(TicketFinding).filter_by(ticket_id=ticket.id)
        }
        assert held == {f.id for f in db_session.query(AssetVulnerability)}

    def test_a_ticket_on_the_superseded_kb_follows_the_later_one(self, db_session):
        ingest_findings(db_session, [finding(remediations=[kb("KB5033371")])], "openvas")
        old = db_session.query(RemediationAction).filter_by(reference="KB5033371").one()
        ticket = RemediationTicket(
            action_id=old.id, owner_team=None, title="Deploy KB5033371", status="open"
        )
        db_session.add(ticket)
        db_session.flush()
        finding_id = db_session.query(AssetVulnerability.id).scalar()
        db_session.add(TicketFinding(ticket_id=ticket.id, finding_id=finding_id))
        db_session.commit()

        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        db_session.refresh(ticket)
        assert ticket.action.reference == "KB5034127"
        assert ticket.title.startswith("Deploy KB5034127")
        assert ticket.status == "open"

    def test_records_the_feed_status(self, db_session):
        apply(
            db_session,
            cvrf("2024-Jan", ("KB5034127", "KB5033371"), ("KB5034129", "KB5033118")),
        )

        status = db_session.get(ThreatFeedStatus, FEED_MSRC)
        assert status.source == "import"
        assert status.source_version == "2024-Jan"
        assert status.records == 2
        assert status.last_error is None

    def test_a_revised_document_replaces_its_own_edges_only(self, db_session):
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))
        apply(
            db_session,
            cvrf("2024-Feb", ("KB5034768", "KB5034127"), initial="2024-02-13T08:00:00"),
        )

        apply(
            db_session,
            cvrf("2024-Jan", ("KB5034129", "KB5033118"), current="2026-10-05T07:00:00"),
        )

        assert sorted(
            (edge.document_id, edge.kb) for edge in db_session.query(KbSupersedence)
        ) == [("2024-Feb", "KB5034768"), ("2024-Jan", "KB5034129")]

    def test_an_older_revision_is_refused_unless_forced(self, db_session):
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))
        older = cvrf(
            "2024-Jan", ("KB5034129", "KB5033118"), current="2025-01-01T00:00:00"
        )

        with pytest.raises(FeedRejected, match="older"):
            apply(db_session, older)
        apply(db_session, older, force=True)

        assert db_session.query(KbSupersedence).one().kb == "KB5034129"

    def test_a_revision_that_would_erase_everything_is_refused(self, db_session):
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        with pytest.raises(FeedRejected, match="no superseded KB"):
            apply(db_session, cvrf("2024-Jan", current="2026-10-05T07:00:00"))
        assert db_session.query(KbSupersedence).count() == 1

    def test_the_import_path_takes_a_raw_document(self, db_session):
        result = import_feed(
            db_session, FEED_MSRC, cvrf("2024-Jan", ("KB5034127", "KB5033371")), now=NOW
        )

        assert (result.feed, result.records) == (FEED_MSRC, 1)


class FakeClient:
    def __init__(self, bodies):
        self.bodies = bodies
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append((url, headers))
        body = self.bodies[url]
        if isinstance(body, Exception):
            raise body
        return body


def refresh(db_session, bodies):
    client = FakeClient(bodies)
    # Through the wrapper the daily task uses, which records a failure.
    result = _refresh_one(
        db_session, FEED_MSRC, lambda: refresh_msrc(db_session, client, NOW), NOW
    )
    return result, client


class TestRefresh:
    def test_fetches_the_documents_of_the_window_as_json(self, db_session):
        result, client = refresh(
            db_session,
            {
                BASE
                + "updates": index(
                    ("2026-Sep", "2026-09-08T07:00:00Z", "2026-10-08T07:00:00Z"),
                    ("2016-Jan", "2016-01-12T08:00:00Z", "2026-10-08T07:00:00Z"),
                ),
                BASE
                + "cvrf/2026-Sep": cvrf(
                    "2026-Sep", ("KB5122876", "KB5120418"), current="2026-10-08T07:00:00Z"
                ),
            },
        )

        assert result.status == "applied"
        # Built from the configured base, never from the index's CvrfUrl; the
        # 2016 document is older than THREAT_INTEL_MSRC_MONTHS.
        assert [url for url, _ in client.calls] == [
            BASE + "updates",
            BASE + "cvrf/2026-Sep",
        ]
        assert all(
            headers == {"Accept": "application/json"} for _, headers in client.calls
        )
        assert db_session.query(KbSupersedence).one().kb == "KB5122876"

    def test_only_new_or_recently_revised_documents_are_fetched_again(self, db_session):
        apply(
            db_session,
            cvrf("2026-Sep", ("KB5122876", "KB5120418"), current="2026-10-01T07:00:00Z"),
            cvrf("2025-Jun", ("KB5060531", "KB5058392"), current="2026-10-01T07:00:00Z"),
            cvrf("2026-Aug", ("KB5120418", "KB5117000"), current="2026-10-01T07:00:00Z"),
        )

        _, client = refresh(
            db_session,
            {
                BASE
                + "updates": index(
                    # Revised, recent: fetched again.
                    ("2026-Sep", "2026-09-08T07:00:00Z", "2026-10-08T07:00:00Z"),
                    # Revised, but over two months old: not again.
                    ("2025-Jun", "2025-06-10T07:00:00Z", "2026-10-08T07:00:00Z"),
                    # Unchanged.
                    ("2026-Aug", "2026-08-11T07:00:00Z", "2026-10-01T07:00:00Z"),
                    # New.
                    ("2026-Oct", "2026-10-02T07:00:00Z", "2026-10-08T07:00:00Z"),
                ),
                BASE
                + "cvrf/2026-Sep": cvrf(
                    "2026-Sep", ("KB5122876", "KB5120418"), current="2026-10-08T07:00:00Z"
                ),
                BASE + "cvrf/2026-Oct": cvrf("2026-Oct", current="2026-10-08T07:00:00Z"),
            },
        )

        assert sorted(url for url, _ in client.calls) == [
            BASE + "cvrf/2026-Oct",
            BASE + "cvrf/2026-Sep",
            BASE + "updates",
        ]

    def test_one_failing_document_applies_none(self, db_session):
        result, _ = refresh(
            db_session,
            {
                BASE
                + "updates": index(
                    ("2026-Aug", "2026-08-11T07:00:00Z", "2026-10-01T07:00:00Z"),
                    ("2026-Sep", "2026-09-08T07:00:00Z", "2026-10-08T07:00:00Z"),
                ),
                BASE + "cvrf/2026-Aug": cvrf("2026-Aug", ("KB5120418", "KB5117000")),
                BASE + "cvrf/2026-Sep": ThreatFeedError("HTTP 503"),
            },
        )

        assert result.status == "failed"
        assert db_session.query(MsrcDocument).count() == 0
        status = db_session.get(ThreatFeedStatus, FEED_MSRC)
        assert "503" in status.last_error
        assert status.last_success_at is None

    def test_a_document_answering_for_another_month_is_an_error(self, db_session):
        result, _ = refresh(
            db_session,
            {
                BASE
                + "updates": index(
                    ("2026-Sep", "2026-09-08T07:00:00Z", "2026-10-08T07:00:00Z")
                ),
                BASE + "cvrf/2026-Sep": cvrf("2026-Aug", ("KB5120418", "KB5117000")),
            },
        )

        assert result.status == "failed"
        assert "2026-Aug" in result.error

    def test_a_suspicious_revision_is_skipped_not_blocking(self, db_session):
        apply(
            db_session,
            cvrf("2026-Sep", ("KB5122876", "KB5120418"), current="2026-10-01T07:00:00Z"),
        )

        result, _ = refresh(
            db_session,
            {
                BASE
                + "updates": index(
                    ("2026-Sep", "2026-09-08T07:00:00Z", "2026-10-08T07:00:00Z"),
                    ("2026-Oct", "2026-10-02T07:00:00Z", "2026-10-08T07:00:00Z"),
                ),
                BASE + "cvrf/2026-Sep": cvrf("2026-Sep", current="2026-10-08T07:00:00Z"),
                BASE
                + "cvrf/2026-Oct": cvrf(
                    "2026-Oct", ("KB5130000", "KB5122876"), current="2026-10-08T07:00:00Z"
                ),
            },
        )

        assert result.status == "applied"
        assert sorted(edge.kb for edge in db_session.query(KbSupersedence)) == [
            "KB5122876",
            "KB5130000",
        ]


class TestFreshness:
    def test_msrc_stays_fresh_a_month_after_an_import(self, db_session):
        apply(db_session, cvrf("2024-Jan", ("KB5034127", "KB5033371")))

        feeds = {
            f["feed"]: f for f in feed_freshness(db_session, NOW + timedelta(days=30))
        }

        assert feeds[FEED_MSRC]["stale"] is False
        assert feeds["kev"]["stale"] is True
        assert feeds[FEED_MSRC]["stale_after_hours"] == 35 * 24
