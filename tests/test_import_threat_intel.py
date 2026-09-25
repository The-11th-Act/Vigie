"""Tests du script d'import hors ligne des flux KEV et EPSS.

C'est le seul chemin d'enrichissement d'une installation sans accès Internet
sortant : s'il est cassé, le score de risque y reste aveugle à l'exploitation.
"""

import gzip
import json

import pytest

from app.models.vulnerability import Vulnerability
from scripts.import_threat_intel import main, parse_args
from tests.test_create_admin import _NonClosing


@pytest.fixture(autouse=True)
def test_session(db_session, monkeypatch):
    monkeypatch.setattr(
        "scripts.import_threat_intel.SessionLocal", lambda: _NonClosing(db_session)
    )
    db_session.add(
        Vulnerability(
            cve_id="CVE-2024-3400", title="PAN-OS", cvss_score=10.0, severity="Critical"
        )
    )
    db_session.commit()
    return db_session


def write_kev(tmp_path, *cves, version="2026.09.25"):
    path = tmp_path / "kev.json"
    path.write_text(
        json.dumps(
            {
                "catalogVersion": version,
                "dateReleased": "2026-09-25",
                "vulnerabilities": [{"cveID": cve} for cve in cves],
            }
        )
    )
    return str(path)


def write_epss(tmp_path, rows):
    path = tmp_path / "epss.csv.gz"
    body = "cve,epss,percentile\n" + "".join(f"{c},{s},0.5\n" for c, s in rows.items())
    path.write_bytes(gzip.compress(body.encode()))
    return str(path)


def stored(db_session):
    return db_session.query(Vulnerability).filter_by(cve_id="CVE-2024-3400").one()


class TestArguments:
    def test_at_least_one_feed_is_required(self):
        with pytest.raises(SystemExit):
            parse_args([])

    def test_force_is_off_by_default(self):
        assert parse_args(["--kev", "kev.json"]).force is False


class TestImport:
    def test_applies_both_files(self, tmp_path, test_session):
        code = main(
            [
                "--kev",
                write_kev(tmp_path, "CVE-2024-3400"),
                "--epss",
                write_epss(tmp_path, {"CVE-2024-3400": 0.97}),
            ]
        )

        assert code == 0
        vuln = stored(test_session)
        assert vuln.in_kev is True
        assert vuln.epss_score == pytest.approx(0.97)

    def test_a_missing_file_fails(self, tmp_path):
        assert main(["--kev", str(tmp_path / "absent.json")]) == 1

    def test_a_malformed_file_fails_without_writing(self, tmp_path, test_session):
        path = tmp_path / "kev.json"
        path.write_text("<html>not the catalogue</html>")

        assert main(["--kev", str(path)]) == 1
        assert stored(test_session).in_kev is False

    def test_one_bad_file_does_not_block_the_other(self, tmp_path, test_session):
        bad = tmp_path / "kev.json"
        bad.write_text("{}")

        code = main(
            ["--kev", str(bad), "--epss", write_epss(tmp_path, {"CVE-2024-3400": 0.4})]
        )

        assert code == 1
        assert stored(test_session).epss_score == pytest.approx(0.4)

    def test_force_applies_a_refused_snapshot(self, tmp_path, test_session):
        many = [f"CVE-2024-{1000 + i}" for i in range(20)]
        assert main(["--kev", write_kev(tmp_path, "CVE-2024-3400", *many)]) == 0

        shrunk = write_kev(tmp_path, "CVE-2024-1000")
        assert main(["--kev", shrunk]) == 1
        assert stored(test_session).in_kev is True

        assert main(["--kev", shrunk, "--force"]) == 0
        assert stored(test_session).in_kev is False
