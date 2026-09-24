"""Tests des chemins d'échec de la tâche Celery d'ingestion.

``test_worker_tasks.py`` couvre le cycle de vie du ScanJob et le fichier
déposé ; ce module couvre ce qui se passe quand ça casse. C'est le code le
plus difficile à déboguer en production : sans requête HTTP à laquelle rattacher une erreur, un
échec ici se manifeste par un scan qui « ne fait rien ». Les chemins qui
comptent ne sont pas le cas passant, mais la gestion des échecs : le rollback,
l'abandon après ``max_retries``, et le fait qu'une session ne fuit jamais.

La tâche est appelée directement plutôt que par ``.delay()`` : aucun broker
n'est nécessaire, et on teste la logique, pas Celery.
"""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from app.worker.tasks import PARSERS, process_scan_file_task

VALID_XML = b"<NessusClientData_v2></NessusClientData_v2>"


@pytest.fixture
def staged(tmp_path):
    """Un rapport déposé sur le volume partagé : la tâche reçoit un chemin,
    pas le contenu."""
    path = tmp_path / "report.nessus"
    path.write_bytes(VALID_XML)
    return str(path)


@contextmanager
def run_task(retries=0):
    """Exécute la tâche hors de Celery, avec un compteur de tentatives choisi.

    La tâche est `bind=True` et enveloppée par `autoretry_for` : appelée
    normalement, Celery intercepterait toute exception pour la convertir en
    `Retry`, ce qui masquerait le comportement qu'on veut observer.
    `_orig_run` est la fonction d'origine, déjà liée à la tâche ; `push_request`
    est le mécanisme prévu par Celery pour lui fournir un contexte d'exécution.
    """
    process_scan_file_task.push_request(retries=retries)
    try:
        yield process_scan_file_task._orig_run
    finally:
        process_scan_file_task.pop_request()


@pytest.fixture
def fake_session():
    session = MagicMock()
    with patch("app.worker.tasks.SessionLocal", return_value=session):
        yield session


class TestScanTypeDispatch:
    def test_every_supported_scan_type_has_a_parser(self):
        """L'API accepte `nessus` et `openvas` ; si le worker ne connaît pas
        exactement les mêmes, un upload valide est accepté puis ignoré."""
        from app.api.v1.scans import VALID_SCAN_TYPES

        assert VALID_SCAN_TYPES == set(PARSERS)

    def test_an_unknown_type_fails_immediately_without_retrying(
        self, fake_session, staged
    ):
        """Un type invalide est une erreur permanente : la réessayer trois fois
        avec backoff ne fait que retarder le même échec."""
        with run_task() as task:
            result = task(staged, "qualys")

        assert result["status"] == "error"
        assert "qualys" in result["message"]
        # Aucune session ne doit être ouverte pour un échec de dispatch.
        fake_session.close.assert_not_called()

    def test_the_scan_type_is_case_insensitive(self, fake_session, staged):
        with patch.dict(PARSERS, {"nessus": lambda _: []}), run_task() as task:
            result = task(staged, "NESSUS")
        assert result["status"] == "success"

    def test_a_missing_scan_type_is_handled(self, fake_session, staged):
        with run_task() as task:
            result = task(staged, None)
        assert result["status"] == "error"


class TestSuccessPath:
    def test_returns_the_ingestion_counters(self, fake_session, staged):
        from app.services.ingestion import IngestionResult

        ingestion_result = IngestionResult(
            processed_records=7, new_assets=2, new_vulnerabilities=3, new_associations=7
        )
        with (
            patch.dict(PARSERS, {"nessus": lambda _: [{"cve_id": "CVE-2021-1"}]}),
            patch("app.worker.tasks.ingest_findings", return_value=ingestion_result),
            run_task() as task,
        ):
            result = task(staged, "nessus")

        assert result["status"] == "success"
        assert result["processed_records"] == 7
        assert result["new_assets"] == 2

    def test_the_session_is_always_closed(self, fake_session, staged):
        from app.services.ingestion import IngestionResult

        with (
            patch.dict(PARSERS, {"nessus": lambda _: []}),
            patch("app.worker.tasks.ingest_findings", return_value=IngestionResult()),
            run_task() as task,
        ):
            task(staged, "nessus")

        fake_session.close.assert_called_once()


class TestFailurePath:
    def test_a_failure_rolls_back_and_closes(self, fake_session, staged):
        """Sans rollback, la connexion revient au pool dans une transaction
        avortée et empoisonne la requête suivante qui la réutilise."""

        def exploding_parser(_):
            raise ValueError("XML corrompu")

        with patch.dict(PARSERS, {"nessus": exploding_parser}), run_task(0) as task:
            with pytest.raises(ValueError):
                task(staged, "nessus")

        fake_session.rollback.assert_called_once()
        fake_session.close.assert_called_once()

    def test_the_exception_is_reraised_so_celery_can_retry(self, fake_session, staged):
        """Tant que les tentatives restent, l'exception doit remonter :
        c'est elle qui déclenche `autoretry_for`."""

        def exploding_parser(_):
            raise RuntimeError("base indisponible")

        with patch.dict(PARSERS, {"nessus": exploding_parser}), run_task(1) as task:
            with pytest.raises(RuntimeError):
                task(staged, "nessus")

    def test_the_last_attempt_returns_an_error_instead_of_raising(
        self, fake_session, staged
    ):
        """À la dernière tentative, relancer ne servirait qu'à produire une
        trace ; on rend un résultat exploitable par l'appelant."""

        def exploding_parser(_):
            raise RuntimeError("échec définitif")

        with patch.dict(PARSERS, {"nessus": exploding_parser}), run_task(3) as task:
            result = task(staged, "nessus")

        assert result["status"] == "error"
        assert "échec définitif" in result["message"]
        fake_session.rollback.assert_called_once()
        fake_session.close.assert_called_once()


class TestRetryConfiguration:
    def test_retries_are_bounded(self):
        """Une tâche qui réessaie indéfiniment sur une erreur permanente
        sature le worker."""
        assert process_scan_file_task.max_retries == 3

    def test_time_limits_are_set(self):
        """Sans limite de temps, un scan pathologique bloque un worker pour
        toujours."""
        assert process_scan_file_task.soft_time_limit is not None
        assert process_scan_file_task.time_limit is not None
        assert process_scan_file_task.soft_time_limit < process_scan_file_task.time_limit
