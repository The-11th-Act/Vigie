"""Metrics summed over the API's processes (PROMETHEUS_MULTIPROC_DIR).

prometheus_client picks its storage when it is imported, so each process is a
real subprocess here, as each uvicorn worker is in production.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

SCRIPT = """
import sys
from app.core import metrics

if sys.argv[1] == "serve":
    metrics.observe_request("GET", "/api/v1/assets", 200, 0.05)
    metrics.REQUESTS_IN_PROGRESS.inc()
    metrics.record_capacity(threads=10, connections=15)
else:
    sys.stdout.write(metrics.exposition().decode())
"""


def _process(directory: Path, role: str) -> str:
    env = dict(os.environ, PROMETHEUS_MULTIPROC_DIR=str(directory))
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT, role],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        check=True,
    )
    return result.stdout


def _value(exposition: str, series: str) -> float:
    line = next(line for line in exposition.splitlines() if line.startswith(series + " "))
    return float(line.rsplit(" ", 1)[1])


def test_counters_add_up_across_processes(tmp_path):
    """Without it, each scrape reached one uvicorn worker, and Prometheus read
    each switch between workers as a counter reset."""
    directory = tmp_path / "prometheus"
    _process(directory, "serve")
    _process(directory, "serve")

    exposition = _process(directory, "expose")

    series = 'vigie_http_requests_total{method="GET",route="/api/v1/assets",status="200"}'
    assert _value(exposition, series) == 2.0


def test_a_dead_process_stops_counting_as_busy(tmp_path):
    """Both serving processes have exited: their in-progress requests and their
    capacity are gone. Read from /proc, so only checked on Linux."""
    if not Path("/proc").is_dir():
        pytest.skip("process liveness is read from /proc")
    directory = tmp_path / "prometheus"
    _process(directory, "serve")
    _process(directory, "serve")

    exposition = _process(directory, "expose")

    assert _value(exposition, "vigie_http_requests_in_progress") == 0.0
    assert _value(exposition, "vigie_api_threads") == 0.0
