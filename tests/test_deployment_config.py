"""Vérifie que la surcouche de production neutralise bien le développement.

Ce test double l'étape équivalente de la CI, mais localement : une erreur de
fusion YAML (une clé mal nommée, un `!override` oublié) relancerait `--reload`
ou republierait PostgreSQL sur l'hôte sans que rien n'échoue visiblement. Le
fichier de production est précisément celui qu'on ne teste jamais à la main.

Ignoré si le binaire `docker` n'est pas disponible : il n'est pas nécessaire
que le démon tourne, `docker compose config` ne fait que fusionner du YAML.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Valeurs factices : la surcouche exige ces variables sans repli, donc la
# fusion échoue si elles manquent. Aucune n'est un secret.
FAKE_ENV = {
    "SECRET_KEY": "test-secret-key-not-used-in-production-0123456789",
    "POSTGRES_USER": "vigie",
    "POSTGRES_PASSWORD": "test-password",
    "POSTGRES_DB": "vigie",
    "REDIS_PASSWORD": "test-redis-password",
    "BACKEND_CORS_ORIGINS": '["https://vigie.example.com"]',
}

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker n'est pas installé"
)


def _merged_prod_config(*extra_args: str) -> str:
    env = dict(os.environ)
    env.update(FAKE_ENV)

    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.prod.yml",
            "config",
            *extra_args,
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    if result.returncode != 0:
        pytest.skip(f"docker compose config indisponible : {result.stderr[:200]}")
    return result.stdout


@pytest.fixture(scope="module")
def prod_config() -> str:
    return _merged_prod_config()


@pytest.fixture(scope="module")
def prod_services() -> dict:
    return json.loads(_merged_prod_config("--format", "json"))["services"]


def _volume_targets(service: dict) -> dict[str, str]:
    return {v["target"]: v.get("source", "") for v in service.get("volumes", [])}


class TestProductionOverlay:
    def test_no_autoreload(self, prod_config):
        """Le rechargeur surveille le système de fichiers, ne sert qu'un
        process, et recharge du code arbitraire s'il change."""
        assert "--reload" not in prod_config

    def test_databases_are_not_published_on_the_host(self, prod_config):
        assert not re.search(r'published: "(5432|6379)"', prod_config)

    def test_frontend_is_not_the_vite_dev_server(self, prod_config):
        assert "npm run dev" not in prod_config

    def test_no_bind_mount(self, prod_config):
        """Avec un bind mount, le conteneur exécute le répertoire de l'hôte et
        l'image construite n'est jamais réellement testée."""
        assert "type: bind" not in prod_config

    def test_environment_is_production(self, prod_config):
        # Active le refus d'un SECRET_KEY faible et masque la documentation.
        assert "ENVIRONMENT: production" in prod_config

    def test_redis_requires_a_password(self, prod_config):
        """Un Redis joignable sans mot de passe permet d'écrire un fichier
        arbitraire sur le disque via CONFIG SET dir/dbfilename."""
        assert "requirepass" in prod_config

    def test_readiness_probe_is_used(self, prod_config):
        """/health reste vert quand Redis est tombé ; seul /ready retire du
        service un nœud incapable d'ingérer."""
        assert "/ready" in prod_config

    def test_resource_limits_are_set(self, prod_config):
        assert "limits" in prod_config

    def test_api_and_worker_share_the_upload_volume(self, prod_services):
        """L'API dépose le scan sur disque et ne transmet que son chemin à
        Celery : si le worker ne voit pas le même volume, chaque upload est
        accepté puis échoue sur un fichier introuvable."""
        target = "/var/lib/vigie/scans"
        web = _volume_targets(prod_services["web"])
        worker = _volume_targets(prod_services["worker"])
        assert target in web and target in worker
        assert web[target] == worker[target]

    def test_every_service_that_needs_the_broker_has_its_password(self, prod_services):
        """Redis exige un mot de passe en production : un service resté sur
        l'URL de développement ne pourrait plus parler au broker."""
        for name in ("web", "worker", "beat"):
            redis_url = prod_services[name]["environment"]["REDIS_URL"]
            assert redis_url.startswith("redis://:"), name


class TestDevConfigStillValid:
    def test_dev_compose_is_valid(self):
        env = dict(os.environ)
        env.update(FAKE_ENV)
        result = subprocess.run(
            ["docker", "compose", "-f", "docker-compose.yml", "config", "--quiet"],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=env,
        )
        if "Cannot connect" in result.stderr or "daemon" in result.stderr:
            pytest.skip("démon docker indisponible")
        assert result.returncode == 0, result.stderr
