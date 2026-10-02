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
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Contenu des fichiers de secrets factices : il ne doit apparaître nulle
# part dans la configuration fusionnée.
FAKE_SECRETS = {
    "secret_key": "fake-secret-key-must-stay-in-its-file-0123456789",
    "postgres_password": "fake-postgres-password-in-its-file",
    "redis_password": "fake-redis-password-in-its-file",
    "previous_secret_keys": '{"k0": "fake-retired-key-in-its-file-0123456789"}',
    "rclone.conf": (
        "[offsite]\ntype = s3\nsecret_access_key = fake-offsite-key-in-its-file\n"
    ),
    "glpi_user_token": "fake-glpi-user-token-in-its-file",
    "glpi_app_token": "fake-glpi-app-token-in-its-file",
}
# Secrets of the optional overlays: absent from the production overlay alone.
OVERLAY_SECRETS = {"rclone.conf", "glpi_user_token", "glpi_app_token"}
_SECRETS_DIR = Path(tempfile.mkdtemp(prefix="vigie-secrets-"))
for _name, _value in FAKE_SECRETS.items():
    (_SECRETS_DIR / _name).write_text(_value, encoding="utf-8")

# Valeurs factices : la surcouche exige ces variables sans repli, donc la
# fusion échoue si elles manquent. Les secrets, eux, sont des fichiers.
FAKE_ENV = {
    "POSTGRES_USER": "vigie",
    "POSTGRES_DB": "vigie",
    "BACKEND_CORS_ORIGINS": '["https://vigie.example.com"]',
    "VIGIE_SECRETS_DIR": str(_SECRETS_DIR),
    # Comme sur un hôte migré qui aurait gardé ses anciennes variables.
    "SECRET_KEY": "leftover-secret-key-from-an-old-env-file-0123456789",
    "POSTGRES_PASSWORD": "leftover-postgres-password",
    "REDIS_PASSWORD": "leftover-redis-password",
    "GLPI_USER_TOKEN": "leftover-glpi-user-token",
}

pytestmark = pytest.mark.skipif(
    shutil.which("docker") is None, reason="docker n'est pas installé"
)


def _merged_prod_config(*extra_args: str, extra_env: dict | None = None) -> str:
    env = dict(os.environ)
    env.update(FAKE_ENV)
    env.update(extra_env or {})

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

    def test_metrics_add_up_across_api_processes(self, prod_services):
        """Sans répertoire multiprocessus, chaque scrape ne voit qu'un des
        process uvicorn : ses compteurs, que Prometheus lit comme remis à zéro.
        Sur un tmpfs, pour repartir de zéro avec le conteneur."""
        web = prod_services["web"]
        directory = web["environment"]["PROMETHEUS_MULTIPROC_DIR"]
        assert any(directory.startswith(mount + "/") for mount in web["tmpfs"])
        assert "--workers" in " ".join(web["command"])

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
        """Redis exige un mot de passe en production : un service sans lui ne
        pourrait plus parler au broker. Il le lit dans son secret."""
        for name in ("web", "worker", "beat"):
            env = prod_services[name]["environment"]
            assert env["REDIS_PASSWORD_FILE"] == "/run/secrets/redis_password", name
            assert "redis_password" in _secret_names(prod_services[name]), name

    def test_the_scheduler_is_not_probed_like_the_api(self, prod_services):
        """Le HEALTHCHECK de l'image interroge l'API sur :8000, que beat ne sert
        pas : le conteneur était marqué « unhealthy » en permanence."""
        assert prod_services["beat"]["healthcheck"]["disable"] is True

    def test_the_database_is_backed_up(self, prod_services):
        backup = prod_services["backup"]
        assert backup["read_only"] is True
        assert "ports" not in backup
        assert "/backups" in _volume_targets(backup)
        # Clé publique transmise ; jamais de clé privée dans l'environnement.
        assert "BACKUP_AGE_RECIPIENT" in backup["environment"]
        assert not any("IDENTITY" in name for name in backup["environment"])

    def test_pg_dump_matches_the_server_version(self, prod_services):
        """pg_dump refuse de sauvegarder un serveur d'une version majeure plus
        récente que lui : l'image de sauvegarde doit suivre celle de la base."""
        dockerfile = (REPO_ROOT / "deploy" / "backup" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        base = next(
            line.split()[1]
            for line in dockerfile.splitlines()
            if line.startswith("FROM ")
        )
        assert base == prod_services["db"]["image"]


# Réglages que le déploiement n'a pas à exposer : des constantes de l'API, ou
# un chemin figé par l'image et ses volumes.
NOT_DEPLOYMENT_SETTINGS = {"PROJECT_NAME", "API_V1_STR", "ALGORITHM", "SCAN_UPLOAD_DIR"}

# Réglages volontairement limités aux services qui s'en servent : un secret ou
# un identifiant administrateur n'a rien à faire dans l'environnement des autres.
ONLY_ON = {
    ("web",): {
        "API_THREADS",
        "INSTANCE_BANNER",
        "BACKEND_CORS_ORIGINS",
        "RATE_LIMIT_ENABLED",
        "LOGIN_MAX_ATTEMPTS",
        "LOGIN_WINDOW_SECONDS",
        "LOGIN_LOCKOUT_SECONDS",
        "ADMIN_USERNAME",
        "ADMIN_EMAIL",
        "ADMIN_PASSWORD",
    },
    ("worker",): {
        "CROWDSTRIKE_CLIENT_ID",
        "CROWDSTRIKE_CLIENT_SECRET",
        "GLPI_USER_TOKEN",
        "GLPI_APP_TOKEN",
    },
    # Les clés retirées : l'API vérifie les tokens qu'elles ont signés, le
    # worker reconnaît et rescelle les webhooks qu'elles ont scellés.
    ("web", "worker"): {"PREVIOUS_SECRET_KEYS"},
}


def _secret_names(service: dict) -> set[str]:
    return {secret["source"] for secret in service.get("secrets", [])}


class TestSecrets:
    """Les secrets sont des fichiers montés (Docker secrets) : absents du .env,
    de l'environnement des conteneurs et donc de `docker inspect`."""

    def test_no_secret_value_in_the_configuration(self, prod_config):
        for value in FAKE_SECRETS.values():
            assert value not in prod_config
        # Ni les anciennes valeurs restées dans l'environnement de l'hôte.
        for name in (
            "SECRET_KEY",
            "POSTGRES_PASSWORD",
            "REDIS_PASSWORD",
            "GLPI_USER_TOKEN",
        ):
            assert FAKE_ENV[name] not in prod_config, name

    @pytest.mark.parametrize("service", ["migrate", "web", "worker", "beat"])
    def test_the_application_reads_them_from_files(self, prod_services, service):
        env = prod_services[service]["environment"]
        assert env["SECRET_KEY_FILE"] == "/run/secrets/secret_key"
        assert env["DATABASE_PASSWORD_FILE"] == "/run/secrets/postgres_password"
        assert env["SECRET_KEY"] == ""
        assert "@db:5432" in env["DATABASE_URL"]
        assert ":" not in env["DATABASE_URL"].split("//", 1)[1].split("@", 1)[0]
        assert {"secret_key", "postgres_password"} <= _secret_names(
            prod_services[service]
        )

    def test_retired_keys_only_reach_the_api_and_the_worker(self, prod_services):
        # Le worker en a besoin aussi : c'est lui qui envoie les webhooks et
        # les rescelle au passage quotidien. Sans elles, chaque rotation de la
        # clé faisait abandonner tous les envois (« another instance »).
        for name in ("web", "worker"):
            service = prod_services[name]
            assert service["environment"]["PREVIOUS_SECRET_KEYS"] == ""
            assert (
                service["environment"]["PREVIOUS_SECRET_KEYS_FILE"]
                == "/run/secrets/previous_secret_keys"
            )
            assert "previous_secret_keys" in _secret_names(service)
        for name in ("beat", "migrate"):
            assert "previous_secret_keys" not in _secret_names(prod_services[name])

    def test_the_database_and_its_backup_too(self, prod_services):
        db = prod_services["db"]["environment"]
        assert "POSTGRES_PASSWORD" not in db
        assert db["POSTGRES_PASSWORD_FILE"] == "/run/secrets/postgres_password"
        backup = prod_services["backup"]["environment"]
        assert "PGPASSWORD" not in backup
        assert backup["PGPASSWORD_FILE"] == "/run/secrets/postgres_password"

    def test_redis_does_not_run_as_root(self, prod_services):
        """Relancé par le script d'entrée de l'image, qui passe à l'utilisateur
        redis ; un `sh -c` seul aurait gardé root."""
        command = " ".join(prod_services["redis"]["command"])
        assert "exec docker-entrypoint.sh redis-server" in command

    def test_they_come_from_the_secrets_directory(self, prod_config):
        parsed = json.loads(_merged_prod_config("--format", "json"))["secrets"]
        assert set(parsed) == set(FAKE_SECRETS) - OVERLAY_SECRETS
        for secret in parsed.values():
            assert Path(secret["file"]).parent == _SECRETS_DIR


@pytest.fixture(scope="module")
def offsite_backup() -> dict:
    env = dict(os.environ)
    env.update(FAKE_ENV)
    env["BACKUP_REMOTE"] = "offsite:vigie-backups"
    result = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "docker-compose.yml",
            "-f",
            "docker-compose.prod.yml",
            "-f",
            "docker-compose.offsite.yml",
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    if result.returncode != 0:
        pytest.skip(f"docker compose config indisponible : {result.stderr[:200]}")
    assert "fake-offsite-key" not in result.stdout
    return json.loads(result.stdout)["services"]["backup"]


class TestOffsiteCopy:
    """La copie hors site est une surcouche : ses identifiants sont un secret de
    plus, jamais une variable."""

    def test_the_backup_copies_offsite(self, offsite_backup):
        env = offsite_backup["environment"]
        assert env["BACKUP_REMOTE"] == "offsite:vigie-backups"
        assert env["RCLONE_CONFIG"] == "/run/secrets/rclone_conf"
        assert {"postgres_password", "rclone_conf"} <= _secret_names(offsite_backup)

    def test_nothing_without_the_overlay(self, prod_services):
        env = prod_services["backup"]["environment"]
        assert "BACKUP_REMOTE" not in env
        assert "rclone_conf" not in _secret_names(prod_services["backup"])


@pytest.fixture(scope="module")
def glpi_services() -> dict:
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
            "-f",
            "docker-compose.glpi.yml",
            "config",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
    )
    if result.returncode != 0:
        pytest.skip(f"docker compose config indisponible : {result.stderr[:200]}")
    assert "fake-glpi" not in result.stdout
    assert FAKE_ENV["GLPI_USER_TOKEN"] not in result.stdout
    return json.loads(result.stdout)["services"]


class TestGlpiConnector:
    """Les jetons GLPI sont des fichiers, montés dans le seul worker par une
    surcouche : l'API, qui ne fait que rendre compte, n'en détient aucun."""

    def test_the_worker_reads_the_tokens_from_files(self, glpi_services):
        worker = glpi_services["worker"]
        env = worker["environment"]
        assert env["GLPI_USER_TOKEN_FILE"] == "/run/secrets/glpi_user_token"
        assert env["GLPI_APP_TOKEN_FILE"] == "/run/secrets/glpi_app_token"
        assert env["GLPI_USER_TOKEN"] == env["GLPI_APP_TOKEN"] == ""
        # La surcouche redonne la liste complète : aucun secret du worker perdu.
        assert _secret_names(worker) == {
            "secret_key",
            "previous_secret_keys",
            "postgres_password",
            "redis_password",
            "glpi_user_token",
            "glpi_app_token",
        }

    def test_nowhere_else(self, glpi_services):
        for name in ("web", "beat", "migrate"):
            service = glpi_services[name]
            assert not {"glpi_user_token", "glpi_app_token"} & _secret_names(service)
            assert "GLPI_USER_TOKEN_FILE" not in service["environment"]

    def test_no_token_from_the_environment_without_the_overlay(self, prod_services):
        env = prod_services["worker"]["environment"]
        assert env["GLPI_USER_TOKEN"] == env["GLPI_APP_TOKEN"] == ""
        assert "glpi_user_token" not in _secret_names(prod_services["worker"])


def _environment(**overrides: str) -> dict:
    return json.loads(_merged_prod_config("--format", "json", extra_env=overrides))


class TestStagingAndPromotion:
    """La préproduction est la surcouche de production lancée depuis un second
    checkout, avec son propre .env : elle ne partage rien avec la production,
    et la production exécute les images qu'elle a validées."""

    def test_no_fixed_container_name(self, prod_services):
        """Un container_name figé fait échouer le démarrage d'une seconde pile
        sur le même hôte, quel que soit son nom de projet."""
        named = [name for name, s in prod_services.items() if "container_name" in s]
        assert not named

    def test_staging_and_production_share_nothing(self):
        prod = _environment(COMPOSE_PROJECT_NAME="vigie")
        staging = _environment(COMPOSE_PROJECT_NAME="vigie-staging", FRONTEND_PORT="8081")

        assert (prod["name"], staging["name"]) == ("vigie", "vigie-staging")
        for kind in ("volumes", "networks"):
            prod_names = {item["name"] for item in prod[kind].values()}
            staging_names = {item["name"] for item in staging[kind].values()}
            assert prod_names and not prod_names & staging_names, kind

        def published(config):
            return {
                port["published"]
                for service in config["services"].values()
                for port in service.get("ports", [])
            }

        assert published(prod) == {"8080"}
        assert published(staging) == {"8081"}

    def test_every_built_image_is_named_after_the_release(self):
        """Sans nom d'image, compose en invente un par projet : la production
        reconstruirait depuis ses sources au lieu d'exécuter l'image validée."""
        services = _environment(VIGIE_VERSION="v1.2.3")["services"]
        built = {name: s for name, s in services.items() if "build" in s}

        assert {"migrate", "web", "worker", "beat", "frontend", "backup"} <= set(built)
        for name, service in built.items():
            assert service.get("image", "").endswith(":v1.2.3"), name

    def test_api_migrations_worker_and_scheduler_run_one_image(self):
        services = _environment(
            VIGIE_VERSION="v1.2.3", VIGIE_REGISTRY="registry.example.com/vigie/"
        )["services"]

        for name in ("migrate", "web", "worker", "beat"):
            assert (
                services[name]["image"] == "registry.example.com/vigie/vigie-api:v1.2.3"
            )
        assert services["frontend"]["image"] == (
            "registry.example.com/vigie/vigie-frontend:v1.2.3"
        )
        assert (
            services["backup"]["image"]
            == "registry.example.com/vigie/vigie-backup:v1.2.3"
        )


class TestConnectionBudget:
    """Chaque processus a son propre pool : les défauts de la pile doivent
    tenir dans max_connections de PostgreSQL. Avant, 4 workers uvicorn × (10 +
    20) pouvaient ouvrir 120 connexions pour 100 disponibles."""

    # Défaut de l'image postgres, que la surcouche ne change pas.
    POSTGRES_MAX_CONNECTIONS = 100
    # superuser_reserved_connections, plus une marge pour l'exploitant (psql,
    # restauration, sonde de supervision).
    RESERVED = 3 + 5

    def test_the_defaults_fit_postgres(self, prod_services):
        from app.core.config import Settings

        fields = Settings.model_fields
        per_api_process = (
            fields["DB_POOL_SIZE"].default + fields["DB_MAX_OVERFLOW"].default
        )
        web = " ".join(prod_services["web"]["command"])
        worker = " ".join(prod_services["worker"]["command"])
        api_processes = int(re.search(r"--workers (\d+)", web).group(1))
        celery_children = int(re.search(r"--concurrency=(\d+)", worker).group(1))

        assert "max_connections" not in json.dumps(prod_services["db"])
        # Un enfant Celery exécute une tâche, donc une session, à la fois ; le
        # beat, la sauvegarde et les migrations en prennent une chacun.
        total = api_processes * per_api_process + celery_children + 3
        assert total <= self.POSTGRES_MAX_CONNECTIONS - self.RESERVED, total


class TestSettingsReachTheContainers:
    """En production, un conteneur ne lit pas le .env : il est exclu de l'image
    et aucun code source n'est monté. Un réglage n'arrive que s'il est câblé
    dans docker-compose.yml. CRITICALITY_RULES et tout le contexte de menace ne
    l'étaient pas : THREAT_INTEL_ENABLED=true dans .env restait sans effet. En
    développement, le .env monté avec le code masquait le trou."""

    @pytest.mark.parametrize("service", ["web", "worker", "beat"])
    def test_every_setting_is_wired(self, prod_services, service):
        from app.core.config import Settings

        expected = set(Settings.model_fields) - NOT_DEPLOYMENT_SETTINGS
        for owners, scoped in ONLY_ON.items():
            if service not in owners:
                expected -= scoped

        # Un secret est câblé par son fichier (NAME_FILE) plutôt que par sa valeur.
        environment = set(prod_services[service]["environment"])
        wired = environment | {
            name.removesuffix("_FILE") for name in environment if name.endswith("_FILE")
        }
        missing = expected - wired
        assert not missing, (
            f"{sorted(missing)} n'atteint pas le service {service} : ajouter la "
            "variable à x-app-settings (ou au service) dans docker-compose.yml."
        )

    @pytest.mark.parametrize("service", ["web", "beat"])
    def test_secrets_stay_where_they_are_used(self, prod_services, service):
        assert "CROWDSTRIKE_CLIENT_SECRET" not in prod_services[service]["environment"]

    def test_a_value_from_the_host_reaches_the_application(self):
        services = json.loads(
            _merged_prod_config(
                "--format",
                "json",
                extra_env={"THREAT_INTEL_ENABLED": "true", "KEV_SLA_DAYS": "7"},
            )
        )["services"]

        for name in ("web", "worker", "beat"):
            env = services[name]["environment"]
            assert env["THREAT_INTEL_ENABLED"] == "true", name
            assert env["KEV_SLA_DAYS"] == "7", name

    def test_an_unset_setting_keeps_the_code_default(self, monkeypatch):
        """Une variable non définie arrive vide : l'application doit l'ignorer,
        pas échouer à lire "" comme un entier, une liste ou un booléen."""
        from app.core.config import Settings

        for name in (
            "KEV_SLA_DAYS",
            "RANSOMWARE_SLA_DAYS",
            "CRITICALITY_RULES",
            "THREAT_INTEL_ENABLED",
        ):
            monkeypatch.setenv(name, "")

        settings = Settings(_env_file=None)

        assert settings.KEV_SLA_DAYS == 14
        assert settings.RANSOMWARE_SLA_DAYS == 7
        assert settings.CRITICALITY_RULES == {}
        assert settings.THREAT_INTEL_ENABLED is False


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
