# Vigie — Risk-Based Vulnerability Management (RBVM) Platform

A modular platform for assets and vulnerabilities management, scanning parsing, and task queue processing.

## Tech Stack
- **Backend**: FastAPI (Python)
- **Frontend**: React + Vite
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Task Queue**: Celery with Redis broker
- **Migrations**: Alembic
- **Testing**: Pytest
- **Quality**: ruff + black (configured in `pyproject.toml`)
- **CI**: GitHub Actions (`.github/workflows/ci.yml`)

## Architecture
- `app/core/`: Application settings, security utilities (JWT/RBAC), admin bootstrap.
- `app/db/`: DB connection & migrations.
- `app/models/`: Database models.
- `app/schemas/`: Data validation models (Pydantic).
- `app/api/`: API endpoints (versioned under `v1/`), including `users` (role management).
- `app/services/`: Pure business logic (e.g., risk scoring, remediation SLA tracking).
- `app/parsers/`: Ingestors for Nessus, OpenVAS, and CrowdStrike data.
- `app/worker/`: Celery asynchronous worker setup.
- `frontend/`: React SPA (dashboard, assets, vulnerabilities, risk backlog, scan upload).

## Getting Started

### Prerequisites
1. Copy `.env.example` to `.env`.
2. Generate a `SECRET_KEY` (the app refuses to start in production without one, and warns in development):
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
3. (Optional) Set `ADMIN_USERNAME`, `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`. If all
   three are set, the app creates (or promotes) that account to admin automatically on
   startup — this is the only way to get a first admin, since self-registration always
   creates an `analyst` account. Once you have one admin, further role changes go through
   `PATCH /api/v1/users/{id}/role` (admin-only).

### Local Setup
1. Set up a virtual environment and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Or venv\\Scripts\activate on Windows
   pip install -r requirements-dev.txt   # includes requirements.txt + test/lint tooling
   ```
2. Run database migrations:
   ```bash
   alembic upgrade head
   ```
3. Run the development server (this also runs the admin bootstrap on startup):
   ```bash
   uvicorn app.main:app --reload
   ```
4. Run the Celery worker (required for scan ingestion):
   ```bash
   celery -A app.worker.celery_app worker --loglevel=info
   ```
5. Run the frontend:
   ```bash
   cd frontend
   npm ci        # `ci`, not `install`: installs exactly what the lockfile pins
   npm run dev
   ```

### Running with Docker Compose (development)
```bash
docker compose up --build
```
Migrations run automatically via a one-shot `migrate` service before `web` and `worker`
start. The admin account is bootstrapped automatically if `ADMIN_USERNAME` /
`ADMIN_EMAIL` / `ADMIN_PASSWORD` are set in `.env`.

This stack is **development only**: it runs `uvicorn --reload`, mounts the source tree
into the container, serves the frontend through the Vite dev server, and publishes
PostgreSQL and Redis on the host. See below for production.

### Running in production

```bash
# 1. Fill in the [PROD] section of .env (REDIS_PASSWORD, BACKEND_CORS_ORIGINS, ...)
# 2. Start the stack with the production overlay:
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

What the overlay changes, and why:

| Development | Production | Reason |
|---|---|---|
| `uvicorn --reload`, 1 process | `--workers N`, no reload | The reloader watches the filesystem and serves a single process |
| Source mounted as a volume | No bind mount | Otherwise the built image is never actually executed, and `USER appuser` protects nothing |
| Frontend via `npm run dev` | Built SPA served by Nginx | The Vite dev server is not a production server |
| Postgres/Redis published on the host | Internal network only | Nothing that holds data should be reachable from outside |
| Redis without a password | `--requirepass` | An exposed passwordless Redis is remote code execution |
| No resource limits | Memory limits, `--max-memory-per-child` | A 50 MB scan must not be able to take the host down |
| `/health` as the probe | `/ready` as the probe | `/health` stays green while Redis is down and ingestion is dead |

The frontend container also acts as the reverse proxy: it serves the static SPA and
forwards `/api` to the API (`frontend/nginx.conf`). It binds to `127.0.0.1:8080` by
default — put a TLS terminator in front of it.

**First admin in production**: rather than leaving `ADMIN_PASSWORD` in a long-running
container's environment, run the one-off script. It prompts for the password instead of
taking it as an argument, which would land in the shell history and the process table:
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml run --rm web \
  python -m scripts.create_admin --username admin --email admin@example.com
```
It is idempotent: run against an existing account, it promotes it instead of failing.

### Running Tests
```bash
pytest                      # configuration lives in pyproject.toml
pytest --cov                # with coverage
ruff check .                # lint
black --check .             # formatting
```

By default the suite runs on SQLite, which is fast and needs no external service. CI also
replays the API suite against a real PostgreSQL, because SQLite says nothing about native
`ENUM`s, `ON DELETE CASCADE` or collations. To do the same locally:
```bash
VIGIE_TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/vigie_test pytest tests/api
```
(There are currently no automated frontend tests.)

## Health probes

| Endpoint | Checks | Use it for |
|---|---|---|
| `GET /health` | Process + PostgreSQL | Liveness. A Redis outage must not restart the API |
| `GET /ready` | PostgreSQL **and** Redis | Readiness. A node that cannot ingest is taken out of rotation |

## Risk Scoring

Findings are ranked by a contextual risk score, not raw CVSS: `app/services/risk_scoring.py`
multiplies the CVSS score by the affected asset's business criticality and adds a capped
penalty once a finding is past its remediation SLA (`app/services/remediation.py`). The
resulting backlog — sorted worst-risk-first — is available via `GET /api/v1/vulnerabilities/findings`
and the `Risk Backlog` page in the frontend, where findings can be triaged (remediated, risk
accepted, or marked a false positive; the latter two require a justification note).

## Project status

- `TODO.md` — prioritised backlog (functional, then technology & deployment)
- `docs/EVALUATION_TECHNIQUE.md` — technology and deployment audit behind the `-DEP` sections
