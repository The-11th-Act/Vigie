# Vigie — Risk-Based Vulnerability Management (RBVM) Platform

A modular platform for assets and vulnerabilities management, scanning parsing, and task queue processing.

## Tech Stack
- **Backend**: FastAPI (Python)
- **Frontend**: React + Vite
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Task Queue**: Celery with Redis broker
- **Migrations**: Alembic
- **Testing**: Pytest

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
   pip install -r requirements.txt
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
   npm install
   npm run dev
   ```

### Running with Docker Compose
```bash
docker-compose up --build
```
Migrations run automatically via a one-shot `migrate` service before `web` and `worker`
start. The admin account is bootstrapped automatically if `ADMIN_USERNAME` /
`ADMIN_EMAIL` / `ADMIN_PASSWORD` are set in `.env`.

### Running Tests
```bash
pytest -q
```
(There are currently no automated frontend tests.)

## Risk Scoring

Findings are ranked by a contextual risk score, not raw CVSS: `app/services/risk_scoring.py`
multiplies the CVSS score by the affected asset's business criticality and adds a capped
penalty once a finding is past its remediation SLA (`app/services/remediation.py`). The
resulting backlog — sorted worst-risk-first — is available via `GET /api/v1/vulnerabilities/findings`
and the `Risk Backlog` page in the frontend, where findings can be triaged (remediated, risk
accepted, or marked a false positive; the latter two require a justification note).
