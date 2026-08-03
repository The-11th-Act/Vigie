# Vigie — Risk-Based Vulnerability Management (RBVM) Platform

Ingests vulnerability scans, contextualises each finding with the business
criticality of the asset it affects, and presents the result as a backlog
ordered by what actually needs fixing first.

## Tech Stack
- **Backend**: FastAPI (Python)
- **Frontend**: React + Vite
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Task Queue**: Celery with Redis broker (plus Celery beat for scheduled pulls)
- **Migrations**: Alembic
- **Testing**: Pytest (backend), Vitest + Testing Library (frontend)

## Architecture
- `app/core/`: settings, security (JWT/RBAC), admin bootstrap, login throttling,
  token revocation, logging and metrics.
- `app/db/`: DB connection & migrations.
- `app/models/`: database models.
- `app/schemas/`: data validation models (Pydantic).
- `app/api/`: API endpoints, versioned under `v1/` (`auth`, `users`, `assets`,
  `vulnerabilities`, `scans`, `dashboard`).
- `app/services/`: business logic — risk scoring, remediation SLA, ingestion,
  asset policy.
- `app/parsers/`: ingestors for Nessus, OpenVAS and CrowdStrike Spotlight.
- `app/worker/`: Celery worker and scheduled tasks.
- `frontend/`: React SPA (dashboard, assets, vulnerabilities, risk backlog,
  scan upload).

## Getting Started

### Prerequisites
1. Copy `.env.example` to `.env`.
2. Generate a `SECRET_KEY` — the app refuses to start in production without a
   strong one, and warns in development:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
3. (Optional but recommended) Set `ADMIN_USERNAME`, `ADMIN_EMAIL` and
   `ADMIN_PASSWORD`. When all three are set, that account is created — or
   promoted — to admin on startup. This is the only way to obtain a first
   admin: self-registration always creates an `analyst`. Afterwards, roles are
   managed through `PATCH /api/v1/users/{id}/role` (admin only).

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
4. Run the Celery worker — required for scan ingestion:
   ```bash
   celery -A app.worker.celery_app worker --loglevel=info
   ```
5. Run the scheduler, only needed for the periodic CrowdStrike sync:
   ```bash
   celery -A app.worker.celery_app beat --loglevel=info
   ```
6. Run the frontend:
   ```bash
   cd frontend
   npm ci
   npm run dev
   ```

### Running with Docker Compose
```bash
docker-compose up --build
```
Migrations run automatically through a one-shot `migrate` service before `web`
and `worker` start. The admin account is bootstrapped when the three `ADMIN_*`
variables are set in `.env`.

> The default Postgres credentials remain `tvm_user` / `tvm_platform` for
> compatibility with existing volumes, even though the project is now called
> Vigie. Override `POSTGRES_USER` / `POSTGRES_DB` for a fresh deployment.

### Running Tests
```bash
pytest -q                      # backend
cd frontend && npm run test    # frontend
cd frontend && npm run lint    # frontend lint
```

## Risk Scoring

A raw CVSS score describes a vulnerability in the abstract; risk is what it
means *here*. `app/services/risk_scoring.py` multiplies CVSS by the affected
asset's business criticality (Critical ×1.5 … Low ×0.7) and adds a capped
penalty once a finding is past the remediation deadline set by
`app/services/remediation.py` (14 days for Critical, up to 180 for Low).

The resulting backlog, worst first, is served by
`GET /api/v1/vulnerabilities/findings` and shown on the **Risk Backlog** page,
where findings are triaged as remediated, risk-accepted or false-positive.
The last two require a justification, and every transition is recorded in an
append-only audit log (`GET /api/v1/vulnerabilities/findings/{id}/history`).

New assets get their criticality from `CRITICALITY_RULES`, a subnet-to-level
map where the most specific prefix wins.

## Scan Ingestion

Uploads are staged on a volume shared between the API and the worker
(`SCAN_UPLOAD_DIR`); only the path travels through the broker. Every upload is
recorded as a `ScanJob` — author, date, outcome and counters — listed by
`GET /api/v1/scans/` and readable only by its author (or an admin).

A finding that a source stops reporting is closed automatically after
`AUTO_REMEDIATE_AFTER_MISSES` consecutive scans without it, so a single partial
scan cannot wrongly clear the backlog.

### CrowdStrike Falcon Spotlight
Set `CROWDSTRIKE_CLIENT_ID` / `CROWDSTRIKE_CLIENT_SECRET`, adjust
`CROWDSTRIKE_BASE_URL` to your region, and set `CROWDSTRIKE_SYNC_ENABLED=true`;
the beat scheduler then pulls open findings every
`CROWDSTRIKE_SYNC_INTERVAL_MINUTES`.

> The client is covered by tests against a simulated transport, not against a
> live Falcon tenant. If a sync returns nothing, check the response field names
> against your region's API first.

## Operations

- `GET /health` — liveness only, no dependency checks.
- `GET /ready` — readiness: PostgreSQL, Redis and the presence of Celery
  workers, reported one by one; 503 if any is unusable.
- `GET /metrics` — Prometheus exposition: HTTP volume and latency by route,
  findings ingested by source, and the size of the open/overdue backlog.
- Every response carries an `X-Request-ID`; an inbound one is reused, and the
  id is propagated to Celery tasks and stamped on every log line.
- Failed logins are throttled per IP and per account (`LOGIN_MAX_ATTEMPTS`,
  `LOGIN_LOCKOUT_SECONDS`). Access tokens can be revoked via
  `POST /api/v1/auth/logout`; refresh tokens rotate on use.

## License

Copyright (C) 2026 The-11th-Act.

Licensed under the GNU Affero General Public License, version 3 or later
(`AGPL-3.0-or-later`). See [LICENSE](LICENSE). In particular, if you run a
modified version of this software as a network service, section 13 requires you
to offer its source to the users of that service.
