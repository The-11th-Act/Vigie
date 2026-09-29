# Vigie — Risk-Based Vulnerability Management (RBVM) Platform

Ingests vulnerability scans, contextualises each finding with the business
criticality of the asset it affects, and presents the result as a backlog
ordered by what actually needs fixing first.

## Tech Stack
- **Backend**: FastAPI (Python)
- **Frontend**: React + Vite
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Task Queue**: Celery with Redis broker (plus Celery beat for scheduled jobs)
- **Migrations**: Alembic
- **Testing**: Pytest (backend), Vitest + Testing Library (frontend)
- **Quality**: ruff + black (configured in `pyproject.toml`), ESLint + Prettier (frontend)
- **CI**: GitHub Actions (`.github/workflows/ci.yml`)

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
- `app/parsers/`: ingestors for Nessus, OpenVAS and CrowdStrike Spotlight, and
  the CISA KEV / FIRST EPSS feed readers.
- `app/worker/`: Celery worker and scheduled tasks.
- `frontend/`: React SPA (dashboard, assets, vulnerabilities, risk backlog,
  scan upload and history).

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
4. Run the Celery worker — required for scan ingestion:
   ```bash
   celery -A app.worker.celery_app worker --loglevel=info
   ```
5. Run the scheduler — it rescores the open backlog daily (`RESCORE_HOUR_UTC`)
   and runs the periodic CrowdStrike sync when enabled:
   ```bash
   celery -A app.worker.celery_app beat --loglevel=info
   ```
6. Run the frontend:
   ```bash
   cd frontend
   npm ci        # `ci`, not `install`: installs exactly what the lockfile pins
   npm run dev
   ```

### Running with Docker Compose (development)
```bash
docker compose up --build
```
Migrations run automatically through a one-shot `migrate` service before `web`
and `worker` start. The admin account is bootstrapped when the three `ADMIN_*`
variables are set in `.env`.

> The default Postgres credentials are `vigie_user` / `vigie` (formerly
> `tvm_user` / `tvm_platform`). A development volume created under the old names
> will not match: either recreate it (`docker compose down -v`) or set the old
> values in `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` in `.env`.

This stack is **development only**: it runs `uvicorn --reload`, mounts the source tree
into the container, serves the frontend through the Vite dev server, and publishes
PostgreSQL and Redis on the host. See below for production.

### Running in production

```bash
# 1. Fill in the [PROD] section of .env (REDIS_PASSWORD, BACKEND_CORS_ORIGINS, ...)
# 2. Start the stack with the production overlay:
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The containers never read `.env` themselves (it is kept out of the image): compose
interpolates each setting from it and passes it on, through the `x-app-settings`
block of `docker-compose.yml`. A variable left unset arrives empty and the
application keeps its own default. `tests/test_deployment_config.py` fails if a
setting defined in `app/core/config.py` is not wired there.

What the overlay changes, and why:

| Development | Production | Reason |
|---|---|---|
| `uvicorn --reload`, 1 process | `--workers N`, no reload | The reloader watches the filesystem and serves a single process |
| Source mounted as a volume | No bind mount (only the shared scan-upload volume) | Otherwise the built image is never actually executed, and `USER appuser` protects nothing |
| Frontend via `npm run dev` | Built SPA served by Nginx | The Vite dev server is not a production server |
| Postgres/Redis published on the host | Internal network only | Nothing that holds data should be reachable from outside |
| Redis without a password | `--requirepass` | An exposed passwordless Redis is remote code execution |
| No resource limits | Memory limits, `--max-memory-per-child` | A 50 MB scan must not be able to take the host down |
| `/health` as the probe | `/ready` as the probe | `/health` stays green while Redis is down or no worker runs, and ingestion is dead |

The frontend container also acts as the reverse proxy: it serves the static SPA and
forwards `/api` to the API (`frontend/nginx.conf`). It binds to `127.0.0.1:8080` by
default — put a TLS terminator in front of it.

**Backups**: the `backup` service dumps the database at start-up and every
`BACKUP_INTERVAL_HOURS`, encrypted with [age](https://age-encryption.org) for
the public key `BACKUP_AGE_RECIPIENT` (the server cannot decrypt its own
backups), and prunes them after `BACKUP_RETENTION_DAYS`. It turns unhealthy when
no recent backup exists. Set-up, on-demand backups and the restore procedure are
in [`docs/SAUVEGARDE.md`](docs/SAUVEGARDE.md); CI restores a real backup into a
wiped database on every commit.

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
pytest                         # configuration lives in pyproject.toml
pytest --cov                   # with coverage
ruff check .                   # lint
black --check .                # formatting
cd frontend && npm run test    # frontend tests
cd frontend && npm run lint    # frontend lint
```

By default the suite runs on SQLite, which is fast and needs no external service. CI also
replays the API suite against a real PostgreSQL, because SQLite says nothing about native
`ENUM`s, `ON DELETE CASCADE` or collations. To do the same locally:
```bash
VIGIE_TEST_DATABASE_URL=postgresql://user:pass@localhost:5432/vigie_test pytest tests/api
```

## Modules and roles

The application is split into modules (`app/core/modules.py`): Dashboard,
Risk Backlog, Remediation, Assets, Vulnerabilities, Scans and Administration. Which ones a
user gets is decided in three layers:

1. an administrator can switch a module off for the whole instance;
2. each role has a profile, the modules it grants in their default order
   (editable on the Administration screen, or reset to the built-in default);
3. each user can reorder or hide the modules of their own profile
   (Preferences). Hiding only removes the tab: the module stays usable.

| Role | Default modules | Can decide risk |
|---|---|---|
| `admin` | all, Administration included | yes |
| `analyst` | all but Administration | yes |
| `remediator` | Remediation, Dashboard, Risk Backlog, Assets | no |

"Deciding risk" means accepting a risk, dismissing a false positive, editing an
asset's criticality or exposure, or a CVE's score: a remediator marks fixes done
but does not decide what is acceptable.

Every route checks the module it belongs to on the server (`require_module`),
from the user as the database knows them now: a tab missing from the sidebar
does not leave its API open. Administrators always keep the Administration
module, and the last administrator cannot be demoted.

## Health probes

| Endpoint | Checks | Use it for |
|---|---|---|
| `GET /health` | Process + PostgreSQL | Liveness. A Redis outage must not restart the API |
| `GET /ready` | PostgreSQL **and** Redis | Readiness. A node that cannot ingest is taken out of rotation |

## Risk Scoring

A raw CVSS score describes a vulnerability in the abstract; risk is what it
means *here*, and how likely it is to be exploited. `app/services/risk_scoring.py`
computes:

```
base    = CVSS × business criticality        (Critical ×1.5, High ×1.2, Medium ×1, Low ×0.7)
threat  = ×1.3 if the CVE is in CISA KEV, otherwise its EPSS band:
          ≥ 50 % ×1.3 · ≥ 10 % ×1.15 · ≥ 1 % ×1 · < 1 % ×0.9 · unknown ×1
expo    = ×1.2 if the asset is Internet-facing
score   = base × min(1.5, threat × expo) + overdue penalty (up to +1.5)
          raised to 7.0 ("High") for a KEV entry, clamped to [0, 10]
```

Without any threat context the score is exactly CVSS × criticality plus the
overdue penalty. EPSS counts by band rather than continuously, so a score moves
when a CVE changes band, not with every daily drift. Every finding returned by
the API carries `risk_factors`, the non-neutral factors behind its score,
computed by the same function that scored it.

The remediation deadline comes from `app/services/remediation.py` (14 days for
Critical, up to 180 for Low). A CVE listed in KEV gets `KEV_SLA_DAYS` (14)
instead, counted from its detection or its listing, whichever is later; the
window only ever shortens. Scores are stored so the backlog sorts in SQL;
`app/services/rescoring.py` recomputes them whenever an input changes (CVSS,
criticality, exposure, threat context) and once a day for the whole open backlog,
since the overdue penalty grows with time alone.

The resulting backlog, worst first, is served by
`GET /api/v1/vulnerabilities/findings` and shown on the **Risk Backlog** page,
where findings are triaged as remediated, risk-accepted or false-positive.
The last two require a justification, and every transition is recorded in an
append-only audit log (`GET /api/v1/vulnerabilities/findings/{id}/history`).

New assets get their criticality from `CRITICALITY_RULES`, a subnet-to-level
map where the most specific prefix wins, and their exposure from
`INTERNET_FACING_SUBNETS`. Both only seed new assets: a value set by hand is
never overwritten by a later scan.

### Threat intelligence (CISA KEV, FIRST EPSS)

With `THREAT_INTEL_ENABLED=true`, the beat scheduler pulls both feeds daily at
`THREAT_INTEL_REFRESH_HOUR_UTC` and rescores only the findings whose score can
move (CVE entering or leaving KEV, EPSS changing band). The refresh never erases
good data: a feed that fails or does not parse changes nothing and its error is
recorded; an older snapshot, or a KEV catalogue under 90 % of the previous one
(what a truncated download looks like), is refused unless forced. Proxies and
internal CAs go through `HTTPS_PROXY` / `NO_PROXY` / `REQUESTS_CA_BUNDLE`.

Without outbound Internet access, leave it disabled and import the files:

```bash
# Download elsewhere:
#   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
#   https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
python -m scripts.import_threat_intel --kev kev.json --epss epss_scores-current.csv.gz
```

or upload them as an admin through `POST /api/v1/threat-intel/import`.
`GET /api/v1/threat-intel/status` reports when each feed was last applied and
whether it is stale (`THREAT_INTEL_STALE_AFTER_HOURS`).

The KEV catalogue is published by CISA; EPSS scores are published by
[FIRST](https://www.first.org/epss/). Check their terms of use for your context.

## Scan Ingestion

Uploads are staged on a volume shared between the API and the worker
(`SCAN_UPLOAD_DIR`); only the path travels through the broker. Every upload is
recorded as a `ScanJob` — author, date, outcome and counters — listed by
`GET /api/v1/scans/` and readable only by its author (or an admin).

A finding that a source stops reporting is closed automatically after
`AUTO_REMEDIATE_AFTER_MISSES` consecutive scans without it, so a single partial
scan cannot wrongly clear the backlog. For file uploads, a miss only counts on a
host the file actually covered — including hosts that came back clean — so a
scan of one subnet never closes another subnet's findings. The CrowdStrike sync
reports the whole inventory each time, so its sweep spans the source.

Misses are counted per source (`finding_detections`): a finding reported by
Nessus and OpenVAS closes only once both have stopped reporting it, and each
finding lists the scanners that see it.

### Remediation actions

Remediation teams work in patches, not CVEs, so every finding also records
what fixes it (`remediation_actions`, linked per finding and per source):

- a Microsoft update is keyed by its KB (`KB5034441`), so every plugin and
  every scanner asking for it lands on the same action. For Nessus rollups, the
  KB comes from the plugin output, which names the update *this* host lacks,
  rather than from the cross-references, which list every Windows version's;
- anything else is keyed by the scanner's check (`nessus:<plugin id>`,
  `openvas:<oid>`), with the vendor's solution and, per host, the installed and
  fixed versions.

Each source's links are replaced when it reports the finding again, so a
superseded cumulative update disappears once the scanner asks for the next one.
Findings carry them as `remediations`, and the CSV export adds `remediation`
and `fixed_version` columns.

The **Remediation** module folds the open backlog per fix
(`GET /api/v1/remediation/actions`): each KB or fix with the hosts still
missing it, the findings and distinct CVEs it closes, KEV and overdue counts,
the nearest deadline, and the sum of their risk, which orders the list. A
finding linked to the same fix by two scanners counts once. Open findings no
scanner gave a fix for are counted apart. Each fix lists its hosts with their
versions and CVEs (`/actions/{id}`), exportable as CSV for a deployment tool
(`/actions/{id}/hosts.csv`).

**Tickets.** A fix is ticketed per team owning the hosts
(`POST /remediation/actions/{id}/tickets`): each asset has an `owner_team`,
set by hand or from `OWNER_TEAM_RULES` (subnet -> team, most specific
prefix wins; applied to new hosts and to hosts without a team). The team
moves its ticket to *in progress* or *deployed*; the scans decide the rest:

- a ticket is **resolved** once every finding it holds is closed (fixed,
  accepted or dismissed), and **reopens** if one comes back;
- a new finding of the same fix on the same team's hosts joins the team's
  open ticket;
- cancelling (deciding not to fix) is an analyst's call and needs a note; the
  findings of a cancelled ticket can go into a new one.

Tickets follow the findings after every ingestion, triage decision, reopened
risk acceptance and daily pass, with an append-only history. Each ticket
exports its hosts as CSV and records an external reference and link, ready
for a Jira, ServiceNow or GLPI connector. Scan files are not kept after ingestion, so
findings imported before this existed gain their remediation on their next scan.

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
  findings ingested by source, the size of the open/overdue backlog, open and
  overdue KEV findings, and `vigie_threat_feed_last_success_timestamp_seconds`
  per feed (0 until first applied — alert on `time() - value > 2 * 86400`).
- Every response carries an `X-Request-ID`; an inbound one is reused, and the
  id is propagated to Celery tasks and stamped on every log line.
- Failed logins are throttled per IP and per account (`LOGIN_MAX_ATTEMPTS`,
  `LOGIN_LOCKOUT_SECONDS`). Access tokens can be revoked via
  `POST /api/v1/auth/logout`; refresh tokens rotate on use.
- The web app keeps no token in `localStorage`: it logs in with
  `X-Session-Mode: cookie` and the API answers with HttpOnly, `SameSite=Strict`
  cookies (`Secure` in production, `AUTH_COOKIE_SECURE`). A request
  authenticated by cookie that changes something must echo the `vigie_csrf`
  cookie in `X-CSRF-Token`. API clients and scripts keep using
  `Authorization: Bearer`, unchanged.
- Tokens carry the id of their signing key (`kid`): the key can be rotated
  without logging anyone out, see
  [`docs/EXPLOITATION.md`](docs/EXPLOITATION.md).

## Project status

- `TODO.md` — prioritised backlog (functional, then technology & deployment)
- `docs/EVALUATION_TECHNIQUE.md` — technology and deployment audit behind the `-DEP` sections
- `docs/MAINTENABILITE.md` — maintainability review

## License

Copyright (C) 2026 The-11th-Act.

Licensed under the GNU Affero General Public License, version 3 or later
(`AGPL-3.0-or-later`). See [LICENSE](LICENSE). In particular, if you run a
modified version of this software as a network service, section 13 requires you
to offer its source to the users of that service.
