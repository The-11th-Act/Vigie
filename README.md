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
- `app/parsers/`: ingestors for Nessus, OpenVAS and CrowdStrike Spotlight
  (standardized via typed `ParsedFinding` / `ParsedRemediation`), and
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
   admin: there is no self-registration, administrators create the accounts
   (Administration screen, `POST /api/v1/users/`). Afterwards, roles are
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
# 1. Secrets, as files (Docker secrets), never in .env:
sudo install -d -m 700 -o root -g root secrets
python3 -c "import secrets; print(secrets.token_urlsafe(48))" | sudo tee secrets/secret_key >/dev/null
python3 -c "import secrets; print(secrets.token_urlsafe(32))" | sudo tee secrets/postgres_password >/dev/null
python3 -c "import secrets; print(secrets.token_urlsafe(32))" | sudo tee secrets/redis_password >/dev/null
echo '{}' | sudo tee secrets/previous_secret_keys >/dev/null
sudo chmod 444 secrets/*
# 2. Fill in the [PROD] section of .env (POSTGRES_USER, BACKEND_CORS_ORIGINS, ...)
# 3. Start the stack with the production overlay:
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The signing key and the PostgreSQL and Redis passwords are mounted as Docker
secrets in `/run/secrets` and read through `SECRET_KEY_FILE`,
`DATABASE_PASSWORD_FILE`, `REDIS_PASSWORD_FILE` (and `POSTGRES_PASSWORD_FILE`,
`PGPASSWORD_FILE` for the database and its backup): they appear neither in
`.env` nor in `docker inspect`. The directory is root-only (0700) on the
host; the files are world-readable (0444) so that each container (postgres,
the application user, the backup) can read them once mounted. A missing
file stops the stack from starting. `VIGIE_SECRETS_DIR` points elsewhere if
needed. A value left in `.env` from before (`SECRET_KEY`...) is ignored in
production: the overlay blanks it so the secret always wins. CI checks that
no secret value shows in any container's environment or command.

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

**Concurrency and sizing**: the API is synchronous by choice. Every route is
a plain `def` run in a thread, so concurrency comes from processes
(`UVICORN_WORKERS`) and, in each, `API_THREADS` threads with a database pool
that covers them (`DB_POOL_SIZE`, `DB_MAX_OVERFLOW`). The whole stack must fit
PostgreSQL's `max_connections`; the formula, the defaults (67 of 100) and how
to scale are in [`docs/EXPLOITATION.md`](docs/EXPLOITATION.md).

**Staging and promotion**: staging is the same production overlay run from a
second checkout, with its own `.env` (`COMPOSE_PROJECT_NAME=vigie-staging`,
`FRONTEND_PORT=8081`) and its own `secrets/`. No container has a fixed name,
so both stacks can share a host without sharing a container, a network or a
volume. The built images are named after the release (`VIGIE_VERSION`):
`vigie-api` (API, migrations, worker, scheduler), `vigie-frontend`,
`vigie-backup`. Staging builds and validates a version, optionally on a
restored copy of production to rehearse its migrations; production then runs
those same images with `up -d --no-build --pull never`, never rebuilding
them. Across two hosts they go through a registry (`VIGIE_REGISTRY`). The
full path, and how to roll back a release that migrated the schema:
[`docs/PREPRODUCTION.md`](docs/PREPRODUCTION.md).

### Running Tests
```bash
pytest                         # configuration lives in pyproject.toml
pytest --cov                   # with coverage
ruff check .                   # lint
black --check .                # formatting
mypy                           # types (app/ and scripts/), blocking in CI
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
Risk Backlog, Remediation, Categorization, Assets, Vulnerabilities, Scans,
API Extracts and Administration. Which ones a
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
| `remediator` | Remediation, Dashboard, Risk Backlog, Assets, API Extracts | no |

"Deciding risk" means accepting a risk, dismissing a false positive, editing an
asset's criticality or exposure, or a CVE's score: a remediator marks fixes done
but does not decide what is acceptable.

Every route checks the module it belongs to on the server (`require_module`),
from the user as the database knows them now: a tab missing from the sidebar
does not leave its API open. Administrators always keep the Administration
module, and the last administrator cannot be demoted.

### Scopes

An administrator can limit an account to some teams (the hosts'
`owner_team`, set by `OWNER_TEAM_RULES` or by hand), plus "hosts without a
team" if wanted: Administration screen, or `PUT /api/v1/users/{id}/teams`.
The account then sees only those hosts and everything attached to them, on
every screen, export and API extract: findings, fixes, tickets, CVEs found on
them, dashboard figures and trends. Another team's object answers 404, as if
it did not exist. The sidebar names the scope.

- An account without teams sees the whole estate, as before scopes existed;
  an administrator is never scoped (promotion drops the teams).
- Actions that reach every team are refused to a scoped account: uploading a
  scan (its ingestion creates hosts and closes findings wherever it covered)
  and editing the CVE catalogue (a score moves every team's risk).
- A scoped account cannot hand a host over to another team, nor declare a
  host by hand: addresses are unique across the estate, so the conflict on a
  taken one would tell it that another team has a host there. Its hosts
  come from the scans.
- `tests/api/test_scopes.py` calls every GET route of the OpenAPI schema as a
  user scoped to one team, with another team's ids, and fails if any answer
  shows a trace of the other team: a new route cannot forget the scope.

## Dashboards and trends

The Dashboard has two views: **Posture** (where the estate stands now) and
**Trends & remediation**, where a remediator lands.

- `backlog_snapshots` keeps, per day and per owner team, the backlog as it
  stood at the end of the day (UTC): open findings, high risk (>= 7), KEV,
  overdue, open risk, new findings, and the day's fixes (count, on time,
  total days to fix, risk removed). The daily pass records yesterday; on its
  first run, or when an administrator calls
  `POST /api/v1/dashboard/snapshots/rebuild`, it also rebuilds the last 90
  days from detection and fix dates. Those days are flagged `estimated`: a
  finding reopened since, or a score that moved, is not visible from today.
- `GET /api/v1/dashboard/trends?days=90&owner_team=` returns one point per
  day, for the estate or a team (`__none__`: hosts without a team).
- `GET /api/v1/dashboard/performance?days=30&owner_team=` is computed from
  the findings: fixes, share of deadlines kept, mean time to remediate
  (overall and by business criticality), risk removed, open findings and
  risk now against the start of the period, and each team's backlog,
  fixes and tickets. Only real fixes count: an accepted risk or a false
  positive is not a remediation.

## Categorization

The **Categorization** module crosses open findings by the kind of software
they hit and the kind of host they sit on (`GET /api/v1/categorization/matrix`),
with the findings of each cell behind it (`/categorization/findings`).

- Findings fold into a fixed taxonomy (`app/services/categorization.py`):
  operating system, browser, office, runtime, database, web server, network
  device, remote access, other application. The finding's title decides
  first, in a set order ("Microsoft Edge" is a browser before it is Windows,
  ".NET" a runtime), then the scanner family; Nessus's "Windows" family,
  which holds third-party programs, counts as an application. A precise
  category is never overwritten by a vaguer one from another check.
- Hosts are crossed by type (server, workstation, network device…, inferred
  from the operating system until set by hand), environment
  (`ENVIRONMENT_RULES`, subnet -> environment), business criticality, owner
  team or Internet exposure.
- Each cell counts findings, hosts, KEV and overdue findings, and sums the
  open risk. Existing data was categorized by migration 0017; the daily pass
  catches up any finding left without a category.

## API extracts and personal tokens

The **API Extracts** module exports datasets as CSV, JSON or XLSX: findings (the
risk backlog), fixes to deploy, remediation tickets, assets and the CVE
catalogue, each only to users whose role has the module behind it.

```bash
curl -H "Authorization: Bearer $VIGIE_TOKEN" \
  "https://vigie.example.com/api/v1/extracts/findings?format=csv&kev_only=true&columns=cve_id,asset,remediation"
```

- `GET /api/v1/extracts/datasets` lists the datasets you can extract, with
  their columns and typed filters. Every other query parameter of an extract
  is a filter; an unknown or malformed one is refused (422) rather than
  silently exporting everything. `limit` cuts a preview.
- Saved extracts (`POST /api/v1/extracts/saved`) give a stable URL,
  `/api/v1/extracts/saved/{id}/run`, for a reporting tool (Power BI, Excel).
- **Personal tokens** (`POST /api/v1/extracts/tokens`) authenticate scripts
  without a password: `vigie_pat_…`, shown once, stored as a SHA-256, with a
  mandatory lifetime (at most 365 days) and 20 active per user. They are
  read-only (any other method is refused), act with their owner's current
  role and modules, and stop working when revoked, expired, or when the
  owner's role loses the API Extracts module. A password change or reset
  revokes them all: after a compromise, a token the intruder created does
  not outlive the new password.
- XLSX (`format=xlsx`) is one sheet, the column keys as a bold header kept in
  view, numbers as numbers and moments in ISO 8601 as in JSON; text is never
  read as a formula there, so it needs no neutralising. Written with the
  standard library, no dependency.
- Values starting with `= + - @` are neutralised in CSV, as in the backlog
  export; files are streamed from a temporary file.

## Webhooks

Administrators register HTTP endpoints (Administration screen, or
`/api/v1/admin/webhooks/`) that Vigie calls when something happens:

| Event | When |
|---|---|
| `scan.completed` / `scan.failed` | A scan file or a CrowdStrike sync was ingested, or failed for good |
| `ticket.created` | A remediation ticket was opened |
| `ticket.status_changed` | A ticket moved, by a person or by the scans (resolved, reopened) |
| `threat.kev_listed` | CVEs with open findings entered CISA KEV or became known for ransomware use (one event per refresh, the 100 most widespread named) |

Each event is a JSON `POST` of `{"id", "event", "created_at", "data"}`,
signed: `X-Vigie-Signature: sha256=<HMAC-SHA256 of "<X-Vigie-Timestamp>.<body>">`
under the webhook's secret (`whsec_…`, shown once, rotatable). Receivers should
check the signature, refuse old timestamps, and deduplicate on
`X-Vigie-Delivery` (the event id, unchanged across retries).

- **Outbox.** Deliveries are written in the transaction of the change they
  report and sent by the worker every `WEBHOOK_DELIVERY_INTERVAL_SECONDS`. A
  non-2xx answer or a network error is retried 6 times over about 21 hours,
  then abandoned (an admin can send it again). Redirects are not followed.
  `vigie_webhook_deliveries{status="pending"|"failed"}` in `/metrics`.
- **Targets.** HTTPS only (`WEBHOOK_ALLOW_HTTP`), no credentials in the URL,
  no private address (`WEBHOOK_ALLOW_PRIVATE_TARGETS`, for an internal
  receiver). Loopback, link-local and cloud metadata addresses are always
  refused. The address is checked at registration and at every delivery, and
  the connection is made to the address checked (the host still names the
  request, the TLS server and the certificate): a DNS answer that changes in
  between (rebinding) cannot redirect it. Behind an outbound proxy
  (`HTTPS_PROXY`, unless `NO_PROXY` exempts the host), the proxy resolves and
  connects, so pinning is then up to the proxy. An internal CA goes through
  `REQUESTS_CA_BUNDLE`.
- **One instance.** A webhook is sealed with the instance's signing key. A
  staging restored from production holds production's webhooks but cannot
  send them; "Use here" gives one a new secret, sealed to the staging.

## Ticketing: GLPI

Remediation tickets can be mirrored in GLPI, where the teams work
(`app/services/glpi.py`, on the generic `app/services/ticketing.py`: another
tool would be another connector). The worker syncs every
`GLPI_SYNC_INTERVAL_MINUTES`, or on demand from the Administration screen.

- **Export.** An active Vigie ticket with no external reference becomes a GLPI
  ticket (`GLPI_TICKET_TYPE`, request by default; `GLPI_ENTITY_ID`,
  `GLPI_CATEGORY_ID`), assigned to the owner team's group (`GLPI_TEAM_GROUPS`,
  `{"Infrastructure": 12, "Unassigned": 3}`), its urgency from the highest
  risk, its description listing the fix and the hosts. With
  `GLPI_EXPORT_UNMAPPED_TEAMS=false`, only the mapped teams get GLPI tickets.
  A ticket linked by hand (`SEC-1234`) is left alone.
- **The team works in GLPI.** Processing or pending there makes the Vigie
  ticket in progress; solved or closed makes it deployed. The scans still
  decide when it is resolved.
- **Vigie's decisions go to GLPI.** Resolved by the scans or cancelled: a
  solution is added. A finding back on a done ticket: the GLPI ticket goes
  back to processing with a followup, or is replaced by a new one when it is
  closed. GLPI closing a solved ticket on its own is not mistaken for the
  team's work.
- **Links are the connector's.** They cannot be edited by hand (409), and are
  sealed with the instance's signing key and the GLPI address: a staging
  restored from production shows production's GLPI links but never touches
  them, and a new GLPI server starts afresh. A ticket deleted in GLPI is no
  longer synced.
- **Credentials.** `GLPI_USER_TOKEN` (the API token of the account Vigie acts
  as) and `GLPI_APP_TOKEN` (the API client's, when GLPI requires one) are
  secrets: in production, files given to the worker alone by
  `docker-compose.glpi.yml`. The API holds none and reports what the last run
  saw. Setup: [`docs/EXPLOITATION.md`](docs/EXPLOITATION.md).

The connector follows GLPI's REST API (`apirest.php`, GLPI 10 and 11) and is
tested against a simulated GLPI; check it against your own instance first,
the group assignment (`_groups_id_assign`) especially.

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
threat  = ×1.3 if the CVE is in CISA KEV (×1.15 additional factor if tied to ransomware),
          otherwise its EPSS band:
          ≥ 50 % ×1.3 · ≥ 10 % ×1.15 · ≥ 1 % ×1 · < 1 % ×0.9 · unknown ×1
expo    = ×1.2 if the asset is Internet-facing
score   = base × min(1.5, threat × expo) + overdue penalty (up to +1.5)
          raised to 7.0 ("High") for a KEV entry, 7.5 for ransomware, clamped to [0, 10]
```

Without any threat context the score is exactly CVSS × criticality plus the
overdue penalty. EPSS counts by band rather than continuously, so a score moves
when a CVE changes band, not with every daily drift. Every finding returned by
the API carries `risk_factors`, the non-neutral factors behind its score,
computed by the same function that scored it.

The remediation deadline comes from `app/services/remediation.py` (14 days for
Critical, up to 180 for Low). A CVE listed in KEV gets `KEV_SLA_DAYS` (14)
instead, counted from its detection or its listing, whichever is later. Known
ransomware use gives `RANSOMWARE_SLA_DAYS` (7), counted from detection or from
the day the flag became known here (CISA may flag an entry listed years ago);
the earlier of the two windows applies, and a window only ever shortens.
Scores are stored so the backlog sorts in SQL; `app/services/rescoring.py` recomputes them whenever an input changes (CVSS,
criticality, exposure, threat context) and once a day for the whole open backlog,
since the overdue penalty grows with time alone.

The resulting backlog, worst first, is served by
`GET /api/v1/vulnerabilities/findings` and shown on the **Risk Backlog** page,
where findings are triaged as remediated, risk-accepted or false-positive.
The last two require a justification, and every transition is recorded in an
append-only audit log (`GET /api/v1/vulnerabilities/findings/{id}/history`).

New assets get their criticality, owner team, environment, and Internet
exposure from automated rules (`app/services/asset_policy.py`). Rules are evaluated
with a strict precedence:
1. **Tags**: first matching tag from `CRITICALITY_TAG_RULES`, `OWNER_TEAM_TAG_RULES`,
   `ENVIRONMENT_TAG_RULES`, or `INTERNET_FACING_TAGS`.
2. **Hostname regex**: first matching case-insensitive regex from
   `CRITICALITY_HOSTNAME_RULES`, `OWNER_TEAM_HOSTNAME_RULES`,
   `ENVIRONMENT_HOSTNAME_RULES`, or `INTERNET_FACING_HOSTNAME_PATTERNS`.
3. **Subnet CIDR**: most specific matching network prefix from `CRITICALITY_RULES`,
   `OWNER_TEAM_RULES`, `ENVIRONMENT_RULES`, or `INTERNET_FACING_SUBNETS`.
4. **Default fallback**: default criticality (`Medium`), no team, or internal.

These rules seed new assets or populate missing fields upon scan ingestion;
a value set by hand or explicitly submitted via the API is never overwritten.
Tags assigned to an asset are merged additively on subsequent scans. Tags
are case-insensitive everywhere: the rules, the `tag` filter of the asset
list and of the extracts (a whole tag, `%` and `_` literal), and an asset
keeps one spelling of each, at most 50. A malformed regex or an unknown
criticality in these rules refuses to start, rather than silently
disabling the rule.


### Threat intelligence (CISA KEV, FIRST EPSS, MSRC)

With `THREAT_INTEL_ENABLED=true`, the beat scheduler pulls both feeds daily at
`THREAT_INTEL_REFRESH_HOUR_UTC` and rescores only the findings whose score can
move (CVE entering or leaving KEV, EPSS changing band). The same task reads the
MSRC CVRF index (`THREAT_INTEL_MSRC_URL`) and fetches, as JSON, the monthly
documents of the last `THREAT_INTEL_MSRC_MONTHS` months (24 by default) that it
has not applied yet; MSRC revises recent documents daily, so a revision is
fetched again only for the last two months. They feed the KB supersedence of
the remediation plan (see *Remediation actions*). The refresh never erases
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

# MSRC: one JSON document per month (the API answers XML without the header)
#   curl -H "Accept: application/json" -o 2026-Sep.json \
#        https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2026-Sep
python -m scripts.import_threat_intel --msrc 2026-Aug.json 2026-Sep.json
```

or upload them as an admin through `POST /api/v1/threat-intel/import`
(`feed=kev`, `epss` or `msrc`). An MSRC document older than the revision
already applied, or one that would remove every supersedence its applied
revision had, is refused unless forced; the network refresh skips such a
document and applies the others. `GET /api/v1/threat-intel/status` reports
when each feed was last applied and whether it is stale
(`THREAT_INTEL_STALE_AFTER_HOURS`; 35 days at least for the monthly MSRC
documents).

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

**KB supersedence.** A scanner whose check names a fixed KB (an OpenVAS NVT, a
Spotlight remediation, a Nessus cross-reference) keeps asking for December's
cumulative update long after January's replaced it. The monthly MSRC documents
say which KB supersedes which (see *Threat intelligence* below): a link to a
superseded KB is recorded against the latest KB replacing it, at ingestion and
whenever a new document arrives, and keeps the scanner's KB in
`reported_reference` (shown as "replaces KB…" in the backlog). Only an
unambiguous replacement is applied: a KB replaced along two chains that never
meet again (a hotpatch superseded by two different updates) stays as the
scanner named it, and so does a KB older than `THREAT_INTEL_MSRC_MONTHS`.
Choosing among the KBs of several Windows versions for one host is not done:
it would need the host's exact build, which the scanners report unevenly.

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
`CROWDSTRIKE_SYNC_INTERVAL_MINUTES`. In production the client secret is a
file, `secrets/crowdstrike_client_secret`, given to the worker alone by the
`docker-compose.crowdstrike.yml` overlay: the production overlay empties the
variable, which `docker inspect` would show.

> The client is covered by tests against a simulated transport, not against a
> live Falcon tenant. If a sync returns nothing, check the response field names
> against your region's API first.

## Operations

- `GET /health` — liveness only, no dependency checks.
- `GET /ready` — readiness: PostgreSQL, Redis and the presence of Celery
  workers, reported one by one; 503 if any is unusable.
- `GET /metrics` — Prometheus exposition: HTTP volume and latency by route,
  findings ingested by source (read from the scan history, since ingestion
  runs in the worker, which serves no metrics; CrowdStrike syncs are recorded
  there like uploads), the size of the open/overdue backlog, open and
  overdue KEV findings, and `vigie_threat_feed_last_success_timestamp_seconds`
  per feed (0 until first applied — alert on `time() - value > 2 * 86400`
  for `kev` and `epss`; `msrc` is monthly when imported by hand, so give it
  a little over its 35 days of freshness, `36 * 86400`),
  and the webhook deliveries pending or abandoned. Remediation over the last
  30 complete days, from the daily snapshots as on the Trends dashboard:
  `vigie_remediated_findings_30d`, `vigie_remediation_on_time_ratio_30d` and
  `vigie_mean_time_to_remediate_seconds_30d` (NaN while nothing was fixed).
  The GLPI connector, once configured: `vigie_ticketing_tickets{state}`
  (linked, pending_export, errors, gone, foreign) and the timestamps of its
  last run and last success (a last run newer than the last success failed).
  Saturation: `vigie_http_requests_in_progress` against `vigie_api_threads`,
  `vigie_db_connections_in_use` against `vigie_db_connections_max`. In
  production the uvicorn processes write to `PROMETHEUS_MULTIPROC_DIR` and a
  scrape sums them all; without it, each scrape saw one process, and every
  switch between processes looked like a counter reset.
- Every response carries an `X-Request-ID`; an inbound one is reused, and the
  id is propagated to Celery tasks and stamped on every log line, the
  worker's and uvicorn's included (they are routed through the application's
  handler). `LOG_FORMAT=json` writes one JSON document per line (time, level,
  logger, request_id, message, extras, exception) for a log collector; the
  production stack test checks that the worker's ingestion line carries the
  id of the upload request.
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
