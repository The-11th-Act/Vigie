# Risk-Based Vulnerability Management (RBVM) Platform

A modular platform for assets and vulnerabilities management, scanning parsing, and task queue processing.

## Tech Stack
- **Framework**: FastAPI (Python)
- **Database**: PostgreSQL with SQLAlchemy ORM
- **Task Queue**: Celery with Redis broker
- **Migrations**: Alembic
- **Testing**: Pytest

## Architecture
- `app/core/`: Application settings, security utilities (JWT/RBAC).
- `app/db/`: DB connection & migrations.
- `app/models/`: Database models.
- `app/schemas/`: Data validation models (Pydantic).
- `app/api/`: API endpoints (versioned under `v1/`).
- `app/services/`: Pure business logic (e.g., risk scoring, remediation SLA tracking).
- `app/parsers/`: Ingestors for Nessus, OpenVAS, and CrowdStrike data.
- `app/worker/`: Celery asynchronous worker setup.

## Getting Started

### Local Setup
1. Clone the project and set up a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Or venv\\Scripts\activate on Windows
   pip install -r requirements.txt
   ```
2. Run database migrations:
   ```bash
   alembic upgrade head
   ```
3. Run the development server:
   ```bash
   uvicorn app.main:app --reload
   ```

### Running with Docker Compose
```bash
docker-compose up --build
```
