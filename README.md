# Crapplet DDoS Shield

On-premises DDoS detection and mitigation platform for hosting providers, ISPs and
data centres: flow-based detection, BGP RTBH (upstream and internal), MikroTik
RouterOS v7 integration, multi-upstream steering, and an operator dashboard.

> **Status: Phase 2 of 10.** This repository currently contains the design
> (Phase 1) and the foundational backend (Phase 2): database schema and migrations,
> authentication, RBAC, MFA, tamper-evident audit log, and configuration APIs for
> prefixes, routers, upstreams and BGP neighbours. **Nothing in this release talks
> to a router or announces a BGP route.** See [docs/roadmap.md](docs/roadmap.md).

## Repository layout

| Path | Contents |
|---|---|
| `docs/` | Architecture, network topology, threat model, tech stack, roadmap, API notes |
| `backend/` | Python FastAPI management API, SQLAlchemy models, Alembic migrations, tests |
| `config/` | Example network inventory (AS154950 lab values — examples only) |
| `deploy/` | systemd units, environment template, install script, nginx TLS front-end |

## Quick start (development)

```bash
# PostgreSQL 15+ running locally
createdb shield
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp ../deploy/env/shield.env.example .env      # edit SHIELD_DATABASE_URL and SHIELD_SECRET_KEY
alembic upgrade head
python -m app.cli create-admin --username admin   # prompts for password
uvicorn app.main:app --host 127.0.0.1 --port 8080
```

OpenAPI docs: `http://127.0.0.1:8080/api/docs` (disabled when `SHIELD_ENV=production`
unless `SHIELD_EXPOSE_DOCS=true`).

Run tests: `SHIELD_TEST_DATABASE_URL=postgresql+psycopg://postgres@127.0.0.1/shield_test pytest`

## Production

See [deploy/README.md](deploy/README.md). The management API binds to localhost and is
fronted by nginx with TLS on the management network only. It must never be reachable
from the public Internet.

## Safety principles (enforced in code, not just documented)

1. Only destinations inside an **explicitly authorised, enabled** protected prefix can
   ever be targeted by a mitigation action.
2. Overlapping protected prefixes and bogon/private ranges are rejected at the API.
3. Every state-changing request is written to a hash-chained audit log in the same
   transaction; the chain can be verified via `GET /api/v1/audit/verify`.
4. Destructive capabilities (RTBH, steering, router writes) are role-gated and,
   from Phase 6 onward, approval-gated and dry-run by default.
