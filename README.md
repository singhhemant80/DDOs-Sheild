# Crapplet DDoS Shield

On-premises DDoS detection and mitigation platform for hosting providers, ISPs and
data centres: flow-based detection, BGP RTBH (upstream and internal), MikroTik
RouterOS v7 integration, multi-upstream steering, and an operator dashboard.

> **Status: Phase 6 of 10.** Live traffic (NetFlow v9 / IPFIX / sFlow collector, ClickHouse
> history), attack detection, read-only MikroTik RouterOS integration, and the **blackhole (RTBH)
> workflow in simulation**: preview, approval, execution, verification, withdrawal and restart
> reconciliation against a simulated BGP speaker. **Nothing in this release changes router
> configuration or announces a BGP route to anyone.** See [docs/roadmap.md](docs/roadmap.md).

## Install

On a fresh Ubuntu 22.04/24.04 or Debian 12 server (or Proxmox VM) on your management network:

```bash
curl -fsSL https://raw.githubusercontent.com/singhhemant80/DDOs-Sheild/main/install.sh | sudo bash
```

It installs everything (PostgreSQL, Redis, ClickHouse, nginx, the API, collector and dashboard),
creates an `admin` account, and prints the dashboard address and password when it finishes.
Run the same command again to upgrade. Options, e.g. your own admin name and the networks
allowed to reach the dashboard:

```bash
curl -fsSL https://raw.githubusercontent.com/singhhemant80/DDOs-Sheild/main/install.sh \
  | sudo SHIELD_ADMIN_USER=hemant SHIELD_MGMT_NETS="10.255.0.0/24 10.254.0.0/24" bash
```

All options are listed at the top of [install.sh](install.sh). Then point your routers at it:
[docs/collector.md](docs/collector.md), and give Shield read-only router access: [docs/mikrotik.md](docs/mikrotik.md).

### Update

Run the install command again. It downloads the newest release, takes a database backup to
`/var/backups/crapplet-shield` before changing the schema, migrates, and restarts the services.
Secrets, users and configuration are kept. To install or go back to a specific release:

```bash
curl -fsSL https://raw.githubusercontent.com/singhhemant80/DDOs-Sheild/main/install.sh | sudo SHIELD_VERSION=v0.6.3 bash
```

Going back to an older release does not undo database migrations; restore the pre-upgrade backup
with `deploy/scripts/restore.sh` if you need the old schema.

## Repository layout

| Path | Contents |
|---|---|
| `docs/` | Architecture, network topology, threat model, tech stack, roadmap, API notes, collector and detection guides |
| `backend/` | Python FastAPI management API, attack detector (`app/detector`), MikroTik poller (`app/mikrotik`), mitigation controller (`app/mitigation`), models, migrations, tests |
| `collector/` | Go: flow collector, SNMP poller, lab flow generator, ClickHouse schema ([docs/collector.md](docs/collector.md)) |
| `frontend/` | React + TypeScript dashboard (Vite, Tailwind, uPlot), fonts self-hosted |
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

OpenAPI docs: `http://127.0.0.1:8080/api/v1/docs` (disabled when `SHIELD_ENV=production`
unless `SHIELD_EXPOSE_DOCS=true`).

Run tests: `make test` (Go) and `SHIELD_TEST_DATABASE_URL=postgresql+psycopg://postgres@127.0.0.1/shield_test pytest`
in `backend/`. Optional: `SHIELD_TEST_REDIS_URL`, `SHIELD_TEST_CLICKHOUSE_URL` enable the live-data tests.

### Live traffic in development

```bash
make collector                                   # builds collector/bin/*
redis-server &                                   # and ClickHouse; apply collector/clickhouse/001_schema.sql
collector/bin/shield-collector -config deploy/collector/collector.example.json   # edit exporters first
collector/bin/shield-flowgen -scenario udp-flood -victim 163.5.191.20            # synthetic lab feed
cd frontend && npm ci && npm run dev             # http://127.0.0.1:5173, proxies /api to :8080
```

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
