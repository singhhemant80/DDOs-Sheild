# Technology Stack and Rationale

| Layer | Choice | Why | Alternatives considered |
|---|---|---|---|
| Management API | Python 3.11+, FastAPI, Pydantic v2 | Typed request validation, auto OpenAPI, async WebSockets, same language as detection/analytics | Go (faster, but slower iteration for policy/business logic) |
| ORM / migrations | SQLAlchemy 2.0, Alembic | Mature, explicit migrations, PostgreSQL-specific types (INET/CIDR) | Raw SQL |
| Config/incident DB | PostgreSQL 15+ | `inet`/`cidr` types and GiST indexes for containment (`<<=`) and overlap (`&&`) queries; exclusion constraints; transactional audit | — |
| Flow analytics | ClickHouse | Columnar, very high insert rate, TTL-based retention and materialised rollups | TimescaleDB (simpler ops, lower ingest ceiling) |
| Live state | Redis 7 | Sub-second counters, pub/sub to WebSocket workers; loss-tolerant | NATS |
| Flow collector | Go | Line-rate UDP decode, low GC pressure, single static binary; libraries for NetFlow v9/IPFIX/sFlow | Rust (equally good; Go chosen for team familiarity), goflow2 as base |
| Router integration | RouterOS API-SSL, own ~300-line client (`backend/app/mikrotik/api.py`) | Structured API, no screen-scraping. Own client so the read-only guard and certificate pinning sit in the one place every command passes through, with no dependency to audit | `librouteros`, pure SSH |
| BGP speaker | FRRouting `bgpd` | Production-grade, prefix-lists/route-maps, scriptable via `vtysh`, packaged on Ubuntu/Alma | ExaBGP (simpler API, fewer guard-rails), GoBGP |
| Password hashing | Argon2id (`argon2-cffi`) | OWASP-recommended, memory-hard | bcrypt |
| Tokens | Short-lived JWT access + opaque rotating refresh token (hashed in DB) | Stateless checks on hot path, revocable sessions | Server sessions only |
| MFA | TOTP (RFC 6238) via `pyotp` | Works offline, no cloud dependency | WebAuthn (planned) |
| Frontend | React 18, TypeScript, Vite, Tailwind, Recharts/uPlot, TanStack Query | Spec recommendation; uPlot for high-rate live series | — |
| Reverse proxy | nginx | TLS termination, IP allow-listing to mgmt network, WebSocket proxying | Caddy |
| Process mgmt | systemd | Native, no container requirement, hardening directives | Docker (optional, not required) |
| Metrics | Prometheus `/metrics` + Grafana | Standard on-prem observability | — |

## Sizing (initial)

| Deployment | vCPU | RAM | Disk | Notes |
|---|---|---|---|---|
| Lab / ≤ 10 Gb/s, 1:1024 sampling | 4 | 8 GB | 100 GB SSD | Everything on one VM |
| Production 2×10–40 Gb/s | 8–16 | 32 GB | 500 GB NVMe | ClickHouse on dedicated disk |
| Large (multiple 100G, 1:256) | Split collector/ClickHouse onto separate hosts | | | |

Flow volume, not traffic volume, drives sizing: estimate flows/s = pps ÷ sampling × flow-cache factor.
