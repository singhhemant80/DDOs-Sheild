# Delivery Roadmap

| Phase | Scope | Exit criteria | Status |
|---|---|---|---|
| 1 | Requirements, architecture, threat model, network design | Docs in `docs/` reviewed | **Done** |
| 2 | DB schema + migrations, auth (Argon2id, JWT, refresh rotation, TOTP), RBAC, audit chain, config APIs | Migrations apply cleanly; test suite green; all non-public routes require auth | **Done** |
| 3 | Go flow collector (NetFlow v9/IPFIX/sFlow), SNMP counter poller, ClickHouse schema, live traffic dashboard | Synthetic flow replay shows correct per-destination pps/bps with provenance tags | **Done** (see docs/collector.md for measured accuracy) |
| 4 | Detection engine, baselines, incident management UI | Lab scenarios: UDP/SYN flood-like patterns detected; benign spike not escalated | **Done** (results in docs/detection.md) |
| 5 | MikroTik read-only integration | Discovery, BGP state, routes, counters from CCR2004 lab unit | Next |
| 6 | RTBH controller in simulation mode | Full workflow with dry-run plans, approvals, idempotency, restart reconciliation | |
| 7 | Staging BGP with FRR, route filters, approval gates | Lab router accepts only authorised /32s; unauthorised and malformed requests rejected | |
| 8 | Controlled live mitigation, rollback, verification | Acceptance tests prove unrelated prefixes unaffected | |
| 9 | Selective ISP steering, local filtering, scrubbing adapter | | |
| 10 | Alerting, reporting, hardening, production checklist | | |

> Note: the master specification document was truncated partway through Phase 9; Phase 9's
> remaining text and any Phase 10 definition should be supplied before that work starts.

## Phase 4 notes

- Alerting (email, Telegram, webhooks) for incidents is Phase 10; incidents are visible in the
  dashboard and published on the `shield:events` Redis channel now.
- Baselines need a few weeks of traffic per hour-of-week slot before "unusual for this time" fires;
  `python -m app.detector rebuild-baselines` seeds them from ClickHouse history.

## Phase 3 notes

- RouterOS API-based counter polling moved to Phase 5 with the rest of the MikroTik adapter; SNMP
  and sFlow counter samples provide measured interface rates now.
- SNMPv3 is not implemented (v2c read-only, management VLAN only).
- The collector does not deduplicate traffic exported by two routers; export only on edge interfaces.

## What is deliberately *not* in Phase 2

- No component sends anything to a router or a BGP peer.
- `mitigation_actions`, `rtbh_routes` etc. exist in the schema so later phases have a stable
  data model, but no API in this release creates them.
