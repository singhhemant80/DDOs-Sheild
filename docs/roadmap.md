# Delivery Roadmap

| Phase | Scope | Exit criteria | Status |
|---|---|---|---|
| 1 | Requirements, architecture, threat model, network design | Docs in `docs/` reviewed | **Done** |
| 2 | DB schema + migrations, auth (Argon2id, JWT, refresh rotation, TOTP), RBAC, audit chain, config APIs | Migrations apply cleanly; test suite green; all non-public routes require auth | **Done** |
| 3 | Go flow collector (NetFlow v9/IPFIX/sFlow), SNMP/RouterOS counter poller, ClickHouse schema, live traffic dashboard | Synthetic flow replay shows correct per-destination pps/bps with provenance tags | Next |
| 4 | Detection engine, baselines, incident management UI | Lab scenarios: UDP/SYN flood-like patterns detected; benign spike not escalated | |
| 5 | MikroTik read-only integration | Discovery, BGP state, routes, counters from CCR2004 lab unit | |
| 6 | RTBH controller in simulation mode | Full workflow with dry-run plans, approvals, idempotency, restart reconciliation | |
| 7 | Staging BGP with FRR, route filters, approval gates | Lab router accepts only authorised /32s; unauthorised and malformed requests rejected | |
| 8 | Controlled live mitigation, rollback, verification | Acceptance tests prove unrelated prefixes unaffected | |
| 9 | Selective ISP steering, local filtering, scrubbing adapter | | |
| 10 | Alerting, reporting, hardening, production checklist | | |

> Note: the master specification document was truncated partway through Phase 9; Phase 9's
> remaining text and any Phase 10 definition should be supplied before that work starts.

## What is deliberately *not* in Phase 2

- No component sends anything to a router or a BGP peer.
- `mitigation_actions`, `rtbh_routes` etc. exist in the schema so later phases have a stable
  data model, but no API in this release creates them.
