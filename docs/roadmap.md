# Delivery Roadmap

| Phase | Scope | Exit criteria | Status |
|---|---|---|---|
| 1 | Requirements, architecture, threat model, network design | Docs in `docs/` reviewed | **Done** |
| 2 | DB schema + migrations, auth (Argon2id, JWT, refresh rotation, TOTP), RBAC, audit chain, config APIs | Migrations apply cleanly; test suite green; all non-public routes require auth | **Done** |
| 3 | Go flow collector (NetFlow v9/IPFIX/sFlow), SNMP counter poller, ClickHouse schema, live traffic dashboard | Synthetic flow replay shows correct per-destination pps/bps with provenance tags | **Done** (see docs/collector.md for measured accuracy) |
| 4 | Detection engine, baselines, incident management UI | Lab scenarios: UDP/SYN flood-like patterns detected; benign spike not escalated | **Done** (results in docs/detection.md) |
| 5 | MikroTik read-only integration | Discovery, BGP state, routes, counters from CCR2004 lab unit | **Done against the RouterOS protocol simulator**; CCR2004/CCR2116 hardware check pending (docs/mikrotik.md) |
| 6 | RTBH controller in simulation mode | Full workflow with dry-run plans, approvals, idempotency, restart reconciliation | **Done** (docs/mitigation.md) |
| 7 | Staging BGP with FRR, route filters, approval gates | Lab router accepts only authorised /32s; unauthorised and malformed requests rejected | **Done** with FRR lab routers (docs/bgp.md); MikroTik filter check pending |
| 8 | Controlled live mitigation, rollback, verification | Acceptance tests prove unrelated prefixes unaffected | Next |
| 9 | Selective ISP steering, local filtering, scrubbing adapter | | |
| 10 | Alerting, reporting, hardening, production checklist | | |

> Note: the master specification document was truncated partway through Phase 9; Phase 9's
> remaining text and any Phase 10 definition should be supplied before that work starts.

## Phase 7 notes

- FRR is configured only with sessions marked staging; production sessions are recorded but
  ignored until phase 8. The `bgp_speaker` setting decides between the simulated speaker and FRR.
- Verification checks that each session advertises the prefix with the discard next hop. FRR does
  not show outgoing communities per neighbour, so communities are guaranteed by the generated
  route-map and checked on the receiving side in the tests, not read back.
- IPv6 blackholes go over IPv6 sessions only (no IPv6-over-IPv4 MP-BGP in this release).

## Phase 6 notes

- Every action runs against `SimulatedSpeaker` (a route table in Redis). Phase 7 adds the FRR
  speaker behind the same interface; the controller, plans and checks do not change.
- Behind an upstream blackhole Shield stops seeing the attack (the provider drops it), so it cannot
  tell when the attack ends. A blackhole is extended at the end of its duration only while the
  attack is still visible in flow data (internal blackholes, or upstreams not included); behind a
  full upstream blackhole it usually is not, so the route is withdrawn when its duration ends. If
  the attack resumes it is detected again and proposed again, with the flap warning.
- Steering, local filtering and scrubbing strategies are Phase 9.

## Phase 5 notes

- Verified end to end against `app.mikrotik.simulator`, which speaks the RouterOS API protocol with
  RouterOS 7-shaped data. It is not a RouterOS emulator: field names and value formats on real
  hardware (especially BGP session fields across 7.x releases and L3HW properties) must be checked
  on a CCR2004/CCR2116 with `python -m app.mikrotik probe` before relying on the checks.
- The `deploy/mikrotik/*.rsc` templates have not been run on hardware yet. Run them in Safe Mode.
- Interface speed is not read from RouterOS; link utilisation uses the upstream's configured
  capacity.

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
