# Threat Model and Security Design

Method: STRIDE over the components in `architecture.md`. The system's most dangerous
capability is that it can **withdraw reachability** (RTBH, steering) and **change router
configuration**. An attacker who controls Shield can take a customer, a prefix, or the whole
network offline. Most controls below exist to prevent Shield from becoming that tool.

## 1. Assets

| Asset | Impact if compromised |
|---|---|
| Ability to announce BGP routes | Self-inflicted outage, route leak, hijack of others' space |
| RouterOS credentials | Full router takeover |
| Operator accounts / sessions | All of the above via the UI |
| Audit log integrity | Loss of accountability; covering tracks |
| Flow data | Customer traffic metadata (privacy) |
| Detection thresholds/policies | Attacker tunes them to suppress detection or trigger self-DoS |

## 2. Trust boundaries

1. Internet ↔ edge routers (untrusted traffic, including spoofed flows).
2. Routers ↔ Shield on management VLAN (flow export is unauthenticated UDP).
3. Operator browser ↔ nginx/API (authenticated HTTPS).
4. Shield ↔ external notification providers (SMTP, Telegram, webhooks).

## 3. Threats and controls

| # | STRIDE | Threat | Control | Phase |
|---|---|---|---|---|
| T1 | S | Spoofed flow packets injected to fake an attack and trigger self-blackholing | Collector accepts flows only from configured exporter IPs on the mgmt interface; host firewall restricts UDP 2055/4739/6343; detection requires corroboration with measured interface counters before auto-RTBH | 3, 4 |
| T2 | T | Attacker floods a customer IP to make Shield blackhole an *entire* /24 | Scope limit: auto actions never exceed /32 unless policy explicitly allows; impact preview lists all affected customers | 2 (schema), 6 |
| T3 | E | Operator role escalates to admin | Server-side RBAC on every route; role changes admin-only, audited, alert-on-change | 2 |
| T4 | S | Credential stuffing / brute force on login | Argon2id, per-IP and per-user rate limits, account lockout with backoff, optional TOTP MFA (required for admin by policy setting) | 2 |
| T5 | R | Operator denies having triggered an RTBH | Hash-chained audit log written in the same DB transaction as the change; actor, IP, user-agent, before/after | 2 |
| T6 | T | DB admin edits audit rows | Chain verification endpoint; `audit_log` has a trigger blocking UPDATE/DELETE; periodic anchor hash exported to syslog/remote | 2 |
| T7 | I | RouterOS creds leak via frontend or logs | Creds stored only server-side, encrypted at rest with a key from a root-only file (`SHIELD_SECRET_KEY` / credential key); never returned by API; redacted in logs | 2 (schema), 5 |
| T8 | E | Shield's RouterOS account abused to change unrelated config | Dedicated RouterOS group with minimal policies; read-only account until Phase 8; writes restricted to Shield-tagged objects; pre-change backup; RouterOS safe mode | 5, 8 |
| T9 | T | Shield's BGP session used to leak/hijack | Router-side inbound filter on the Shield session: only protected prefixes le 32 with Shield community; max-prefix limit; FRR outbound prefix-list mirrors it | 7 |
| T10 | D | Shield itself DDoSed or overloaded by flow volume | Mgmt VLAN isolation; collectors bounded queues with drop counters; detection degrades to counters-only | 3 |
| T11 | D | Shield crash mid-mitigation leaves stale blackhole | Persistent action state machine + startup reconciliation; every RTBH has a max lifetime enforced router-side where possible | 6–8 |
| T12 | T | CSRF from operator's browser | API uses bearer tokens in `Authorization` header (not cookies) → not CSRF-exposed; if cookie mode is enabled, SameSite=Strict + double-submit token | 2 |
| T13 | I | Session token theft | Short-lived access tokens (15 min), rotating refresh tokens stored hashed with revocation, bound to session row; logout revokes | 2 |
| T14 | E | Unauthenticated endpoint triggers network change | Default-deny dependency on every router except `/health` and `/auth/login`; test asserts all non-public routes return 401 without a token | 2 |
| T15 | T | Malicious policy edit disables detection or sets auto-RTBH on everything | Policy changes require Network Engineer+; changes versioned in `config_versions` and alerted | 2, 6 |
| T16 | I | Webhook/Telegram secrets leaked | Stored encrypted; masked in API responses | 2 (schema), 10 |

## 4. Roles

| Capability | Admin | Network Engineer | NOC Operator | Read-Only |
|---|---|---|---|---|
| View dashboards, incidents, audit | ✓ | ✓ | ✓ | ✓ |
| Acknowledge incidents, propose mitigation | ✓ | ✓ | ✓ | |
| Approve / execute / withdraw mitigation | ✓ | ✓ | ✓ (if policy allows) | |
| Edit prefixes, routers, upstreams, policies | ✓ | ✓ | | |
| Toggle automation / emergency stop | ✓ | ✓ | ✓ (stop only) | |
| Manage users, roles, system settings | ✓ | | | |

Emergency **stop** is deliberately available to NOC operators; **re-enabling** automation is not.

## 5. Residual risks

- Flow export over UDP cannot be authenticated; mitigated by network isolation and corroboration (T1).
- A compromised Admin account can do anything Shield can do. Mitigate with MFA, alerting and
  two-person approval for prefix-wide RTBH (configurable, Phase 6).
- Shield cannot defend against link saturation upstream of the routers.
