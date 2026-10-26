# API Guide (v1, Phase 3)

Interactive OpenAPI: `/api/v1/docs` (non-production, or `SHIELD_EXPOSE_DOCS=true`).
Raw spec: `/api/v1/openapi.json`.

## Authentication

```bash
# 1. Log in (add "totp_code" when MFA is enabled; a 401 with detail "mfa_required" means prompt for it)
curl -s -X POST https://shield/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"username":"noc1","password":"..."}'
# -> {"access_token":"...","refresh_token":"...","expires_in":900,"mfa_verified":false}

# 2. Call the API
curl -s https://shield/api/v1/prefixes -H "Authorization: Bearer $ACCESS"

# 3. Refresh before expiry (refresh tokens rotate: the old one stops working)
curl -s -X POST https://shield/api/v1/auth/refresh -d '{"refresh_token":"..."}' -H 'content-type: application/json'
```

Access tokens live 15 minutes; sessions 8 hours. Logout, password change, role change or
disabling a user revokes sessions immediately.

## Endpoint groups

| Group | Endpoints | Min. role for writes |
|---|---|---|
| Health | `GET /health` (public), `GET /health/details` | — |
| Auth | `login`, `refresh`, `logout`, `me`, `password`, `mfa/{setup,enable,disable}`, `sessions` | self |
| Users | `GET/POST /users`, `PATCH /users/{id}` | Admin |
| Prefixes | `GET/POST /prefixes`, `GET/PATCH/DELETE /prefixes/{id}`, `GET /prefixes/eligibility?target=` | Network Engineer |
| Routers | `GET/POST /routers`, `GET/PATCH/DELETE /routers/{id}` | Network Engineer |
| Upstreams | CRUD + `PUT /upstreams/{id}/rtbh-policy`, `POST …/verify`, `…/enable`, `…/disable` | Engineer (disable: NOC) |
| BGP | `GET/POST /bgp/neighbors`, `DELETE /bgp/neighbors/{id}` | Network Engineer |
| Customers | `GET/POST /customers/ips`, `DELETE /customers/ips/{id}` | Network Engineer |
| Audit | `GET /audit`, `GET /audit/verify` | — (read) |
| Settings | `GET /settings`, `PUT /settings/{key}` | Admin |
| Safety | `POST /system/emergency-stop` (NOC+), `POST /system/automation?enabled=` (Engineer+) | |
| Traffic | `GET /traffic/live`, `/traffic/history`, `/traffic/totals`, `/traffic/top`, `/traffic/destinations/{ip}`, `/traffic/interfaces`, `/collector/status` | read-only |
| Live stream | WebSocket `/ws/traffic` | read-only |

## Live traffic WebSocket

```js
const ws = new WebSocket("wss://shield/api/v1/ws/traffic");
ws.onopen = () => ws.send(JSON.stringify({ token: accessToken }));   // within 5 s
ws.onmessage = (e) => {
  const m = JSON.parse(e.data);
  // {"type":"ready"} | {"type":"traffic","data":Snapshot} | {"type":"status","available":false,"reason":"..."}
};
```

The token travels in a message, not the URL, so it never appears in proxy logs. Sessions are
re-checked every 30 s; logout or revocation closes the socket with code 4401. Max 5 sockets per user.

Every traffic value carries `provenance`: `measured`, `sampled`, `estimated` or `unavailable`.
Responses for ClickHouse-backed endpoints include `available: false` and a `reason` instead of an
error when history storage is down.

## Enabling RTBH for an upstream (required sequence)

```bash
# Store the provider's documented rules. Any PUT disables + un-verifies the policy.
curl -X PUT .../upstreams/1/rtbh-policy -d '{
  "communities": ["174:666"], "min_prefix_len": 32, "max_prefix_len": 32,
  "max_routes": 20, "documentation_ref": "https://provider.example/rtbh.pdf (ticket #4411)"}'
curl -X POST .../upstreams/1/rtbh-policy/verify     # records who verified, when
curl -X POST .../upstreams/1/rtbh-policy/enable     # refused unless verified
```

## Authorising a prefix for mitigation

```bash
curl -X PATCH .../prefixes/1 -d '{
  "ownership_verified": true,
  "ownership_evidence": "RIPE route 163.5.191.0/24 origin AS154950; RPKI ROA valid",
  "rtbh_allowed": true}'
curl ".../prefixes/eligibility?target=163.5.191.20"   # explains exactly what is and isn't allowed
```

`min_mitigation_prefix_len` defaults to /32 (/128 for IPv6): only single hosts can be targeted.
Lowering it (e.g. to /24) is an explicit, audited decision.

## Errors

| Code | Meaning |
|---|---|
| 401 | Missing/invalid/expired token, revoked session, or bad credentials (deliberately generic) |
| 403 | Authenticated but role lacks permission, or MFA required by policy |
| 409 | Conflict: overlap, duplicate, last admin, live dependencies |
| 422 | Validation: bogon prefix, host bits set, bad community/ASN, safety rule violated |
| 429 | Rate limited (`Retry-After` header) |
| 503 | Database unavailable or server-side key missing |

## Coming in later phases

`/attacks`, `/mitigation` (preview / approve / reject / withdraw with `Idempotency-Key`),
`/rtbh` (active routes, verify), `/policies`, `/notifications`, and incident events on the WebSocket.
The database tables for these already exist (see `backend/app/models.py`).
