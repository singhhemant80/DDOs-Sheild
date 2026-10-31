# Hardening and production checklist (Phase 10)

Menu: **Production readiness** shows the checks below on your installation, the setup steps that
are still open, and what has to be confirmed once on your own equipment.

## Checked by Shield (read-only)

| Area | Check | Fix |
|---|---|---|
| Accounts | every administrator uses two-factor; two-factor required for administrator logins and for approving mitigations; no shared `admin` account; not everyone an administrator | Settings → My account; Users & roles |
| Exposure | dashboard allow-list (`SHIELD_MGMT_NETS`): warns when it is open to everyone | reinstall with your office/VPN ranges when possible; keep two-factor on |
| Exposure | HTTPS certificate: self-signed or expiring | replace `/etc/crapplet-shield/tls/shield.crt` and `.key` (e.g. Let's Encrypt), reload nginx |
| Exposure | API documentation pages off in production | `SHIELD_ENV=production` |
| Data | credentials encrypted (`SHIELD_CREDENTIAL_KEY`), ClickHouse password, audit log hash chain intact, last database backup < 36 h | installer; `systemctl start shield-backup`; copy backups off the server |
| Routers | polling account read-only; write (filter) accounts only over a verified or pinned certificate | `deploy/mikrotik/shield-readonly.rsc`; pin the certificate |
| Operations | at least one alert channel, one that escalates, `dashboard_url` set, emergency stop state, which mitigation methods are still simulated | Alerts; Settings |

## Built in

- nginx: TLS only, HSTS, a strict Content-Security-Policy, `X-Content-Type-Options`,
  `Referrer-Policy`, rate limiting on the API; the dashboard limited to `SHIELD_MGMT_NETS`.
- Services run as the unprivileged `shield` user under systemd sandboxing (`ProtectSystem=strict`,
  no capabilities, system-call filter); PostgreSQL, Redis and ClickHouse listen on localhost only.
- Passwords Argon2id, short-lived JWTs with rotating refresh tokens, TOTP two-factor, login rate
  limits, roles with least privilege, hash-chained append-only audit log, nightly backups.
- Router access read-only by default; changes only through a separate, write-restricted client
  that refuses everything but Shield's own tagged rules; every change planned, approved, verified,
  reversible and audited; every mitigation method simulated until switched on.

## Before going live

1. Production readiness shows no problems.
2. Each alert channel received its test message.
3. Every item under *Confirm on your equipment* was tried once on a test address or prefix.
4. Backups are copied off the server; a restore was tested (`deploy/scripts/restore.sh`).
5. Your team knows the emergency stop and **Withdraw all**.
