# Deployment

Target: a dedicated server or Proxmox VM on the **management VLAN**, Ubuntu Server 22.04/24.04
(AlmaLinux 9 best-effort). No Docker required.

## Install / upgrade

```bash
git clone <this repo> && cd crapplet-ddos-shield
sudo deploy/scripts/install.sh          # idempotent; re-run to upgrade
```

The installer creates the `shield` system user, a venv in `/opt/crapplet-shield/venv`, the
`shield` PostgreSQL role and database, `/etc/crapplet-shield/shield.env` with generated secrets,
runs migrations, and enables:

| Unit | Purpose |
|---|---|
| `shield-api.service` | FastAPI on 127.0.0.1:8080 (hardened systemd sandbox) |
| `shield-maintenance.timer` | Nightly retention purge + audit-chain verification (unit fails if the chain is broken) |
| `shield-backup.timer` | Nightly `pg_dump` to `/var/backups/crapplet-shield`, 14-day retention, optional GPG |
| `shield-collector.service` | Flow collector (enabled once `/etc/crapplet-shield/collector.json` exists) |
| `shield-snmp-poller.service` | Interface counters (enabled once `snmp-poller.json` exists) |

Build first on a machine with Go 1.22+ and Node 20.19+: `make` produces `collector/bin/` and
`frontend/dist/`; the server itself needs neither toolchain. The installer also sets up Redis
(localhost, password) and ClickHouse LTS from ClickHouse's official repository, applies the
ClickHouse schema, and creates a `shield` ClickHouse user limited to the `shield` database.

## Secrets

- `SHIELD_SECRET_KEY` signs access tokens. Rotating it logs everyone out.
- `SHIELD_CREDENTIAL_KEY` encrypts router passwords, MFA secrets and notification tokens.
  **Back it up separately from the database backups.** A DB backup without this key cannot
  decrypt stored credentials; that is intentional.

## Host firewall (nftables example)

```nft
table inet shield {
  chain input {
    type filter hook input priority 0; policy drop;
    ct state established,related accept
    iif lo accept
    ip saddr { 10.255.0.0/24, 10.254.0.0/24 } tcp dport { 22, 443 } accept   # mgmt + VPN
    # Flow export from routers only
    ip saddr { 10.255.0.1, 10.255.0.2 } udp dport { 2055, 4739, 6343 } accept
    # Phase 7: BGP from routers only
    # ip saddr { 10.255.0.1, 10.255.0.2 } tcp dport 179 accept
    icmp type echo-request limit rate 10/second accept
  }
}
```

PostgreSQL, Redis and ClickHouse listen on localhost only. Do not expose 8080, 5432, 6379, 8123, 9000 or the collector's metrics port 9180.

## Rollback

1. `sudo systemctl stop shield-api`
2. `sudo deploy/scripts/restore.sh /var/backups/crapplet-shield/<backup>.dump`
3. Check out the previous release tag and re-run `install.sh`.

Alembic downgrades exist (`alembic downgrade -1`) but restoring the pre-upgrade backup is the
supported rollback path for production.

## Health checks

- `GET /api/v1/health` — unauthenticated, returns `{"status":"ok"}` or 503. Use for monitoring.
- `GET /api/v1/health/details` — authenticated; schema revision, safety switches, component status.
- `python -m app.cli verify-audit` — exit code 2 if the audit chain is broken.

## Logs

All services log to journald (`journalctl -u shield-api`). Configure retention in
`/etc/systemd/journald.conf` (e.g. `SystemMaxUse=2G`) and forward to your syslog/SIEM.
