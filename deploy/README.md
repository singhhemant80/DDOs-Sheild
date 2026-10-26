# Deployment

Target: a dedicated server or Proxmox VM on the **management VLAN**, Ubuntu Server 22.04/24.04
(AlmaLinux 9 best-effort). No Docker required.

## Install / upgrade

```bash
curl -fsSL https://raw.githubusercontent.com/singhhemant80/DDOs-Sheild/main/install.sh | sudo bash
```

The bootstrap downloads the latest release bundle for the server's CPU (amd64 or arm64) and
verifies its SHA-256, or, if no release exists, builds from source with temporary Go and Node
toolchains that are verified against their published checksums and deleted afterwards. It then
runs `deploy/scripts/install.sh`, which:

- installs PostgreSQL, Redis, ClickHouse LTS (official repository) and nginx
- creates the `shield` system user, `/opt/crapplet-shield`, and `/etc/crapplet-shield/*.env` with
  generated secrets (never overwritten on upgrade)
- runs database migrations and applies the ClickHouse schema
- creates the first administrator (only if no users exist) and prints the password once
- creates a self-signed certificate and an nginx site that only answers the management networks
- enables:

**Offline servers:** run the same command with `SHIELD_DOWNLOAD_ONLY=/tmp/shield` on a machine
with Internet access, copy `/tmp/shield` across, and run `sudo /tmp/shield/deploy/scripts/install.sh`.
The server still needs its OS package repositories (or a local mirror) for PostgreSQL, Redis,
ClickHouse and nginx.

**Releases:** change the `VERSION` file on `main` (e.g. `v0.4.0`) and push; GitHub Actions creates the tag and publishes
`crapplet-shield-vX.Y.Z-linux-{amd64,arm64}.tar.gz` with `.sha256` files.

| Unit | Purpose |
|---|---|
| `shield-api.service` | FastAPI on 127.0.0.1:8080 (hardened systemd sandbox) |
| `shield-maintenance.timer` | Nightly retention purge + audit-chain verification (unit fails if the chain is broken) |
| `shield-backup.timer` | Nightly `pg_dump` to `/var/backups/crapplet-shield`, 14-day retention, optional GPG |
| `shield-detector.service` | Attack detection: reads the collector's live stream, writes incidents (safe to restart; open incidents resume) |
| `shield-mikrotik.service` | Read-only RouterOS poller: interfaces, BGP, flow-export checks every 10/30/60 s |
| `shield-mitigator.service` | Mitigation controller: executes approved blackholes, verifies, withdraws, reconciles (simulation only in this release) |
| `shield-collector.service` | Flow collector (enabled once `/etc/crapplet-shield/collector.json` exists) |
| `shield-snmp-poller.service` | Interface counters (enabled once `snmp-poller.json` exists) |

Redis listens on localhost with a password; ClickHouse gets a `shield` user limited to the `shield`
database and to local connections. To use your own certificate, replace
`/etc/crapplet-shield/tls/shield.crt` and `shield.key` and run `systemctl reload nginx`. To edit the
nginx site yourself, delete its first line (`managed-by: ...`) and upgrades will leave it alone.

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
