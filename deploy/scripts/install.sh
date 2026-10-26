#!/usr/bin/env bash
# Crapplet DDoS Shield - server installer. Usually run for you by the one-command installer
# (install.sh at the repository root). Can also be run directly from an unpacked release bundle
# or a built source tree (`make`):
#
#   sudo deploy/scripts/install.sh
#
# Idempotent: re-running upgrades code and services and never overwrites secrets, users or config.
# Supported: Ubuntu 22.04 / 24.04, Debian 12. AlmaLinux / Rocky 9: best effort.
#
# Options (environment variables):
#   SHIELD_ADMIN_USER       first administrator's username (default: admin). Only used on first install.
#   SHIELD_ADMIN_PASSWORD   their password (default: generated and shown once)
#   SHIELD_MGMT_NETS        space-separated networks allowed to open the dashboard
#                           (default: "10.0.0.0/8 172.16.0.0/12 192.168.0.0/16")
#   SHIELD_SEED_EXAMPLE=1   load config/network.example.yaml (AS154950 example values) on first install
set -euo pipefail

PREFIX=/opt/crapplet-shield
ETC=/etc/crapplet-shield
SRC=$(cd "$(dirname "$0")/../.." && pwd)
CREDS_FILE=/root/crapplet-shield-admin.txt
MGMT_NETS=${SHIELD_MGMT_NETS:-"10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"}

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
as()   { local u=$1; shift; runuser -u "$u" -- "$@"; }
rand() { openssl rand -hex "${1:-24}"; }

[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
{ command -v systemctl >/dev/null && [ -d /run/systemd/system ]; } || die "systemd is required"
[ -f "$SRC/backend/pyproject.toml" ] || die "run from the Shield source tree or release bundle"
for n in $MGMT_NETS; do
  [[ $n =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || die "SHIELD_MGMT_NETS: '$n' is not an address or network"
done

# ---------------------------------------------------------------- packages
say "Installing system packages"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg openssl rsync nginx postgresql postgresql-contrib \
    redis-server >/dev/null
  PY=""
  for v in python3.13 python3.12 python3.11; do command -v "$v" >/dev/null && { PY=$v; break; }; done
  if [ -z "$PY" ]; then   # Ubuntu 22.04 ships 3.10; 3.11 is in its standard repositories
    apt-get install -y -qq python3.11 python3.11-venv python3.11-dev >/dev/null
    PY=python3.11
  fi
  apt-get install -y -qq "${PY}-venv" >/dev/null 2>&1 || apt-get install -y -qq python3-venv >/dev/null
  if ! command -v clickhouse-server >/dev/null; then
    note "adding the official ClickHouse LTS repository"
    curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
      | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=$(dpkg --print-architecture)] https://packages.clickhouse.com/deb lts main" \
      > /etc/apt/sources.list.d/clickhouse.list
    apt-get update -qq
    apt-get install -y -qq clickhouse-server clickhouse-client >/dev/null
  fi
  REDIS_UNIT=redis-server
  NGINX_SITE=/etc/nginx/sites-available/crapplet-shield.conf
  NGINX_LINK=/etc/nginx/sites-enabled/crapplet-shield.conf
elif command -v dnf >/dev/null; then
  dnf install -y -q ca-certificates curl gnupg2 openssl rsync nginx postgresql-server postgresql-contrib \
    redis python3.11 python3.11-devel
  PY=python3.11
  [ -d /var/lib/pgsql/data/base ] || postgresql-setup --initdb
  if ! command -v clickhouse-server >/dev/null; then
    dnf install -y -q yum-utils
    yum-config-manager -y --add-repo https://packages.clickhouse.com/rpm/lts/clickhouse.repo >/dev/null
    dnf install -y -q clickhouse-server clickhouse-client
  fi
  REDIS_UNIT=redis
  NGINX_SITE=/etc/nginx/conf.d/crapplet-shield.conf
  NGINX_LINK=""
else
  die "unsupported distribution (need apt or dnf)"
fi
systemctl enable --now postgresql >/dev/null 2>&1 || true
PG_MAJOR=$(as postgres psql -tAc "show server_version" | cut -d. -f1)
[ "${PG_MAJOR:-0}" -ge 14 ] || die "PostgreSQL >= 14 required (found ${PG_MAJOR:-none})"
note "$($PY --version), PostgreSQL $PG_MAJOR"

# ---------------------------------------------------------------- code
say "Installing Crapplet Shield $(cat "$SRC/VERSION" 2>/dev/null || echo "(source build)")"
id shield >/dev/null 2>&1 || useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin shield
[ -x "$SRC/collector/bin/shield-collector" ] || die "collector binaries missing (use a release bundle or run 'make')"
[ -f "$SRC/frontend/dist/index.html" ] || die "dashboard build missing (use a release bundle or run 'make')"
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/frontend" "$PREFIX/clickhouse"
rsync -a --delete --exclude '.git' --exclude '__pycache__' --exclude '.venv' --exclude 'node_modules' \
  "$SRC/backend" "$SRC/deploy" "$SRC/config" "$SRC/docs" "$PREFIX/"
chmod 0755 "$PREFIX"/deploy/scripts/*.sh
install -m 0755 "$SRC"/collector/bin/shield-* "$PREFIX/bin/"
rsync -a --delete "$SRC/frontend/dist" "$PREFIX/frontend/"
cp "$SRC"/collector/clickhouse/*.sql "$PREFIX/clickhouse/"
if [ -f "$SRC/VERSION" ]; then cp "$SRC/VERSION" "$PREFIX/VERSION"; fi

if [ -d "$PREFIX/venv" ] && ! "$PREFIX/venv/bin/python" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  rm -rf "$PREFIX/venv"   # built with a Python that is too old
fi
[ -d "$PREFIX/venv" ] || "$PY" -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q "$PREFIX/backend"

# ---------------------------------------------------------------- secrets & config
say "Configuration and secrets"
install -d -o root -g shield -m 0750 "$ETC" "$ETC/tls"
FIRST_INSTALL=0
NEW_DB_PW=""; NEW_REDIS_PW=""; NEW_CH_PW=""
if [ ! -f "$ETC/shield.env" ]; then
  FIRST_INSTALL=1
  NEW_DB_PW=$(rand 24)
  ck=$("$PREFIX/venv/bin/python" -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')
  sed -e "s|CHANGE_ME_DB_PASSWORD|$NEW_DB_PW|" -e "s|CHANGE_ME_GENERATE_A_LONG_RANDOM_VALUE|$(rand 48)|" \
      -e "s|^SHIELD_CREDENTIAL_KEY=.*|SHIELD_CREDENTIAL_KEY=$ck|" \
      "$PREFIX/deploy/env/shield.env.example" > "$ETC/shield.env"
  note "generated $ETC/shield.env (back up SHIELD_CREDENTIAL_KEY separately from database backups)"
fi
if ! grep -q '^SHIELD_REDIS_URL=' "$ETC/shield.env"; then
  NEW_REDIS_PW=$(rand 24); NEW_CH_PW=$(rand 24)
  cat >> "$ETC/shield.env" <<ENV
SHIELD_REDIS_URL=redis://:$NEW_REDIS_PW@127.0.0.1:6379/0
SHIELD_CLICKHOUSE_URL=http://127.0.0.1:8123
SHIELD_CLICKHOUSE_USER=shield
SHIELD_CLICKHOUSE_PASSWORD=$NEW_CH_PW
ENV
  printf 'SHIELD_REDIS_PASSWORD=%s\nSHIELD_CLICKHOUSE_PASSWORD=%s\n' "$NEW_REDIS_PW" "$NEW_CH_PW" > "$ETC/collector.env"
fi
chown root:shield "$ETC/shield.env" "$ETC/collector.env"
chmod 0640 "$ETC/shield.env" "$ETC/collector.env"
for f in collector snmp-poller; do
  install -o root -g shield -m 0640 "$PREFIX/deploy/collector/$f.example.json" "$ETC/$f.json.example"
done

# ---------------------------------------------------------------- PostgreSQL
say "PostgreSQL"
if ! as postgres psql -tAc "select 1 from pg_roles where rolname='shield'" | grep -q 1; then
  [ -n "$NEW_DB_PW" ] || die "shield.env exists but the 'shield' database role does not; restore it or remove $ETC/shield.env"
  as postgres psql -q -v ON_ERROR_STOP=1 -c "CREATE ROLE shield LOGIN PASSWORD '$NEW_DB_PW'"
fi
as postgres psql -tAc "select 1 from pg_database where datname='shield'" | grep -q 1 || as postgres createdb -O shield shield
run_shield() {  # run a command as the shield user with shield.env loaded
  # shellcheck source=/dev/null
  (cd "$PREFIX/backend" && set -a && . "$ETC/shield.env" && set +a && \
    runuser -u shield --preserve-environment -- "$@")
}
if as postgres psql -d shield -tAc "select 1 from information_schema.tables where table_name='alembic_version'" | grep -q 1; then
  # Upgrade: keep a database backup from just before the schema changes.
  install -d -o postgres -g postgres -m 0700 /var/backups/crapplet-shield
  if as postgres env BACKUP_DIR=/var/backups/crapplet-shield bash "$PREFIX/deploy/scripts/backup.sh" >/dev/null; then
    note "pre-upgrade database backup written to /var/backups/crapplet-shield"
  else
    die "pre-upgrade backup failed; nothing was changed in the database"
  fi
fi
run_shield "$PREFIX/venv/bin/alembic" upgrade head
note "schema up to date"

# ---------------------------------------------------------------- Redis
say "Redis (localhost only, password required)"
RCONF=/etc/redis/redis.conf; [ -f "$RCONF" ] || RCONF=/etc/redis.conf
if [ -n "$NEW_REDIS_PW" ]; then
  sed -i -e '/^#\? *requirepass /d' -e 's/^bind .*/bind 127.0.0.1 -::1/' "$RCONF"
  echo "requirepass $NEW_REDIS_PW" >> "$RCONF"
fi
systemctl enable "$REDIS_UNIT" >/dev/null 2>&1
systemctl restart "$REDIS_UNIT"

# ---------------------------------------------------------------- ClickHouse
say "ClickHouse"
systemctl enable clickhouse-server >/dev/null 2>&1
systemctl start clickhouse-server
for _ in $(seq 1 60); do curl -fsS http://127.0.0.1:8123/ping >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8123/ping >/dev/null || die "ClickHouse did not start (journalctl -u clickhouse-server)"
clickhouse-client --multiquery < "$PREFIX/clickhouse/001_schema.sql"
if [ -n "$NEW_CH_PW" ]; then
  clickhouse-client -q "CREATE USER IF NOT EXISTS shield IDENTIFIED WITH sha256_password BY '$NEW_CH_PW' HOST LOCAL"
  clickhouse-client -q "GRANT SELECT, INSERT ON shield.* TO shield"
fi
note "schema applied"

# ---------------------------------------------------------------- services
say "Services"
install -m 0644 "$PREFIX/deploy/sysctl/90-shield.conf" /etc/sysctl.d/90-shield.conf
sysctl -q --system >/dev/null 2>&1 || true
install -m 0644 "$PREFIX"/deploy/systemd/*.service "$PREFIX"/deploy/systemd/*.timer /etc/systemd/system/
install -d -o postgres -g postgres -m 0700 /var/backups/crapplet-shield
systemctl daemon-reload
systemctl enable shield-api.service shield-detector.service shield-mikrotik.service shield-mitigator.service shield-maintenance.timer shield-backup.timer >/dev/null 2>&1
systemctl restart shield-api.service shield-detector.service shield-mikrotik.service shield-mitigator.service
systemctl start shield-maintenance.timer shield-backup.timer
for f in collector snmp-poller; do
  if [ -f "$ETC/$f.json" ]; then
    systemctl enable "shield-$f.service" >/dev/null 2>&1
    systemctl restart "shield-$f.service"
  fi
done
for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1 && break; sleep 1; done
curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null || die "API did not start (journalctl -u shield-api)"
note "API healthy"

# ---------------------------------------------------------------- first administrator
say "Administrator account"
ADMIN_USER=${SHIELD_ADMIN_USER:-admin}
ADMIN_PW=${SHIELD_ADMIN_PASSWORD:-}
GENERATED_PW=0
if [ -z "$ADMIN_PW" ]; then ADMIN_PW="Sh-$(rand 9)-$(rand 3)"; GENERATED_PW=1; fi
out=$(printf '%s\n' "$ADMIN_PW" | run_shield "$PREFIX/venv/bin/python" -m app.cli create-admin \
  --username "$ADMIN_USER" --if-none --password-stdin)
note "$out"
CREATED_ADMIN=0
case "$out" in *created.*) CREATED_ADMIN=1 ;; esac
if [ "$CREATED_ADMIN" = 1 ] && [ "$GENERATED_PW" = 1 ]; then
  (umask 077 && printf 'Crapplet Shield administrator\nusername: %s\npassword: %s\n' "$ADMIN_USER" "$ADMIN_PW" > "$CREDS_FILE")
fi
if [ "$FIRST_INSTALL" = 1 ] && [ "${SHIELD_SEED_EXAMPLE:-0}" = 1 ]; then
  run_shield "$PREFIX/venv/bin/python" -m app.cli seed --file "$PREFIX/config/network.example.yaml"
fi

# ---------------------------------------------------------------- HTTPS dashboard
say "Dashboard (HTTPS)"
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ ! -f "$ETC/tls/shield.crt" ]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -days 825 -nodes -subj "/CN=$(hostname)" \
    -addext "subjectAltName=DNS:$(hostname),DNS:localhost${IP:+,IP:$IP},IP:127.0.0.1" \
    -keyout "$ETC/tls/shield.key" -out "$ETC/tls/shield.crt" >/dev/null 2>&1
  chmod 0600 "$ETC/tls/shield.key"
  note "created a self-signed certificate; replace $ETC/tls/shield.crt and .key with your own when ready"
fi
if [ ! -f "$NGINX_SITE" ] || grep -q 'managed-by: crapplet-shield-installer' "$NGINX_SITE"; then
  allow=""
  for n in $MGMT_NETS; do allow="${allow}    allow $n;\n"; done
  sed -e "s|@ALLOW@|$allow|" "$PREFIX/deploy/nginx/crapplet-shield.conf.tmpl" > "$NGINX_SITE"
  if [ -n "$NGINX_LINK" ]; then ln -sf "$NGINX_SITE" "$NGINX_LINK"; fi
fi
if ! nginx -t >/dev/null 2>&1; then nginx -t; die "nginx configuration test failed"; fi
systemctl enable nginx >/dev/null 2>&1
systemctl reload nginx 2>/dev/null || systemctl restart nginx

# ---------------------------------------------------------------- summary
say "Done"
cat <<EOF

  Dashboard:    https://${IP:-<this-server>}/
                (self-signed certificate: your browser warns until you install a real one)
  Allowed from: $MGMT_NETS
EOF
if [ "$CREATED_ADMIN" = 1 ]; then
  if [ "$GENERATED_PW" = 1 ]; then
    cat <<EOF
  Sign in as:   $ADMIN_USER
  Password:     $ADMIN_PW
                (also saved in $CREDS_FILE, root only; delete it after signing in)
EOF
  else
    echo "  Sign in as:   $ADMIN_USER with the password you provided"
  fi
  echo "  Then turn on two-factor authentication under Settings."
fi
cat <<EOF

  Next:
    1. Point your routers' flow export at this server ($PREFIX/docs/collector.md)
    2. cp $ETC/collector.json.example $ETC/collector.json, list your routers as exporters,
       then: systemctl enable --now shield-collector
    3. For exact link counters do the same with snmp-poller.json and shield-snmp-poller
    4. Host firewall: $PREFIX/deploy/README.md (this installer does not change your firewall)

  Re-run the same install command at any time to upgrade.
EOF
