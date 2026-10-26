#!/usr/bin/env bash
# Crapplet DDoS Shield installer (Ubuntu 22.04/24.04; AlmaLinux 9 best-effort).
# Idempotent: safe to re-run for upgrades. Run from the repository root as root, after
# building artifacts with `make` (collector/bin/* and frontend/dist) on a build machine.
set -euo pipefail

PREFIX=/opt/crapplet-shield
ETC=/etc/crapplet-shield
SRC=$(cd "$(dirname "$0")/../.." && pwd)

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

echo "==> Packages"
if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-dev postgresql postgresql-contrib nginx gnupg curl \
    redis-server rsync >/dev/null
  if ! command -v clickhouse-server >/dev/null; then
    echo "    adding the official ClickHouse LTS apt repository"
    curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
      | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=$(dpkg --print-architecture)] https://packages.clickhouse.com/deb lts main" \
      > /etc/apt/sources.list.d/clickhouse.list
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq clickhouse-server clickhouse-client >/dev/null
  fi
elif command -v dnf >/dev/null; then
  dnf install -y -q python3.11 postgresql-server postgresql-contrib nginx gnupg2 redis rsync
  command -v clickhouse-server >/dev/null || { echo "Install ClickHouse LTS first: https://clickhouse.com/docs/en/install"; exit 1; }
  [ -d /var/lib/pgsql/data/base ] || postgresql-setup --initdb
  systemctl enable --now postgresql
fi
PG_MAJOR=$(psql --version | awk '{print $3}' | cut -d. -f1)
[ "$PG_MAJOR" -ge 14 ] || { echo "PostgreSQL >= 14 required (found $PG_MAJOR)"; exit 1; }

echo "==> Service user"
id shield >/dev/null 2>&1 || useradd --system --home-dir "$PREFIX" --shell /usr/sbin/nologin shield

echo "==> Code"
install -d -o root -g root -m 0755 "$PREFIX"
rsync -a --delete --exclude '.git' --exclude '__pycache__' --exclude '.venv' "$SRC/backend" "$SRC/deploy" "$SRC/config" "$PREFIX/"
chmod 0755 "$PREFIX"/deploy/scripts/*.sh
install -d -m 0755 "$PREFIX/bin" "$PREFIX/frontend" "$PREFIX/clickhouse"
if ls "$SRC"/collector/bin/shield-collector >/dev/null 2>&1; then
  install -m 0755 "$SRC"/collector/bin/shield-* "$PREFIX/bin/"
else
  echo "    WARNING: collector/bin is empty - run 'make collector' first; collector not installed"
fi
cp "$SRC"/collector/clickhouse/*.sql "$PREFIX/clickhouse/"
if [ -f "$SRC/frontend/dist/index.html" ]; then
  rsync -a --delete "$SRC/frontend/dist" "$PREFIX/frontend/"
else
  echo "    WARNING: frontend/dist missing - run 'make frontend' first; dashboard not installed"
fi

echo "==> Python venv"
[ -d "$PREFIX/venv" ] || python3 -m venv "$PREFIX/venv"
"$PREFIX/venv/bin/pip" install -q --upgrade pip
"$PREFIX/venv/bin/pip" install -q "$PREFIX/backend"

echo "==> Config"
install -d -o root -g shield -m 0750 "$ETC" "$ETC/tls"
if [ ! -f "$ETC/shield.env" ]; then
  dbpw=$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')
  sk=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
  ck=$("$PREFIX/venv/bin/python" -c 'from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())')
  sed -e "s|CHANGE_ME_DB_PASSWORD|$dbpw|" -e "s|CHANGE_ME_GENERATE_A_LONG_RANDOM_VALUE|$sk|" \
      -e "s|^SHIELD_CREDENTIAL_KEY=.*|SHIELD_CREDENTIAL_KEY=$ck|" \
      "$PREFIX/deploy/env/shield.env.example" > "$ETC/shield.env"
  chown root:shield "$ETC/shield.env"; chmod 0640 "$ETC/shield.env"
  echo "    generated $ETC/shield.env — BACK UP SHIELD_CREDENTIAL_KEY separately"
  NEW_DB_PW=$dbpw
fi
if ! grep -q '^SHIELD_REDIS_URL=' "$ETC/shield.env"; then
  rpw=$(python3 -c 'import secrets;print(secrets.token_hex(24))')
  cpw=$(python3 -c 'import secrets;print(secrets.token_hex(24))')
  cat >> "$ETC/shield.env" <<ENV
SHIELD_REDIS_URL=redis://:$rpw@127.0.0.1:6379/0
SHIELD_CLICKHOUSE_URL=http://127.0.0.1:8123
SHIELD_CLICKHOUSE_USER=shield
SHIELD_CLICKHOUSE_PASSWORD=$cpw
ENV
  printf 'SHIELD_REDIS_PASSWORD=%s\nSHIELD_CLICKHOUSE_PASSWORD=%s\n' "$rpw" "$cpw" > "$ETC/collector.env"
  chown root:shield "$ETC/collector.env"; chmod 0640 "$ETC/collector.env"
  NEW_REDIS_PW=$rpw
  NEW_CH_PW=$cpw
fi
for f in collector snmp-poller; do
  [ -f "$ETC/$f.json" ] || install -o root -g shield -m 0640 "$PREFIX/deploy/collector/$f.example.json" "$ETC/$f.json.example"
done

echo "==> Redis (localhost only, password required)"
RCONF=/etc/redis/redis.conf; [ -f "$RCONF" ] || RCONF=/etc/redis.conf
if [ -n "${NEW_REDIS_PW:-}" ]; then
  sed -i -e 's/^#\? *requirepass .*/requirepass '"$NEW_REDIS_PW"'/' -e 's/^bind .*/bind 127.0.0.1 -::1/' "$RCONF"
  grep -q '^requirepass' "$RCONF" || echo "requirepass $NEW_REDIS_PW" >> "$RCONF"
fi
systemctl enable --now redis-server 2>/dev/null || systemctl enable --now redis
systemctl restart redis-server 2>/dev/null || systemctl restart redis

echo "==> ClickHouse"
systemctl enable --now clickhouse-server
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8123/ping >/dev/null 2>&1 && break; sleep 1; done
clickhouse-client --multiquery < "$PREFIX/clickhouse/001_schema.sql"
if [ -n "${NEW_CH_PW:-}" ]; then
  clickhouse-client -q "CREATE USER IF NOT EXISTS shield IDENTIFIED WITH sha256_password BY '$NEW_CH_PW' HOST LOCAL"
  clickhouse-client -q "GRANT SELECT, INSERT ON shield.* TO shield"
fi

echo "==> Kernel UDP buffers"
install -m 0644 "$PREFIX/deploy/sysctl/90-shield.conf" /etc/sysctl.d/90-shield.conf
sysctl -q --system || true

echo "==> Database"
if ! sudo -u postgres psql -tAc "select 1 from pg_roles where rolname='shield'" | grep -q 1; then
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE ROLE shield LOGIN PASSWORD '${NEW_DB_PW:?existing shield.env but no shield role; create it manually}'"
fi
sudo -u postgres psql -tAc "select 1 from pg_database where datname='shield'" | grep -q 1 || \
  sudo -u postgres createdb -O shield shield

echo "==> Migrations"
( cd "$PREFIX/backend" && set -a && . "$ETC/shield.env" && set +a && \
  sudo -E -u shield "$PREFIX/venv/bin/alembic" upgrade head )

echo "==> systemd"
install -m 0644 "$PREFIX"/deploy/systemd/*.service "$PREFIX"/deploy/systemd/*.timer /etc/systemd/system/
install -d -o postgres -g postgres -m 0700 /var/backups/crapplet-shield
systemctl daemon-reload
systemctl enable --now shield-api.service shield-maintenance.timer shield-backup.timer
systemctl restart shield-api.service
for f in collector snmp-poller; do
  if [ -f "$ETC/$f.json" ] && [ -x "$PREFIX/bin/shield-$f" ]; then
    systemctl enable "shield-$f.service"; systemctl restart "shield-$f.service"
  fi
done

echo "==> Health"
for i in $(seq 1 20); do
  curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null 2>&1 && { echo "    API healthy"; break; }
  sleep 1
done

cat <<EOF

Installed. Next steps:
  1. Create the first administrator:
       cd $PREFIX/backend && sudo -u shield env \$(grep -v '^#' $ETC/shield.env | xargs) \\
         $PREFIX/venv/bin/python -m app.cli create-admin --username <you>
  2. Put a TLS certificate in $ETC/tls/, edit deploy/nginx/crapplet-shield.conf (listen address,
     allow-list) and install it into /etc/nginx/sites-enabled/.
  3. Host firewall: allow 443/tcp from management networks only (see deploy/README.md).
  4. Optionally seed inventory: python -m app.cli seed --file $PREFIX/config/network.example.yaml
  5. Flow collection: copy $ETC/collector.json.example to $ETC/collector.json, list your routers
     as exporters, then: systemctl enable --now shield-collector   (router setup: docs/collector.md)
  6. Interface counters: same for snmp-poller.json, then: systemctl enable --now shield-snmp-poller
EOF
