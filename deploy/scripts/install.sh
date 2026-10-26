#!/usr/bin/env bash
# Crapplet DDoS Shield — Phase 2 installer (Ubuntu 22.04/24.04; AlmaLinux 9 best-effort).
# Idempotent: safe to re-run for upgrades. Run from the repository root as root.
set -euo pipefail

PREFIX=/opt/crapplet-shield
ETC=/etc/crapplet-shield
SRC=$(cd "$(dirname "$0")/../.." && pwd)

[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }

echo "==> Packages"
if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv python3-dev postgresql postgresql-contrib nginx gnupg >/dev/null
elif command -v dnf >/dev/null; then
  dnf install -y -q python3.11 postgresql-server postgresql-contrib nginx gnupg2
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
EOF
