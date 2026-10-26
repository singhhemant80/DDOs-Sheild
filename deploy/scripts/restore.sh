#!/usr/bin/env bash
# Restore a backup into the shield database. Stops the API first.
# Usage: sudo deploy/scripts/restore.sh /var/backups/crapplet-shield/shield-YYYYmmddTHHMMSSZ.dump[.gpg]
set -euo pipefail
file=${1:?usage: restore.sh <backup file>}
DB=${DB:-shield}

if [ -f "$file.sha256" ]; then (cd "$(dirname "$file")" && sha256sum -c "$(basename "$file").sha256"); fi

tmp=$(mktemp)
trap 'shred -u "$tmp" 2>/dev/null || rm -f "$tmp"' EXIT
case "$file" in
  *.gpg) gpg --batch --decrypt --output "$tmp" "$file" ;;
  *)     cp "$file" "$tmp" ;;
esac
chown postgres "$tmp"

read -r -p "This REPLACES database '$DB'. Type the database name to continue: " ans
[ "$ans" = "$DB" ] || { echo "aborted"; exit 1; }

systemctl stop shield-api.service || true
sudo -u postgres dropdb --if-exists "${DB}_pre_restore"
sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER DATABASE \"$DB\" RENAME TO \"${DB}_pre_restore\""
sudo -u postgres createdb -O shield "$DB"
sudo -u postgres pg_restore --no-owner --role=shield -d "$DB" "$tmp"
systemctl start shield-api.service
echo "Restored. Previous database kept as ${DB}_pre_restore; drop it once verified."
echo "Run: sudo -u shield /opt/crapplet-shield/venv/bin/python -m app.cli verify-audit"
