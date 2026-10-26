#!/usr/bin/env bash
# Nightly PostgreSQL backup. Runs as the postgres user.
# Optional encryption: set BACKUP_GPG_RECIPIENT in /etc/crapplet-shield/backup.env
set -euo pipefail

BACKUP_DIR=${BACKUP_DIR:-/var/backups/crapplet-shield}
KEEP_DAYS=${KEEP_DAYS:-14}
DB=${DB:-shield}
# shellcheck source=/dev/null
[ -f /etc/crapplet-shield/backup.env ] && . /etc/crapplet-shield/backup.env

umask 077
mkdir -p "$BACKUP_DIR"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="$BACKUP_DIR/shield-$stamp.dump"
trap 'rm -f "$out.tmp"' EXIT

pg_dump --format=custom --compress=6 --no-owner "$DB" > "$out.tmp"
pg_restore --list "$out.tmp" > /dev/null          # sanity check the archive
mv "$out.tmp" "$out"

if [ -n "${BACKUP_GPG_RECIPIENT:-}" ]; then
  gpg --batch --yes --encrypt --recipient "$BACKUP_GPG_RECIPIENT" --output "$out.gpg" "$out"
  shred -u "$out"
  out="$out.gpg"
fi

sha256sum "$out" > "$out.sha256"
find "$BACKUP_DIR" -name 'shield-*.dump*' -mtime +"$KEEP_DAYS" -delete
echo "backup written: $out"
