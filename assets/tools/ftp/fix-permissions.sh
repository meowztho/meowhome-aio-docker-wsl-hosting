#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "Fixing webroot permissions (host)..."

UID_NOW="$(id -u)"
GID_NOW="$(id -g)"

sudo chown -R "${UID_NOW}:${GID_NOW}" htdocs/ 2>/dev/null || true
sudo find htdocs/ -type d -exec chmod 2775 {} \; 2>/dev/null || true
sudo find htdocs/ -type f -exec chmod 664 {} \; 2>/dev/null || true

docker exec meowhome_ftp chown root:root /etc/vsftpd/vsftpd.conf 2>/dev/null || true
docker exec meowhome_ftp chmod 600 /etc/vsftpd/vsftpd.conf 2>/dev/null || true

echo "Done. Restarting FTP..."
docker compose restart ftp
