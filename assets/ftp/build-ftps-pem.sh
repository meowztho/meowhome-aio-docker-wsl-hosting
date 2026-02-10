#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  echo "Usage: ./ftp/build-ftps-pem.sh <domain>"
  exit 1
fi

CRT="letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY="letsencrypt/live/${DOMAIN}/privkey.pem"
OUT="ftp/ssl/vsftpd.pem"

if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
  echo "Error: certificate files not found:"
  echo "  $CRT"
  echo "  $KEY"
  exit 1
fi

cat "$CRT" "$KEY" > "$OUT"
chmod 600 "$OUT"
echo "OK: created $OUT"
