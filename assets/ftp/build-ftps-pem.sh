#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

read_env_key() {
  local key="$1" value=""
  [[ -f .env ]] || return 0
  value="$(grep -E "^${key}=" .env | tail -n1 | cut -d= -f2- || true)"
  value="${value%\"}"; value="${value#\"}"
  value="${value%\'}"; value="${value#\'}"
  printf '%s' "$value"
}

DOMAIN="${1:-$(read_env_key FTP_CERT_DOMAIN)}"
if [[ -z "$DOMAIN" ]]; then
  echo "Usage: ./ftp/build-ftps-pem.sh <domain>" >&2
  echo "Or set FTP_CERT_DOMAIN in .env." >&2
  exit 1
fi
if [[ ! "$DOMAIN" =~ ^[A-Za-z0-9.-]+$ || "$DOMAIN" == .* || "$DOMAIN" == *. || "$DOMAIN" == *..* ]]; then
  echo "Error: invalid certificate domain: $DOMAIN" >&2
  exit 2
fi

CRT="letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY="letsencrypt/live/${DOMAIN}/privkey.pem"
OUT="ftp/ssl/vsftpd.pem"
if [[ ! -f "$CRT" || ! -f "$KEY" ]]; then
  echo "Error: certificate files not found:" >&2
  echo "  $CRT" >&2
  echo "  $KEY" >&2
  exit 1
fi
mkdir -p "$(dirname "$OUT")"
umask 077
cat "$CRT" "$KEY" > "$OUT"
chmod 600 "$OUT"
echo "OK: created $OUT"
