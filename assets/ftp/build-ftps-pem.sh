#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${MEOWHOME_PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
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
if [[ ! -s "$CRT" || ! -s "$KEY" ]]; then
  echo "Error: certificate files are missing or empty:" >&2
  echo "  $CRT" >&2
  echo "  $KEY" >&2
  exit 1
fi

# Validate the first certificate in the chain and the private key without
# exposing key material, then require their public keys to match.
if ! openssl x509 -in "$CRT" -noout >/dev/null 2>&1; then
  echo "Error: certificate file is invalid: $CRT" >&2
  exit 1
fi
if ! openssl pkey -in "$KEY" -noout -check >/dev/null 2>&1; then
  echo "Error: private key file is invalid: $KEY" >&2
  exit 1
fi
CERT_PUBLIC_KEY="$(openssl x509 -in "$CRT" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256)"
KEY_PUBLIC_KEY="$(openssl pkey -in "$KEY" -pubout -outform DER | openssl dgst -sha256)"
if [[ "$CERT_PUBLIC_KEY" != "$KEY_PUBLIC_KEY" ]]; then
  echo "Error: certificate and private key do not match." >&2
  exit 1
fi

# Anchor output to real directories so a linked ftp/ssl cannot redirect the key.
python3 - "$CRT" "$KEY" <<'PY'
import os, pathlib, secrets, sys

flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
ftp_fd = os.open("ftp", flags)
try:
    try:
        os.mkdir("ssl", mode=0o700, dir_fd=ftp_fd)
    except FileExistsError:
        pass
    ssl_fd = os.open("ssl", flags, dir_fd=ftp_fd)
    try:
        temporary = ".vsftpd.pem." + secrets.token_hex(12)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=ssl_fd)
        try:
            with os.fdopen(fd, "wb") as output:
                output.write(pathlib.Path(sys.argv[1]).read_bytes())
                output.write(pathlib.Path(sys.argv[2]).read_bytes())
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, "vsftpd.pem", src_dir_fd=ssl_fd, dst_dir_fd=ssl_fd)
        finally:
            try:
                os.unlink(temporary, dir_fd=ssl_fd)
            except FileNotFoundError:
                pass
    finally:
        os.close(ssl_fd)
finally:
    os.close(ftp_fd)
PY
echo "OK: created $OUT"
