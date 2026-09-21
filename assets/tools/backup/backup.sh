#!/usr/bin/env bash
set -euo pipefail

# Backups contain database contents, .env secrets and private keys.
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLED_PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
if [[ -n "${MEOWHOME_PROJECT_DIR:-}" ]]; then
  PROJECT_DIR="${MEOWHOME_PROJECT_DIR}"
elif [[ -f "${INSTALLED_PROJECT_DIR}/docker-compose.yml" ]]; then
  PROJECT_DIR="${INSTALLED_PROJECT_DIR}"
else
  PROJECT_DIR="$HOME/meowhome"
fi
BACKUP_DIR="${PROJECT_DIR}/backups"
TS="$(date +%Y%m%d-%H%M%S)"
mkdir -p "${BACKUP_DIR}"
WORK="$(mktemp -d "${BACKUP_DIR}/.work-${TS}-XXXXXX")"
OUT="${BACKUP_DIR}/meowhome-backup-${TS}.tar.gz"
WITH_HTDOCS="${1:-}"

if [[ -n "${WITH_HTDOCS}" && "${WITH_HTDOCS}" != "--with-htdocs" ]]; then
  echo "Usage: $0 [--with-htdocs]" >&2
  exit 2
fi

cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    echo "ERROR: Docker Compose nicht gefunden." >&2
    return 127
  fi
}

read_env_value() {
  local key="$1" value=""
  [[ -f "${PROJECT_DIR}/.env" ]] || return 0
  value="$(grep -E "^${key}=" "${PROJECT_DIR}/.env" | tail -n1 | cut -d= -f2- || true)"
  if [[ ${#value} -ge 2 ]]; then
    if [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]] || [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi
  printf '%s' "$value"
}

if ! docker inspect meowhome_db >/dev/null 2>&1; then
  echo "ERROR: Container 'meowhome_db' nicht gefunden." >&2
  exit 1
fi

mkdir -p "${WORK}/db"
echo "[backup] Ziel: ${OUT}"
echo "[backup] DB dump (all databases incl users/grants)..."

DUMP_CMD="mariadb-dump"
if ! docker exec meowhome_db sh -lc "command -v mariadb-dump >/dev/null 2>&1"; then
  DUMP_CMD="mysqldump"
fi
DB_ROOT_PASSWORD="$(read_env_value DB_ROOT_PASSWORD)"
docker exec -e "MYSQL_PWD=${DB_ROOT_PASSWORD}" meowhome_db \
  "$DUMP_CMD" --all-databases --single-transaction --routines --events --triggers -uroot \
  | gzip -c > "${WORK}/db/all-databases.sql.gz"
gzip -t "${WORK}/db/all-databases.sql.gz"

# Build one portable project archive. Runtime/generated trees are excluded.
echo "[backup] Projektfiles sammeln..."
tar -C "${PROJECT_DIR}" -czf "${WORK}/project.tar.gz" \
  --exclude='./.git' \
  --exclude='./backups' \
  --exclude='./db' \
  --exclude='./htdocs' \
  --exclude='./ftp/data' \
  --exclude='./ftp/ssl/vsftpd.pem' \
  .

if [[ "${WITH_HTDOCS}" == "--with-htdocs" ]]; then
  echo "[backup] htdocs inkludieren..."
  if [[ -d "${PROJECT_DIR}/htdocs" ]]; then
    tar -C "${PROJECT_DIR}" -czf "${WORK}/htdocs.tar.gz" "htdocs"
  fi
else
  echo "[backup] htdocs optional: nutze '--with-htdocs' wenn gewuenscht."
fi

cat > "${WORK}/manifest.json" <<EOF_MANIFEST
{
  "format_version": 2,
  "created_at": "$(date -Iseconds)",
  "project_dir": "${PROJECT_DIR}",
  "includes": {
    "db_all_databases": true,
    "project_tar": true,
    "ftp_users_sqlite": $( [[ -f "${PROJECT_DIR}/ftp/users.sqlite" ]] && echo true || echo false ),
    "htdocs_tar": $( [[ -f "${WORK}/htdocs.tar.gz" ]] && echo true || echo false )
  }
}
EOF_MANIFEST

items=("db" "project.tar.gz" "manifest.json")
[[ -f "${WORK}/htdocs.tar.gz" ]] && items+=("htdocs.tar.gz")
tar -C "${WORK}" -czf "${OUT}" "${items[@]}"
chmod 600 "${OUT}"

# The UI and sudo-driven backups may run as root, but artifacts live in the
# user-owned WSL project. Hand the final archive back to the canonical host ID.
if [[ "$(id -u)" == "0" ]]; then
  PUID="$(read_env_value PUID)"
  PGID="$(read_env_value PGID)"
  if [[ "$PUID" =~ ^[0-9]+$ && "$PGID" =~ ^[0-9]+$ ]]; then
    chown "${PUID}:${PGID}" "${OUT}"
  fi
fi

echo "[backup] Fertig: ${OUT}"
