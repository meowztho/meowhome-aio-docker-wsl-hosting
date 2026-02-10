#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${MEOWHOME_PROJECT_DIR:-$HOME/meowhome}"
BACKUP_DIR="${PROJECT_DIR}/backups"
TS="$(date +%Y%m%d-%H%M%S)"
WORK="${BACKUP_DIR}/work-${TS}"
OUT="${BACKUP_DIR}/meowhome-backup-${TS}.tar.gz"

WITH_HTDOCS="${1:-}"  # use: --with-htdocs

mkdir -p "${BACKUP_DIR}" "${WORK}"

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

need_container() {
  local name="$1"
  if ! docker inspect "$name" >/dev/null 2>&1; then
    echo "ERROR: Container '$name' nicht gefunden." >&2
    exit 1
  fi
}

need_container "meowhome_db"

echo "[backup] Ziel: ${OUT}"
echo "[backup] Workdir: ${WORK}"

# ----------------------------
# 1) DB Dump: ALL databases incl. mysql system db (Users/Grants!)
# ----------------------------
echo "[backup] DB dump (all databases incl users/grants)..."
mkdir -p "${WORK}/db"

DUMP_CMD="mariadb-dump"
if ! docker exec meowhome_db sh -lc "command -v mariadb-dump >/dev/null 2>&1"; then
  DUMP_CMD="mysqldump"
fi

# DB_ROOT_PASSWORD aus .env (falls vorhanden), sonst leer
DB_ROOT_PASSWORD=""
if [[ -f "${PROJECT_DIR}/.env" ]]; then
  DB_ROOT_PASSWORD="$(grep -E '^DB_ROOT_PASSWORD=' "${PROJECT_DIR}/.env" | head -n1 | cut -d= -f2- || true)"
fi

# shellcheck disable=SC2001
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD%\"}"
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD#\"}"

# Dump -> gzip
docker exec meowhome_db sh -lc \
  "${DUMP_CMD} --all-databases --single-transaction --routines --events --triggers -uroot -p\"${DB_ROOT_PASSWORD}\"" \
  | gzip -c > "${WORK}/db/all-databases.sql.gz"

echo "[backup] DB dump ok: ${WORK}/db/all-databases.sql.gz"

# ----------------------------
# 2) Projektfiles packen (ohne htdocs per default)
# ----------------------------
echo "[backup] Projektfiles sammeln..."
mkdir -p "${WORK}/project"

copy_if_exists() {
  local rel="$1"
  if [[ -e "${PROJECT_DIR}/${rel}" ]]; then
    mkdir -p "$(dirname "${WORK}/project/${rel}")"
    cp -a "${PROJECT_DIR}/${rel}" "${WORK}/project/${rel}"
  fi
}

# Wichtige Konfig + persistente Daten
copy_if_exists "docker-compose.yml"
copy_if_exists ".env"
copy_if_exists "apache/vhosts"
copy_if_exists "apache/snippets"
copy_if_exists "letsencrypt"
copy_if_exists "tools/ftp"     # enthaelt u.a. FTP SQLite DB / scripts
copy_if_exists "certbot"
copy_if_exists "dns-updater"
copy_if_exists "php"
copy_if_exists "web"

# Optional: htdocs separat, weil groß
if [[ "${WITH_HTDOCS}" == "--with-htdocs" ]]; then
  echo "[backup] htdocs inkludieren..."
  if [[ -d "${PROJECT_DIR}/htdocs" ]]; then
    tar -C "${PROJECT_DIR}" -czf "${WORK}/htdocs.tar.gz" "htdocs"
    echo "[backup] htdocs ok: ${WORK}/htdocs.tar.gz"
  else
    echo "[backup] htdocs nicht gefunden, skip."
  fi
else
  echo "[backup] htdocs optional: nutze '--with-htdocs' wenn gewuenscht."
fi

# project/ tar
tar -C "${WORK}" -czf "${WORK}/project.tar.gz" "project"

# manifest
cat > "${WORK}/manifest.json" <<EOF
{
  "created_at": "$(date -Iseconds)",
  "project_dir": "${PROJECT_DIR}",
  "includes": {
    "db_all_databases": true,
    "project_tar": true,
    "htdocs_tar": $( [[ "${WITH_HTDOCS}" == "--with-htdocs" ]] && echo true || echo false )
  }
}
EOF

# Finales Archiv
tar -C "${WORK}" -czf "${OUT}" "db" "project.tar.gz" "manifest.json" $( [[ -f "${WORK}/htdocs.tar.gz" ]] && echo "htdocs.tar.gz" || true )

# Cleanup workdir
rm -rf "${WORK}"

echo "[backup] Fertig: ${OUT}"

