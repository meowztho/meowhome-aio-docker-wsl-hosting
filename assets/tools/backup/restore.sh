#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${MEOWHOME_PROJECT_DIR:-$HOME/meowhome}"
BACKUP_TAR="${1:-}"

if [[ -z "${BACKUP_TAR}" || ! -f "${BACKUP_TAR}" ]]; then
  echo "Usage: $0 /pfad/zu/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz" >&2
  exit 1
fi

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

TMP="$(mktemp -d)"
cleanup() { rm -rf "${TMP}"; }
trap cleanup EXIT

echo "[restore] Backup: ${BACKUP_TAR}"
echo "[restore] Temp: ${TMP}"

tar -C "${TMP}" -xzf "${BACKUP_TAR}"

if [[ ! -f "${TMP}/db/all-databases.sql.gz" ]]; then
  echo "ERROR: db/all-databases.sql.gz fehlt im Backup." >&2
  exit 1
fi
if [[ ! -f "${TMP}/project.tar.gz" ]]; then
  echo "ERROR: project.tar.gz fehlt im Backup." >&2
  exit 1
fi

echo "[restore] Stack stoppen..."
cd "${PROJECT_DIR}"
compose down

echo "[restore] Projektfiles entpacken..."
tar -C "${TMP}" -xzf "${TMP}/project.tar.gz"

# Jetzt liegt alles unter ${TMP}/project/...
if [[ ! -d "${TMP}/project" ]]; then
  echo "ERROR: project/ fehlt nach Entpacken." >&2
  exit 1
fi

# Rueckspielen (ueberschreiben)
rsync -a --delete "${TMP}/project/" "${PROJECT_DIR}/"

# Optional: htdocs
if [[ -f "${TMP}/htdocs.tar.gz" ]]; then
  echo "[restore] htdocs zurueckspielen..."
  tar -C "${PROJECT_DIR}" -xzf "${TMP}/htdocs.tar.gz"
else
  echo "[restore] htdocs nicht im Backup, ueberspringe."
fi

# Root-Passwort nach Restore aus .env
DB_ROOT_PASSWORD=""
if [[ -f "${PROJECT_DIR}/.env" ]]; then
  DB_ROOT_PASSWORD="$(grep -E '^DB_ROOT_PASSWORD=' "${PROJECT_DIR}/.env" | head -n1 | cut -d= -f2- || true)"
fi
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD%\"}"
DB_ROOT_PASSWORD="${DB_ROOT_PASSWORD#\"}"

echo "[restore] DB starten..."
compose up -d mariadb

echo "[restore] Warte auf MariaDB..."
for i in {1..60}; do
  if docker exec meowhome_db sh -lc "mariadb-admin ping -uroot -p\"${DB_ROOT_PASSWORD}\" --silent" >/dev/null 2>&1; then
    echo "[restore] MariaDB ready."
    break
  fi
  sleep 2
  if [[ "$i" -eq 60 ]]; then
    echo "ERROR: MariaDB wurde nicht ready." >&2
    docker logs --tail 80 meowhome_db || true
    exit 1
  fi
done

echo "[restore] Import all-databases.sql.gz (inkl. mysql user/grants)..."
gunzip -c "${TMP}/db/all-databases.sql.gz" | docker exec -i meowhome_db sh -lc "mariadb -uroot -p\"${DB_ROOT_PASSWORD}\""

echo "[restore] Restliche Services starten..."
compose up -d

echo "[restore] Fertig."
echo "[restore] Tipp: Falls etwas komisch ist: 'docker logs meowhome_db --tail 200' und 'docker logs meowhome_ftp --tail 200'"
