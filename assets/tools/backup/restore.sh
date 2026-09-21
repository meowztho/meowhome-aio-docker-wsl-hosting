#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALLED_PROJECT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
if [[ -n "${MEOWHOME_PROJECT_DIR:-}" ]]; then
  PROJECT_DIR="${MEOWHOME_PROJECT_DIR}"
elif [[ -f "${INSTALLED_PROJECT_DIR}/docker-compose.yml" ]]; then
  PROJECT_DIR="${INSTALLED_PROJECT_DIR}"
else
  PROJECT_DIR="$HOME/meowhome"
fi
BACKUP_TAR="${1:-}"

mkdir -p "${PROJECT_DIR}"
PROJECT_DIR="$(cd "${PROJECT_DIR}" && pwd -P)"

if [[ -z "${BACKUP_TAR}" || ! -f "${BACKUP_TAR}" ]]; then
  echo "Usage: $0 /pfad/zu/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz" >&2
  exit 1
fi

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

set_env_key() {
  local key="$1" value="$2" tmp
  [[ -f "${PROJECT_DIR}/.env" ]] || { echo "ERROR: .env fehlt beim Setzen von ${key}." >&2; return 1; }
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { written = 0 }
    $0 ~ ("^" key "=") {
      if (!written) { print key "=" value; written = 1 }
      next
    }
    { print }
    END { if (!written) print key "=" value }
  ' "${PROJECT_DIR}/.env" > "$tmp"
  cat "$tmp" > "${PROJECT_DIR}/.env"
  rm -f "$tmp"
}

assert_safe_tar() {
  python3 - "$1" <<'PY'
import pathlib, sys, tarfile

archive = pathlib.Path(sys.argv[1])

def normalize_relative(path: pathlib.PurePosixPath, *, label: str) -> pathlib.PurePosixPath:
    if path.is_absolute():
        raise SystemExit(f"unsafe absolute {label}: {path}")
    parts: list[str] = []
    for part in path.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise SystemExit(f"unsafe escaping {label}: {path}")
            parts.pop()
        else:
            parts.append(part)
    return pathlib.PurePosixPath(*parts)

with tarfile.open(archive, "r:gz") as tf:
    for member in tf.getmembers():
        member_path = normalize_relative(pathlib.PurePosixPath(member.name), label="tar path")
        if member.issym():
            # Symlink targets are relative to the link's parent. This permits
            # Let's Encrypt's live/<domain> -> ../../archive/<domain> layout
            # while rejecting links that escape the extraction root.
            link = pathlib.PurePosixPath(member.linkname)
            if link.is_absolute():
                raise SystemExit(f"unsafe absolute tar link: {member.name} -> {member.linkname}")
            normalize_relative(member_path.parent / link, label="tar symlink")
        elif member.islnk():
            # Tar hard-link targets are archive-root relative.
            normalize_relative(pathlib.PurePosixPath(member.linkname), label="tar hardlink")
PY
}

TMP="$(mktemp -d)"
cleanup() { rm -rf "${TMP}"; }
trap cleanup EXIT

echo "[restore] Backup: ${BACKUP_TAR}"
assert_safe_tar "${BACKUP_TAR}"
tar -C "${TMP}" -xzf "${BACKUP_TAR}"

[[ -f "${TMP}/db/all-databases.sql.gz" ]] || { echo "ERROR: db/all-databases.sql.gz fehlt im Backup." >&2; exit 1; }
[[ -f "${TMP}/project.tar.gz" ]] || { echo "ERROR: project.tar.gz fehlt im Backup." >&2; exit 1; }
gzip -t "${TMP}/db/all-databases.sql.gz"
assert_safe_tar "${TMP}/project.tar.gz"
[[ -f "${TMP}/htdocs.tar.gz" ]] && assert_safe_tar "${TMP}/htdocs.tar.gz"

echo "[restore] Projektbackup vorbereiten und validieren..."
mkdir -p "${TMP}/project-unpack"
tar -C "${TMP}/project-unpack" -xzf "${TMP}/project.tar.gz"

# v2 stores files at archive root; v1 stored them under project/.
PROJECT_SOURCE="${TMP}/project-unpack"
if [[ -d "${TMP}/project-unpack/project" && ! -f "${TMP}/project-unpack/docker-compose.yml" ]]; then
  PROJECT_SOURCE="${TMP}/project-unpack/project"
fi
if [[ ! -f "${PROJECT_SOURCE}/docker-compose.yml" || ! -f "${PROJECT_SOURCE}/.env" ]]; then
  echo "ERROR: Projektbackup enthaelt keine vollstaendige Runtime (.env/docker-compose.yml)." >&2
  exit 1
fi

if [[ -f "${PROJECT_DIR}/docker-compose.yml" ]]; then
  echo "[restore] Bestehenden Stack stoppen..."
  (cd "${PROJECT_DIR}" && compose down)
else
  echo "[restore] Kein bestehender Stack im Ziel; compose down wird uebersprungen."
fi

echo "[restore] Projektfiles zurueckspielen (overlay; keine impliziten Loeschungen)..."
cp -a "${PROJECT_SOURCE}/." "${PROJECT_DIR}/"
cd "${PROJECT_DIR}"

# Location-specific runtime metadata must follow the restore destination.
# All user configuration remains untouched.
set_env_key "MEOWHOME_HOST_PROJECT_DIR" "$PROJECT_DIR"

if [[ -f "${TMP}/htdocs.tar.gz" ]]; then
  echo "[restore] htdocs zurueckspielen..."
  tar -C "${PROJECT_DIR}" -xzf "${TMP}/htdocs.tar.gz"
else
  echo "[restore] htdocs nicht im Backup; bestehendes htdocs bleibt unveraendert."
fi

DB_ROOT_PASSWORD="$(read_env_value DB_ROOT_PASSWORD)"
echo "[restore] DB starten..."
compose up -d mariadb

echo "[restore] Warte auf MariaDB..."
ready=0
for i in {1..60}; do
  if docker exec -e "MYSQL_PWD=${DB_ROOT_PASSWORD}" meowhome_db mariadb-admin ping -uroot --silent >/dev/null 2>&1; then
    ready=1
    echo "[restore] MariaDB ready."
    break
  fi
  sleep 2
done
if [[ "$ready" != "1" ]]; then
  echo "ERROR: MariaDB wurde nicht ready." >&2
  docker logs --tail 80 meowhome_db || true
  exit 1
fi

echo "[restore] Import all-databases.sql.gz (inkl. mysql user/grants)..."
gunzip -c "${TMP}/db/all-databases.sql.gz" | docker exec -i -e "MYSQL_PWD=${DB_ROOT_PASSWORD}" meowhome_db mariadb -uroot

echo "[restore] Restliche Services starten..."
compose up -d

# ftp/data is generated state and intentionally not part of v2 backups.
if [[ -f "${PROJECT_DIR}/ftp/users.sqlite" && -x "${PROJECT_DIR}/tools/ftp/meowftp.py" ]]; then
  echo "[restore] FTP Auth-State aus ftp/users.sqlite neu aufbauen..."
  if [[ "${MEOWHOME_SKIP_FTP_REBUILD:-false}" == "true" ]]; then
    echo "[restore] FTP rebuild durch MEOWHOME_SKIP_FTP_REBUILD=true uebersprungen."
  else
    "${PROJECT_DIR}/tools/ftp/meowftp.py" apply
  fi
fi

echo "[restore] Fertig."
