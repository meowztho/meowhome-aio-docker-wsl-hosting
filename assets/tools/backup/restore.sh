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
  local key="$1" env_file="${2:-${PROJECT_DIR}/.env}" value=""
  [[ -f "${env_file}" ]] || return 0
  value="$(grep -E "^${key}=" "${env_file}" | tail -n1 | cut -d= -f2- || true)"
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

validate_restore_paths() {
  local root="$1" label="$2" require_runtime="$3"
  python3 - "$root" "$label" "$require_runtime" <<'PY'
import pathlib, stat, sys

root = pathlib.Path(sys.argv[1])
label = sys.argv[2]
require_runtime = sys.argv[3] == "yes"
required_files = {".env", "docker-compose.yml"}
sensitive_files = required_files | {
    "control/control.token", "control/certbot.token",
    "ftp/users.sqlite", "ftp/ssl/vsftpd.pem",
}
protected_dirs = {"control", "ftp", "ftp/ssl"}

def reject(path, reason):
    raise SystemExit(f"ERROR: unsafe {label} path {path}: {reason}")

for rel in sorted(sensitive_files):
    path = root / rel
    # Check each protected ancestor without following links.
    for parent_rel in pathlib.PurePosixPath(rel).parents:
        if str(parent_rel) == ".":
            continue
        parent = root / str(parent_rel)
        try:
            st = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            reject(parent_rel, "ancestor must be a real directory")

    try:
        st = path.lstat()
    except FileNotFoundError:
        if require_runtime and rel in required_files:
            reject(rel, "required runtime file is missing")
        continue
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
        reject(rel, "must be a regular file, not a symlink or special file")
    if rel in sensitive_files and st.st_nlink != 1:
        reject(rel, "must not have multiple hard links")

for rel in protected_dirs:
    path = root / rel
    try:
        st = path.lstat()
    except FileNotFoundError:
        continue
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        reject(rel, "must be a real directory")
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
validate_restore_paths "${PROJECT_SOURCE}" "backup" yes

# The combined vsftpd PEM is generated state and intentionally excluded from
# backups. Rebuild it in the extracted staging tree before touching the target
# project or stopping its running services.
FTP_TLS="$(read_env_value FTP_TLS "${PROJECT_SOURCE}/.env" | tr '[:lower:]' '[:upper:]')"
if [[ "${FTP_TLS}" == "YES" || "${FTP_TLS}" == "TRUE" || "${FTP_TLS}" == "1" || "${FTP_TLS}" == "ON" ]]; then
  # Use the current validator even when restoring an older archive whose
  # bundled builder merely concatenated files without validating the key pair.
  PEM_BUILDER="${SCRIPT_DIR}/../../ftp/build-ftps-pem.sh"
  if [[ ! -f "${PEM_BUILDER}" ]]; then
    echo "ERROR: FTPS ist aktiviert, aber der aktuelle PEM-Builder fehlt." >&2
    exit 1
  fi
  echo "[restore] FTPS-Zertifikat und Schluessel vorab pruefen..."
  if ! MEOWHOME_PROJECT_DIR="${PROJECT_SOURCE}" bash "${PEM_BUILDER}"; then
    echo "ERROR: FTPS-PEM konnte aus dem Backup nicht erzeugt werden; Zielprojekt blieb unveraendert." >&2
    exit 1
  fi
  if [[ ! -s "${PROJECT_SOURCE}/ftp/ssl/vsftpd.pem" ]]; then
    echo "ERROR: FTPS-PEM wurde nicht erzeugt; Zielprojekt blieb unveraendert." >&2
    exit 1
  fi
fi

# Existing destinations can contain links left by prior projects. Check them
# before stopping services or overlay-copying the archive.
validate_restore_paths "${PROJECT_DIR}" "target" no

# GNU tar follows existing destination directory links. Inspect every webroot
# destination before stopping services, including nested paths and hard links.
if [[ -f "${TMP}/htdocs.tar.gz" ]]; then
  python3 - "${TMP}/htdocs.tar.gz" "${PROJECT_DIR}" "${PROJECT_SOURCE}" <<'PY'
import os, pathlib, stat, sys, tarfile

for root_arg in sys.argv[2:]:
    root = pathlib.Path(root_arg)
    with tarfile.open(sys.argv[1], "r:gz") as archive:
        for member in archive:
            parts = pathlib.PurePosixPath(member.name).parts
            if not parts or parts[0] != "htdocs":
                raise SystemExit("ERROR: webroot archive contains a path outside htdocs")
            path = root
            for index, part in enumerate(parts):
                path = path / part
                try:
                    metadata = path.lstat()
                except FileNotFoundError:
                    continue
                leaf = index == len(parts) - 1
                # An unchanged leaf symlink is safe to restore as a link. Never
                # traverse it to restore a descendant or replace it with a file.
                same_link = (leaf and member.issym() and stat.S_ISLNK(metadata.st_mode)
                             and os.readlink(path) == member.linkname)
                if stat.S_ISLNK(metadata.st_mode) and not same_link:
                    raise SystemExit(f"ERROR: unsafe webroot restore target: {path.relative_to(root)} is a symlink")
                if not leaf and not stat.S_ISDIR(metadata.st_mode):
                    raise SystemExit(f"ERROR: unsafe webroot restore ancestor: {path.relative_to(root)}")
                if leaf and stat.S_ISREG(metadata.st_mode) and metadata.st_nlink != 1:
                    raise SystemExit(f"ERROR: unsafe webroot restore target: {path.relative_to(root)} has hard links")
PY
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

# Restored archives can carry permissive historical modes. Normalize only
# credential/configuration files; never recurse into or chown user web content.
chmod 600 "${PROJECT_DIR}/.env"
if [[ -d "${PROJECT_DIR}/control" ]]; then
  chmod 700 "${PROJECT_DIR}/control"
  for token_file in "${PROJECT_DIR}/control/control.token" "${PROJECT_DIR}/control/certbot.token"; do
    [[ ! -f "${token_file}" ]] || chmod 600 "${token_file}"
  done
fi
if [[ -f "${PROJECT_DIR}/ftp/users.sqlite" ]]; then
  chmod 600 "${PROJECT_DIR}/ftp/users.sqlite"
fi

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
  # ping can succeed even on access denied. TCP also excludes the temporary
  # socket-only server used while a fresh MariaDB data directory initializes.
  if docker exec -e "MYSQL_PWD=${DB_ROOT_PASSWORD}" meowhome_db mariadb --protocol=tcp -h127.0.0.1 -uroot -Nse 'SELECT 1' >/dev/null 2>&1; then
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
