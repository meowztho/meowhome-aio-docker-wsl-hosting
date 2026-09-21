#!/usr/bin/env bash
set -euo pipefail

log() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "WARN: $*" >&2; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

read_env_key() {
  local env_file="$1" key="$2" default="$3" value=""
  if [[ -f "$env_file" ]]; then
    value="$(grep -E "^${key}=" "$env_file" | tail -n1 | cut -d= -f2- || true)"
  fi
  value="${value%\"}"; value="${value#\"}"
  value="${value%\'}"; value="${value#\'}"
  printf '%s' "${value:-$default}"
}

ensure_env_key() {
  local env_file="$1" key="$2" value="$3"
  if [[ ! -f "$env_file" ]]; then
    warn "[env] missing .env at $env_file (skip)"
    return 0
  fi
  if grep -qE "^${key}=" "$env_file"; then
    return 0
  fi
  printf '\n%s=%s\n' "$key" "$value" >> "$env_file"
  log "[env] added ${key}=${value}"
}

run_privileged() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif have_cmd sudo; then
    sudo "$@"
  else
    warn "[perm] root privileges required (run as root or install/use sudo)"
    return 1
  fi
}

fix_webroot_permissions() {
  local webroot="$1" uid_now="$2" gid_now="$3"
  if [[ ! -d "$webroot" ]]; then
    warn "[perm] webroot not found at $webroot (skip)"
    return 0
  fi

  log "[perm] ownership -> ${uid_now}:${gid_now} for $webroot"
  run_privileged chown -R "${uid_now}:${gid_now}" "$webroot"

  # Keep executable bits on files. Directories are setgid/group-writable so
  # newly uploaded files inherit the project group.
  log "[perm] dirs: group writable + setgid | files: group writable (exec bits preserved)"
  run_privileged find "$webroot" -type d -exec chmod g+rwx,o+rx,g+s {} \;
  run_privileged find "$webroot" -type f -exec chmod g+rw,o+r {} \;

  if have_cmd setfacl; then
    log "[perm] ACL available: setting default ACL (best-effort)"
    run_privileged setfacl -R -m "u:${uid_now}:rwx" "$webroot" || true
    run_privileged setfacl -R -d -m "u:${uid_now}:rwx" "$webroot" || true
    run_privileged setfacl -R -m "o::rx" "$webroot" || true
    run_privileged setfacl -R -d -m "o::rx" "$webroot" || true
  fi
}

usage() {
  cat <<'EOF_USAGE'
Usage:
  permissions_hardening.sh [--project DIR] --apply
EOF_USAGE
}

main() {
  local project="" apply="0"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --project) project="${2:-}"; shift 2;;
      --apply) apply="1"; shift;;
      -h|--help) usage; exit 0;;
      *) warn "Unknown arg: $1"; usage; exit 2;;
    esac
  done
  if [[ -z "$project" ]]; then
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    project="$(cd "$script_dir/.." && pwd)"
  fi
  [[ "$apply" == "1" ]] || { warn "Nothing done. Run with --apply"; exit 1; }

  local env_file="$project/.env" webroot="$project/htdocs"
  local invoking_uid="${SUDO_UID:-$(id -u)}" invoking_gid="${SUDO_GID:-$(id -g)}"
  ensure_env_key "$env_file" PUID "$invoking_uid"
  ensure_env_key "$env_file" PGID "$invoking_gid"

  local target_uid target_gid
  target_uid="$(read_env_key "$env_file" PUID "$invoking_uid")"
  target_gid="$(read_env_key "$env_file" PGID "$invoking_gid")"
  if ! [[ "$target_uid" =~ ^[0-9]+$ && "$target_gid" =~ ^[0-9]+$ ]]; then
    warn "[env] PUID/PGID must be numeric"
    exit 2
  fi

  log "[info] project: $project"
  fix_webroot_permissions "$webroot" "$target_uid" "$target_gid"
  log "[done] permissions hardening applied"
}

main "$@"
