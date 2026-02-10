#!/usr/bin/env bash
set -euo pipefail

log() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "WARN: $*" >&2; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

ensure_env_key() {
  local env_file="$1"
  local key="$2"
  local value="$3"

  if [[ ! -f "$env_file" ]]; then
    warn "[env] missing .env at $env_file (skip)"
    return 0
  fi

  if grep -qE "^${key}=" "$env_file"; then
    log "[env] ${key} already present"
    return 0
  fi

  printf '\n%s=%s\n' "$key" "$value" >> "$env_file"
  log "[env] added ${key}=${value}"
}

fix_webroot_permissions() {
  local webroot="$1"
  local uid_now gid_now

  if [[ ! -d "$webroot" ]]; then
    warn "[perm] webroot not found at $webroot (skip)"
    return 0
  fi

  uid_now="$(id -u)"
  gid_now="$(id -g)"

  log "[perm] ownership -> ${uid_now}:${gid_now} for $webroot"
  sudo chown -R "${uid_now}:${gid_now}" "$webroot" 2>/dev/null || true

  log "[perm] dirs: 2775 (setgid) | files: 664"
  sudo find "$webroot" -type d -exec chmod 2775 {} \; 2>/dev/null || true
  sudo find "$webroot" -type f -exec chmod 664 {} \; 2>/dev/null || true

  if have_cmd setfacl; then
    log "[perm] ACL available: setting default ACL (best-effort)"
    sudo setfacl -R -m "u:${uid_now}:rwx" "$webroot" 2>/dev/null || true
    sudo setfacl -R -d -m "u:${uid_now}:rwx" "$webroot" 2>/dev/null || true
    sudo setfacl -R -m "o::rx" "$webroot" 2>/dev/null || true
    sudo setfacl -R -d -m "o::rx" "$webroot" 2>/dev/null || true
  else
    log "[perm] setfacl not available: skipping ACL"
  fi
}

usage() {
  cat <<'EOF'
Usage:
  permissions_hardening.sh [--project DIR] --apply

Options:
  --project DIR   Root of meowhome project (default: script_dir/..)
  --apply         Apply env + permissions
EOF
}

main() {
  local project=""
  local apply="0"

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

  if [[ "$apply" != "1" ]]; then
    warn "Nothing done. Run with --apply"
    exit 1
  fi

  local env_file="$project/.env"
  local webroot="$project/htdocs"

  log "[info] project: $project"
  ensure_env_key "$env_file" "PUID" "$(id -u)"
  ensure_env_key "$env_file" "PGID" "$(id -g)"

  fix_webroot_permissions "$webroot"

  log "[done] permissions hardening applied"
}

main "$@"
