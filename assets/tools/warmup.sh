#!/usr/bin/env bash
set -euo pipefail

BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE"

LOG_DIR="$BASE/state"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/warmup.log"

ts() { date +"%Y-%m-%d %H:%M:%S"; }
log() { echo "[$(ts)] $*" | tee -a "$LOG"; }

log "warmup: start (base=$BASE)"

for i in $(seq 1 60); do
  if docker info >/dev/null 2>&1; then
    log "Docker is available."
    break
  fi
  if [ "$i" -eq 60 ]; then
    log "ERROR: Docker not available after 60s."
    exit 1
  fi
  sleep 1
done

sleep 10

restart_one() {
  local name="$1"
  if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
    log "Restarting: $name"
    docker restart "$name" >/dev/null
  else
    log "WARNING: container not found: $name"
  fi
}

restart_one "meowhome_db"
restart_one "meowhome_php"
restart_one "meowhome_apache"
restart_one "meowhome_pma"
restart_one "meowhome_dns_updater"
restart_one "meowhome_ftp"
restart_one "meowhome_certbot"

log "warmup: done"
