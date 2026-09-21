#!/usr/bin/env bash
set -euo pipefail
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE"
LOG_DIR="$BASE/state"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/warmup.log"
ts() { date +"%Y-%m-%d %H:%M:%S"; }
log() { echo "[$(ts)] $*" | tee -a "$LOG"; }

compose() {
  if docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  elif command -v docker-compose >/dev/null 2>&1; then
    docker-compose "$@"
  else
    log "ERROR: Docker Compose not available."
    return 127
  fi
}

log "warmup: start (base=$BASE)"
for i in $(seq 1 60); do
  if docker info >/dev/null 2>&1; then
    log "Docker is available."
    break
  fi
  if [[ "$i" -eq 60 ]]; then
    log "ERROR: Docker not available after 60s."
    exit 1
  fi
  sleep 1
done
sleep 10

# Compose owns lifecycle; restart the project's currently defined services in one operation.
log "Restarting MeowHome services via Compose..."
compose restart
log "warmup: done"
