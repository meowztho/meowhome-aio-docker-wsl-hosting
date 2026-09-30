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

docker_server_ready() {
  local out
  out="$(docker version --format 'MEOWHOME_DOCKER_SERVER={{.Server.Version}}' 2>&1 || true)"
  grep -Eq '^MEOWHOME_DOCKER_SERVER=[0-9]' <<<"$out"
}

probe_image() {
  local image
  image="$(docker inspect --format '{{.Image}}' meowhome_apache 2>/dev/null || true)"
  if [[ "$image" =~ ^sha256: ]]; then
    printf '%s\n' "$image"
  else
    printf '%s\n' 'meowhome-web'
  fi
}

wsl_bind_mount_ready() {
  local out image
  image="$(probe_image)"
  out="$(docker run --rm --entrypoint sh \
    -v "$BASE:/meowhome-probe:ro" \
    "$image" \
    -c 'test -f /meowhome-probe/VERSION && test -f /meowhome-probe/docker-compose.yml && printf "MEOWHOME_BIND_OK\\n"' \
    2>&1 || true)"
  grep -qx 'MEOWHOME_BIND_OK' <<<"$out"
}

log "warmup: start (base=$BASE)"
for i in $(seq 1 180); do
  if docker_server_ready && wsl_bind_mount_ready; then
    log "Docker API and WSL bind mounts are ready."
    break
  fi
  if (( i % 10 == 0 )); then
    log "Waiting for Docker Desktop WSL integration... (${i}s)"
  fi
  if [[ "$i" -eq 180 ]]; then
    log "ERROR: Docker API / WSL bind mounts not ready after 180s; refusing to recreate containers."
    exit 1
  fi
  sleep 1
done

# Compose owns lifecycle. Recreate after WSL integration is proven healthy so
# containers created during the startup race cannot retain stale bind-mount mirrors.
log "Recreating MeowHome services via Compose..."
compose up -d --force-recreate --no-build
log "warmup: done"
