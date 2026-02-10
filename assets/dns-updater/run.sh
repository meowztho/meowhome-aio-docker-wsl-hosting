#!/bin/sh
set -eu

# DNS_UPDATER_ENABLED=false -> container exists but does nothing
if [ "${DNS_UPDATER_ENABLED:-true}" != "true" ]; then
  echo "[dns-updater] DNS_UPDATER_ENABLED=false -> idle"
  while true; do sleep 365d; done
fi

mkdir -p /state
export STATE_PATH="${STATE_PATH:-/state/state.json}"
export LOG_PATH="${LOG_PATH:-/state/dns_updater.log}"
exec python /app/DNSUpdatecloudflare.py
