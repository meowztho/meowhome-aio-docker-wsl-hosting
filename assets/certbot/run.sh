#!/bin/sh
set -eu

if [ "${CERTBOT_ENABLED:-true}" != "true" ]; then
  echo "[certbot] CERTBOT_ENABLED=false -> idle"
  while true; do sleep 365d; done
fi

[ -n "${LE_EMAIL:-}" ] || { echo "[certbot] LE_EMAIL fehlt"; exit 1; }
[ -n "${DOMAINS:-}" ] || { echo "[certbot] DOMAINS fehlt"; exit 1; }

PROP="${CF_PROPAGATION_SECONDS:-30}"
CH="${ACME_CHALLENGE:-dns}"
PROVIDER="${DNS_PROVIDER:-cloudflare}"
RETRY="${CERTBOT_RETRY_SECONDS:-300}"
ACCOUNT_DIR="/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory"
CERTBOT_ACCOUNT="${LE_ACCOUNT:-}"

resolve_certbot_account() {
  if [ -n "${CERTBOT_ACCOUNT}" ]; then
    echo "[certbot] using LE_ACCOUNT=${CERTBOT_ACCOUNT}"
    return 0
  fi
  [ -d "${ACCOUNT_DIR}" ] || return 0
  count="$(find "${ACCOUNT_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d '[:space:]')"
  if [ "${count}" = "1" ]; then
    CERTBOT_ACCOUNT="$(find "${ACCOUNT_DIR}" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | head -n 1)"
    echo "[certbot] auto-selected account: ${CERTBOT_ACCOUNT}"
    return 0
  fi
  renewal_accounts="$(grep -hE '^account *= *' /etc/letsencrypt/renewal/*.conf 2>/dev/null | sed -E 's/^account *= *//' | tr -d '[:space:]' | sed '/^$/d' | sort -u || true)"
  renewal_count="$(printf '%s\n' "${renewal_accounts}" | sed '/^$/d' | wc -l | tr -d '[:space:]')"
  if [ "${renewal_count}" = "1" ]; then
    candidate="$(printf '%s\n' "${renewal_accounts}" | head -n 1)"
    if [ -n "${candidate}" ] && [ -d "${ACCOUNT_DIR}/${candidate}" ]; then
      CERTBOT_ACCOUNT="${candidate}"
      echo "[certbot] auto-selected account from renewal config: ${CERTBOT_ACCOUNT}"
      return 0
    fi
  fi
  if [ "${count}" -gt 1 ] 2>/dev/null; then
    echo "[certbot] multiple Let's Encrypt accounts found; set LE_ACCOUNT in .env."
    find "${ACCOUNT_DIR}" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sed 's/^/[certbot]   - /'
    return 1
  fi
}

run_certbot() {
  if [ -n "${CERTBOT_ACCOUNT}" ]; then
    certbot "$@" --account "${CERTBOT_ACCOUNT}"
  else
    certbot "$@"
  fi
}

reload_apache() {
  echo "[certbot] apache reload/restart"
  docker exec meowhome_apache apachectl -k graceful >/dev/null 2>&1 && return 0
  docker restart meowhome_apache >/dev/null 2>&1 && return 0
  echo "[certbot] WARNING: Apache reload/restart failed" >&2
  return 1
}

issue_dns_cloudflare() {
  [ "${PROVIDER}" = "cloudflare" ] || { echo "[certbot] DNS_PROVIDER='${PROVIDER}' ist nicht implementiert."; return 1; }
  [ -n "${CLOUDFLARE_API_TOKEN:-}" ] || { echo "[certbot] CLOUDFLARE_API_TOKEN fehlt"; return 1; }
  CF_INI="/tmp/cf.ini"
  printf 'dns_cloudflare_api_token = %s\n' "${CLOUDFLARE_API_TOKEN}" > "${CF_INI}"
  chmod 600 "${CF_INI}"

  if [ "${WILDCARD:-true}" = "true" ]; then
    ok=1
    for zone in $(echo "$DOMAINS" | tr ',' ' '); do
      echo "[certbot] issuing wildcard for zone: $zone"
      if ! run_certbot certonly --non-interactive --agree-tos --email "${LE_EMAIL}" \
        --dns-cloudflare --dns-cloudflare-credentials "${CF_INI}" \
        --dns-cloudflare-propagation-seconds "${PROP}" -d "${zone}" -d "*.${zone}"; then
        ok=0
      fi
    done
    [ "$ok" = "1" ]
    return
  fi

  [ -n "${HOSTS:-}" ] || { echo "[certbot] WILDCARD=false aber HOSTS ist leer"; return 1; }
  set --
  for host in $(echo "$HOSTS" | tr ',' ' '); do
    set -- "$@" -d "$host"
  done
  run_certbot certonly --non-interactive --agree-tos --email "${LE_EMAIL}" \
    --dns-cloudflare --dns-cloudflare-credentials "${CF_INI}" \
    --dns-cloudflare-propagation-seconds "${PROP}" "$@"
}

issue_http01_webroot() {
  ok=1
  for zone in $(echo "$DOMAINS" | tr ',' ' '); do
    WEBROOT="/var/www/${zone}"
    mkdir -p "$WEBROOT/.well-known/acme-challenge"
    echo "[certbot] issuing cert for: $zone (webroot=$WEBROOT)"
    if ! run_certbot certonly --non-interactive --agree-tos --email "${LE_EMAIL}" \
      --webroot -w "$WEBROOT" -d "$zone"; then
      ok=0
    fi
  done
  [ "$ok" = "1" ]
}

resolve_certbot_account

# Initial issuance must succeed before entering renew-only mode. Otherwise a
# temporary DNS/network failure on first start could leave the container alive
# forever without ever obtaining a certificate.
while true; do
  if [ "$CH" = "dns" ]; then
    issue_dns_cloudflare && break
  elif [ "$CH" = "http" ]; then
    issue_http01_webroot && break
  else
    echo "[certbot] ACME_CHALLENGE muss dns oder http sein"
    exit 1
  fi
  echo "[certbot] initial issuance failed; retry in ${RETRY}s"
  sleep "${RETRY}"
done
reload_apache || true

while true; do
  echo "[certbot] renew start"
  if run_certbot renew --non-interactive --quiet; then
    reload_apache || true
  else
    echo "[certbot] renew failed; will retry on next cycle"
  fi
  echo "[certbot] renew done, sleeping 12h"
  sleep 12h
done
