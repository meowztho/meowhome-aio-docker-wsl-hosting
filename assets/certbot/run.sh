#!/bin/sh
set -eu

# CERTBOT_ENABLED=false -> container exists but does nothing
if [ "${CERTBOT_ENABLED:-true}" != "true" ]; then
  echo "[certbot] CERTBOT_ENABLED=false -> idle"
  while true; do sleep 365d; done
fi

if [ -z "${LE_EMAIL:-}" ]; then
  echo "[certbot] LE_EMAIL fehlt"
  exit 1
fi
if [ -z "${DOMAINS:-}" ]; then
  echo "[certbot] DOMAINS fehlt"
  exit 1
fi

PROP="${CF_PROPAGATION_SECONDS:-30}"
CH="${ACME_CHALLENGE:-dns}"
PROVIDER="${DNS_PROVIDER:-cloudflare}"
ACCOUNT_DIR="/etc/letsencrypt/accounts/acme-v02.api.letsencrypt.org/directory"
CERTBOT_ACCOUNT="${LE_ACCOUNT:-}"

resolve_certbot_account() {
  if [ -n "${CERTBOT_ACCOUNT}" ]; then
    echo "[certbot] using LE_ACCOUNT=${CERTBOT_ACCOUNT}"
    return 0
  fi

  if [ ! -d "${ACCOUNT_DIR}" ]; then
    return 0
  fi

  count="$(find "${ACCOUNT_DIR}" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d '[:space:]')"

  if [ "${count}" = "1" ]; then
    CERTBOT_ACCOUNT="$(find "${ACCOUNT_DIR}" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | head -n 1)"
    echo "[certbot] auto-selected account: ${CERTBOT_ACCOUNT}"
    return 0
  fi

  # If multiple accounts exist, try to infer from existing renewal files.
  renewal_accounts="$(
    grep -hE '^account *= *' /etc/letsencrypt/renewal/*.conf 2>/dev/null \
      | sed -E 's/^account *= *//' \
      | tr -d '[:space:]' \
      | sed '/^$/d' \
      | sort -u
  )"
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
    echo "[certbot] available account IDs:"
    find "${ACCOUNT_DIR}" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sed 's/^/[certbot]   - /'
    echo "[certbot] example: LE_ACCOUNT=70e6"
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
  if docker exec meowhome_apache apachectl -k graceful >/dev/null 2>&1; then
    return 0
  fi
  docker restart meowhome_apache >/dev/null 2>&1 || true
}

if ! resolve_certbot_account; then
  exit 1
fi

issue_dns_cloudflare() {
  if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
    echo "[certbot] CLOUDFLARE_API_TOKEN fehlt (ACME_CHALLENGE=dns, DNS_PROVIDER=cloudflare)"
    exit 1
  fi

  CF_INI="/tmp/cf.ini"
  echo "dns_cloudflare_api_token = ${CLOUDFLARE_API_TOKEN}" > "${CF_INI}"
  chmod 600 "${CF_INI}"

  issue_wildcard_for_zone() {
    zone="$1"
    echo "[certbot] issuing wildcard for zone: $zone"
    run_certbot certonly \
      --non-interactive --agree-tos \
      --email "${LE_EMAIL}" \
      --dns-cloudflare --dns-cloudflare-credentials "${CF_INI}" \
      --dns-cloudflare-propagation-seconds "${PROP}" \
      -d "${zone}" -d "*.${zone}" || true
  }

  issue_hosts() {
    if [ -z "${HOSTS:-}" ]; then
      echo "[certbot] WILDCARD=false aber HOSTS ist leer"
      return 0
    fi

    echo "[certbot] issuing hosts: ${HOSTS}"
    args=""
    for h in $(echo "$HOSTS" | tr ',' ' '); do
      args="$args -d $h"
    done

    # shellcheck disable=SC2086
    run_certbot certonly \
      --non-interactive --agree-tos \
      --email "${LE_EMAIL}" \
      --dns-cloudflare --dns-cloudflare-credentials "${CF_INI}" \
      --dns-cloudflare-propagation-seconds "${PROP}" \
      $args || true
  }

  W="${WILDCARD:-true}"
  for zone in $(echo "$DOMAINS" | tr ',' ' '); do
    if [ "$W" = "true" ]; then
      issue_wildcard_for_zone "$zone"
    else
      issue_hosts
      break
    fi
  done
}

issue_http01_webroot() {
  echo "[certbot] HTTP-01 webroot mode (no wildcard)."
  for zone in $(echo "$DOMAINS" | tr ',' ' '); do
    WEBROOT="/var/www/${zone}"
    mkdir -p "$WEBROOT/.well-known/acme-challenge"
    echo "[certbot] issuing cert for: $zone (webroot=$WEBROOT)"
    run_certbot certonly \
      --non-interactive --agree-tos \
      --email "${LE_EMAIL}" \
      --webroot -w "$WEBROOT" \
      -d "$zone" || true
  done
}

if [ "$CH" = "dns" ]; then
  if [ "$PROVIDER" != "cloudflare" ]; then
    echo "[certbot] DNS_PROVIDER='$PROVIDER' ist nicht implementiert. Nutze DNS_PROVIDER=cloudflare oder ACME_CHALLENGE=http."
    exit 1
  fi
  issue_dns_cloudflare
else
  issue_http01_webroot
fi

reload_apache

while true; do
  echo "[certbot] renew start"
  run_certbot renew --non-interactive --quiet || true
  reload_apache
  echo "[certbot] renew done, sleeping 12h"
  sleep 12h
done
