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

reload_apache() {
  echo "[certbot] apache reload/restart"
  if docker exec meowhome_apache apachectl -k graceful >/dev/null 2>&1; then
    return 0
  fi
  docker restart meowhome_apache >/dev/null 2>&1 || true
}

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
    certbot certonly \
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
    certbot certonly \
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
    certbot certonly \
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
  certbot renew --non-interactive --quiet || true
  reload_apache
  echo "[certbot] renew done, sleeping 12h"
  sleep 12h
done
