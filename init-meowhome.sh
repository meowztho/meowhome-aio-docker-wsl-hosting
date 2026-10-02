#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# MeowHome Bootstrapper (Core + Tools + FTP Virtual Users)
# Version: 2.6.2 (Apache control-plane ownership + AOP asset hardening)
# - erstellt ~/meowhome komplett
# - Tools unter ./tools (modular erweiterbar)
# - FTP: vsftpd Virtual Users + Tool (SQLite auf Host)
# - phpMyAdmin nur auf 127.0.0.1 gebunden
# - kopiert DNSUpdatecloudflare.py wenn neben Script vorhanden
#
# FIX (Permissions / Ownership):
# - verhindert dass FTP/Container den Host-Bind-Mount htdocs "uebernimmt"
# - setzt PUID/PGID in .env und nutzt sie in docker-compose (web/php)
# - setzt vsftpd umask auf 002 (group-writable Uploads)
# - entfernt chown -R ftp:ftp /var/www (zerstoert Host-Ownership bei Bind-Mounts)
# - Tool: ./tools/permissions_hardening.sh (nur explizit; Upgrades aendern htdocs-Rechte nicht)
#
# NEW (Certbot/DNS optional):
# - CERTBOT_ENABLED / DNS_UPDATER_ENABLED toggles (container idles when disabled)
# - ACME_CHALLENGE=dns (default, Cloudflare DNS-01, wildcard) or ACME_CHALLENGE=http (HTTP-01 fallback, no wildcard)
# ============================================================

PROJECT_DIR="${1:-$HOME/meowhome}"
HOST_UID="${SUDO_UID:-$(id -u)}"
HOST_GID="${SUDO_GID:-$(id -g)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$PROJECT_DIR"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd -P)"

# ----------------------------
# Struktur
# ----------------------------
mkdir -p \
  "$PROJECT_DIR/apache/vhosts" \
  "$PROJECT_DIR/apache/snippets" \
  "$PROJECT_DIR/htdocs/example.com" \
  "$PROJECT_DIR/web" \
  "$PROJECT_DIR/php" \
  "$PROJECT_DIR/certbot" \
  "$PROJECT_DIR/dns-updater" \
  "$PROJECT_DIR/ftp/data/users.d" \
  "$PROJECT_DIR/ftp/ssl" \
  "$PROJECT_DIR/tools/ftp" \
  "$PROJECT_DIR/tools/backup" \
  "$PROJECT_DIR/tools/apache" \
  "$PROJECT_DIR/db" \
  "$PROJECT_DIR/letsencrypt" \
  "$PROJECT_DIR/state" \
  "$PROJECT_DIR/legacy"

# ----------------------------
# Tools: Warmup (WSL Mount Race Fix)
# ----------------------------
cp "$SCRIPT_DIR/assets/tools/warmup.sh" "$PROJECT_DIR/tools/warmup.sh"
chmod +x "$PROJECT_DIR/tools/warmup.sh"

# ----------------------------
# Tools: Restore
# ----------------------------
cp "$SCRIPT_DIR/assets/tools/backup/restore.sh" "$PROJECT_DIR/tools/backup/restore.sh"
chmod +x "$PROJECT_DIR/tools/backup/restore.sh"

# ----------------------------
# Tools: Backup
# ----------------------------
cp "$SCRIPT_DIR/assets/tools/backup/backup.sh" "$PROJECT_DIR/tools/backup/backup.sh"
chmod +x "$PROJECT_DIR/tools/backup/backup.sh"

# ----------------------------
# Tools: Permissions Hardening
# ----------------------------
cp "$SCRIPT_DIR/assets/tools/permissions_hardening.sh" "$PROJECT_DIR/tools/permissions_hardening.sh"
chmod +x "$PROJECT_DIR/tools/permissions_hardening.sh"

# Core operational interface + contract docs
cp "$SCRIPT_DIR/assets/tools/meowhome.py" "$PROJECT_DIR/tools/meowhome.py"
chmod +x "$PROJECT_DIR/tools/meowhome.py"
cp "$SCRIPT_DIR/ARCHITECTURE.md" "$PROJECT_DIR/ARCHITECTURE.md"
cp "$SCRIPT_DIR/AGENTS.md" "$PROJECT_DIR/AGENTS.md"
cp "$SCRIPT_DIR/CHANGELOG.md" "$PROJECT_DIR/CHANGELOG.md"
cp "$SCRIPT_DIR/VERSION" "$PROJECT_DIR/VERSION"

# ----------------------------
# .gitignore
# ----------------------------
cp "$SCRIPT_DIR/assets/root/.gitignore" "$PROJECT_DIR/.gitignore"

# ----------------------------
# .env.example
# ----------------------------
cp "$SCRIPT_DIR/assets/root/.env.example" "$PROJECT_DIR/.env.example"

# ----------------------------
# .env anlegen, falls nicht vorhanden
# ----------------------------
FRESH_ENV=0
if [ ! -f "$PROJECT_DIR/.env" ]; then
  cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
  chmod 600 "$PROJECT_DIR/.env"
  FRESH_ENV=1
fi

# Fresh installs use the invoking host identity. Existing installations keep
# their explicit IDs to avoid changing ownership contracts during upgrades.
if [ "$FRESH_ENV" = "1" ]; then
  sed -i -E "s/^PUID=.*/PUID=${HOST_UID}/; s/^PGID=.*/PGID=${HOST_GID}/" "$PROJECT_DIR/.env"
fi

# Existing .env files from older/manual setups may contain duplicate canonical
# IDs. Keep the last assignment (the effective dotenv value) and collapse each
# key to one line so host tools and Compose cannot disagree about ownership.
normalize_env_key_last_wins() {
  local key="$1"
  local count value tmp
  count="$(grep -cE "^${key}=" "$PROJECT_DIR/.env" || true)"
  [ "${count:-0}" -le 1 ] && return 0

  value="$(grep -E "^${key}=" "$PROJECT_DIR/.env" | tail -n1 | cut -d= -f2-)"
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { written = 0 }
    $0 ~ ("^" key "=") {
      if (!written) { print key "=" value; written = 1 }
      next
    }
    { print }
  ' "$PROJECT_DIR/.env" > "$tmp"
  cat "$tmp" > "$PROJECT_DIR/.env"
  rm -f "$tmp"
  echo "[upgrade] Duplicate ${key} entries collapsed; preserved last value: ${value}"
}

normalize_env_key_last_wins "PUID"
normalize_env_key_last_wins "PGID"

# This technical locator is owned by the installation location, not by user
# configuration. It must match the real host path so Compose invocations from
# inside the UI container still create bind mounts against the WSL host path.
set_env_key() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { written = 0 }
    $0 ~ ("^" key "=") {
      if (!written) { print key "=" value; written = 1 }
      next
    }
    { print }
    END { if (!written) print key "=" value }
  ' "$PROJECT_DIR/.env" > "$tmp"
  cat "$tmp" > "$PROJECT_DIR/.env"
  rm -f "$tmp"
}

set_env_key "MEOWHOME_HOST_PROJECT_DIR" "$PROJECT_DIR"
if ! grep -q '^PUID=' "$PROJECT_DIR/.env"; then
  # Upgrade compatibility: v2.2/v2.3 installations may have only the legacy
  # FTP_HOST_UID key. Preserve that ownership contract instead of silently
  # switching existing bind-mounted content to the invoking host user.
  LEGACY_PUID="$(grep -E '^FTP_HOST_UID=[0-9]+$' "$PROJECT_DIR/.env" | tail -n1 | cut -d= -f2- || true)"
  printf '\nPUID=%s\n' "${LEGACY_PUID:-$HOST_UID}" >> "$PROJECT_DIR/.env"
fi
if ! grep -q '^PGID=' "$PROJECT_DIR/.env"; then
  LEGACY_PGID="$(grep -E '^FTP_HOST_GID=[0-9]+$' "$PROJECT_DIR/.env" | tail -n1 | cut -d= -f2- || true)"
  printf 'PGID=%s\n' "${LEGACY_PGID:-$HOST_GID}" >> "$PROJECT_DIR/.env"
fi

# Preserve published port settings from older managed Compose files before the
# installer replaces the managed core file. This is best-effort and only fills
# new .env keys when they do not already exist.
legacy_port_mapping() {
  local service="$1" target="$2" default_bind="$3" default_port="$4"
  local compose_file="$PROJECT_DIR/docker-compose.yml"
  local mapping=""
  if [ -f "$compose_file" ]; then
    mapping="$(awk -v svc="$service" -v target="$target" '
      $0 ~ ("^  " svc ":$") { in_service=1; next }
      in_service && $0 ~ /^  [A-Za-z0-9_-]+:$/ { exit }
      in_service && $0 ~ /^[[:space:]]*-[[:space:]]*/ && $0 ~ (":" target "\"?[[:space:]]*$") {
        line=$0
        sub(/^[[:space:]]*-[[:space:]]*/, "", line)
        gsub(/[\" ]/, "", line)
        print line
        exit
      }
    ' "$compose_file" 2>/dev/null || true)"
  fi

  local bind="$default_bind" port="$default_port"
  if [ -n "$mapping" ] && [[ "$mapping" != *'${'* ]]; then
    local a b c
    IFS=':' read -r a b c <<< "$mapping"
    if [ -n "${c:-}" ]; then
      bind="$a"; port="$b"
    elif [ -n "${b:-}" ]; then
      port="$a"
    fi
  fi
  printf '%s|%s\n' "$bind" "$port"
}

IFS='|' read -r LEGACY_HTTP_BIND LEGACY_HTTP_PORT <<< "$(legacy_port_mapping web 80 0.0.0.0 80)"
IFS='|' read -r LEGACY_HTTPS_BIND LEGACY_HTTPS_PORT <<< "$(legacy_port_mapping web 443 0.0.0.0 443)"
IFS='|' read -r LEGACY_PMA_BIND LEGACY_PMA_PORT <<< "$(legacy_port_mapping phpmyadmin 80 127.0.0.1 8080)"
IFS='|' read -r LEGACY_FTP_BIND LEGACY_FTP_PORT <<< "$(legacy_port_mapping ftp 21 0.0.0.0 21)"

# .env: neue Keys ergaenzen (falls fehlt) – ueberschreibt NICHT bestehende Werte
append_env_if_missing() {
  local key="$1"
  local value="$2"
  if ! grep -qE "^${key}=" "$PROJECT_DIR/.env"; then
    printf '\n%s=%s\n' "$key" "$value" >> "$PROJECT_DIR/.env"
  fi
}

append_env_if_missing "HTTP_BIND" "$LEGACY_HTTP_BIND"
append_env_if_missing "HTTP_PORT" "$LEGACY_HTTP_PORT"
append_env_if_missing "HTTPS_BIND" "$LEGACY_HTTPS_BIND"
append_env_if_missing "HTTPS_PORT" "$LEGACY_HTTPS_PORT"
append_env_if_missing "PHPMYADMIN_BIND" "$LEGACY_PMA_BIND"
append_env_if_missing "PHPMYADMIN_PORT" "$LEGACY_PMA_PORT"
append_env_if_missing "FTP_BIND" "$LEGACY_FTP_BIND"
append_env_if_missing "FTP_PORT" "$LEGACY_FTP_PORT"
append_env_if_missing "CERTBOT_ENABLED" "true"
append_env_if_missing "DNS_UPDATER_ENABLED" "true"
append_env_if_missing "ACME_CHALLENGE" "dns"
append_env_if_missing "DNS_PROVIDER" "cloudflare"
append_env_if_missing "LE_ACCOUNT" ""
append_env_if_missing "CERTBOT_RETRY_SECONDS" "300"
append_env_if_missing "MEOWHOME_UI_BIND" "127.0.0.1"
append_env_if_missing "MEOWHOME_UI_PORT" "9090"
append_env_if_missing "MEOWHOME_UI_USER" "admin"
append_env_if_missing "MEOWHOME_UI_PASS" "admin"
append_env_if_missing "MEOWHOME_WEB_EXTERNAL_NETWORKS" ""



render_web_external_networks() {
  local compose_file="$PROJECT_DIR/docker-compose.yml"
  local raw names=() name web_block="" top_block=""
  raw="$(grep -E '^MEOWHOME_WEB_EXTERNAL_NETWORKS=' "$PROJECT_DIR/.env" | tail -n1 | cut -d= -f2- || true)"
  IFS=',' read -r -a names <<< "$raw"
  for name in "${names[@]}"; do
    name="$(printf '%s' "$name" | xargs)"
    [ -z "$name" ] && continue
    if [[ ! "$name" =~ ^[A-Za-z0-9_.-]+$ ]]; then
      echo "ERROR: invalid external Docker network name: $name" >&2
      exit 1
    fi
    if [ -z "$web_block" ]; then
      web_block=$'    networks:\n      - default'
    fi
    web_block+=$'\n      - '"$name"
    top_block+=$'  '"$name"$':\n    external: true\n    name: '"$name"$'\n'
  done
  python3 - "$compose_file" "$web_block" "$top_block" <<'PY_RENDER'
from pathlib import Path
import sys
path=Path(sys.argv[1]); web=sys.argv[2]; top=sys.argv[3]
s=path.read_text()
s=s.replace('#__MEOWHOME_WEB_EXTERNAL_NETWORKS__', web)
s=s.replace('#__MEOWHOME_TOP_LEVEL_EXTERNAL_NETWORKS__', ('networks:\n'+top.rstrip()) if top else '')
path.write_text(s)
PY_RENDER
}

# ----------------------------
# Beispiel Webroot
# ----------------------------
if [ ! -e "$PROJECT_DIR/htdocs/example.com/index.php" ]; then
  cp "$SCRIPT_DIR/assets/htdocs/example.com/index.php" "$PROJECT_DIR/htdocs/example.com/index.php"
fi

# ----------------------------
# Apache Snippets
# ----------------------------
cp "$SCRIPT_DIR/assets/apache/snippets/php-fpm.conf" "$PROJECT_DIR/apache/snippets/php-fpm.conf"

cp "$SCRIPT_DIR/assets/apache/snippets/ssl-common.conf" "$PROJECT_DIR/apache/snippets/ssl-common.conf"

cp "$SCRIPT_DIR/assets/apache/snippets/cf-safe-redirect.conf" "$PROJECT_DIR/apache/snippets/cf-safe-redirect.conf"

# Public CA used by optional Cloudflare Authenticated Origin Pulls. Shipping it
# as a managed snippet makes SSLCACertificateFile references deterministic; AOP
# enforcement itself remains per-vhost and opt-in.
cp "$SCRIPT_DIR/assets/apache/snippets/cloudflare-origin-pull-ca.pem" "$PROJECT_DIR/apache/snippets/cloudflare-origin-pull-ca.pem"
chmod 0644 "$PROJECT_DIR/apache/snippets/cloudflare-origin-pull-ca.pem"

# ----------------------------
# Apache VHosts (Example)
# ----------------------------
if [ ! -e "$PROJECT_DIR/apache/vhosts/10-example.conf" ]; then
  cp "$SCRIPT_DIR/assets/apache/vhosts/10-example.conf" "$PROJECT_DIR/apache/vhosts/10-example.conf"
fi

if [ ! -e "$PROJECT_DIR/apache/vhosts/20-templates.conf" ]; then
  cp "$SCRIPT_DIR/assets/apache/vhosts/20-templates.conf" "$PROJECT_DIR/apache/vhosts/20-templates.conf"
fi

# ----------------------------
# FTP Container: vsftpd Virtual Users (FIXED)
# ----------------------------
cp "$SCRIPT_DIR/assets/ftp/Dockerfile" "$PROJECT_DIR/ftp/Dockerfile"

cp "$SCRIPT_DIR/assets/ftp/entrypoint.sh" "$PROJECT_DIR/ftp/entrypoint.sh"
chmod +x "$PROJECT_DIR/ftp/entrypoint.sh"

# ----------------------------
# FTPS PEM Builder (aus Let's Encrypt)
# ----------------------------
cp "$SCRIPT_DIR/assets/ftp/build-ftps-pem.sh" "$PROJECT_DIR/ftp/build-ftps-pem.sh"
chmod +x "$PROJECT_DIR/ftp/build-ftps-pem.sh"

# ----------------------------
# Tools: FTP Tool (SQLite + apply) - FIXED VERSION
# ----------------------------
cp "$SCRIPT_DIR/assets/tools/ftp/meowftp.py" "$PROJECT_DIR/tools/ftp/meowftp.py"
chmod +x "$PROJECT_DIR/tools/ftp/meowftp.py"

# ----------------------------
# Debug Scripts fuer FTP
# ----------------------------
cp "$SCRIPT_DIR/assets/tools/ftp/debug-ftp.sh" "$PROJECT_DIR/tools/ftp/debug-ftp.sh"
chmod +x "$PROJECT_DIR/tools/ftp/debug-ftp.sh"

cp "$SCRIPT_DIR/assets/tools/ftp/fix-permissions.sh" "$PROJECT_DIR/tools/ftp/fix-permissions.sh"
chmod +x "$PROJECT_DIR/tools/ftp/fix-permissions.sh"

# ----------------------------
# docker-compose.yml
# - php laeuft als Host-UID/GID (verhindert mixed ownership bei Bind-Mounts)
# - certbot bekommt optional webroot mount fuer HTTP-01
# ----------------------------
cp "$SCRIPT_DIR/assets/root/docker-compose.yml" "$PROJECT_DIR/docker-compose.yml"
render_web_external_networks
# ----------------------------
# Optional: MeowHome Web UI (wenn ./meowhome-ui neben dem Installer liegt)
# ----------------------------
if [ -d "$SCRIPT_DIR/meowhome-ui" ]; then
  echo "[ui] meowhome-ui/ gefunden -> kopiere UI und aktiviere Compose-Service"

  mkdir -p "$PROJECT_DIR/meowhome-ui"
  # copy (inkl. Unterordner)
  cp -a "$SCRIPT_DIR/meowhome-ui/." "$PROJECT_DIR/meowhome-ui/"

  # Stelle sicher, dass der Platzhalter existiert
  if ! grep -q "#__MEOWHOME_UI_SERVICE__" "$PROJECT_DIR/docker-compose.yml"; then
    echo "[ui] WARN: UI Platzhalter nicht gefunden, breche UI-Aktivierung ab"
  else
    # Ersetze Marker durch echten Service-Block
    # Hinweis: sed -i funktioniert je nach Umgebung; in Debian/Ubuntu ok.
    sed -i 's|^[[:space:]]*#__MEOWHOME_UI_SERVICE__.*$|  ui:\n    build:\n      context: ./meowhome-ui\n      dockerfile: Dockerfile\n    container_name: meowhome_ui\n    env_file: ./.env\n    environment:\n      MEOWHOME_PROJECT_DIR: /meowhome\n      MEOWHOME_UI_BIND: ${MEOWHOME_UI_BIND:-127.0.0.1}\n      MEOWHOME_UI_PORT: ${MEOWHOME_UI_PORT:-9090}\n      MEOWHOME_UI_USER: ${MEOWHOME_UI_USER:-admin}\n      MEOWHOME_UI_PASS: ${MEOWHOME_UI_PASS:-admin}\n    ports:\n      - \"${MEOWHOME_UI_BIND:-127.0.0.1}:${MEOWHOME_UI_PORT:-9090}:8000\"\n    volumes:\n      - "${MEOWHOME_HOST_PROJECT_DIR:-.}:/meowhome:rw"\n      - /var/run/docker.sock:/var/run/docker.sock\n    restart: unless-stopped|g' "$PROJECT_DIR/docker-compose.yml"

    # Installer materializes files only. Lifecycle remains with Compose and is
    # never mutated implicitly during an upgrade.
  fi
else
  # wenn kein UI vorhanden: Marker entfernen (sauberer Compose)
  sed -i '/#__MEOWHOME_UI_SERVICE__/d' "$PROJECT_DIR/docker-compose.yml" 2>/dev/null || true
fi


# ----------------------------
# web/Dockerfile (Apache)
# ----------------------------
cp "$SCRIPT_DIR/assets/web/Dockerfile" "$PROJECT_DIR/web/Dockerfile"

# ----------------------------
# php/Dockerfile + ini
# ----------------------------
cp "$SCRIPT_DIR/assets/php/Dockerfile" "$PROJECT_DIR/php/Dockerfile"

cp "$SCRIPT_DIR/assets/php/custom.ini" "$PROJECT_DIR/php/custom.ini"

# ----------------------------
# certbot (Dockerfile + run.sh)
# ----------------------------
cp "$SCRIPT_DIR/assets/certbot/Dockerfile" "$PROJECT_DIR/certbot/Dockerfile"

cp "$SCRIPT_DIR/assets/certbot/run.sh" "$PROJECT_DIR/certbot/run.sh"
chmod +x "$PROJECT_DIR/certbot/run.sh"

# ----------------------------
# dns-updater (Dockerfile + run.sh)
# ----------------------------
cp "$SCRIPT_DIR/assets/dns-updater/Dockerfile" "$PROJECT_DIR/dns-updater/Dockerfile"

cp "$SCRIPT_DIR/assets/dns-updater/run.sh" "$PROJECT_DIR/dns-updater/run.sh"
chmod +x "$PROJECT_DIR/dns-updater/run.sh"

# ----------------------------
# Kopiere User-Scripte (wenn neben init Script vorhanden)
# ----------------------------
DNS_SRC="$SCRIPT_DIR/DNSUpdatecloudflare.py"
CERT_SRC="$SCRIPT_DIR/certbot.py"

if [ -f "$DNS_SRC" ]; then
  cp -f "$DNS_SRC" "$PROJECT_DIR/dns-updater/DNSUpdatecloudflare.py"
else
  cat > "$PROJECT_DIR/dns-updater/DNSUpdatecloudflare.py" <<'PY'
print("DNSUpdatecloudflare.py fehlt. Bitte neben init-meowhome.sh legen und Script erneut ausfuehren.")
PY
fi

if [ -f "$CERT_SRC" ]; then
  cp -f "$CERT_SRC" "$PROJECT_DIR/legacy/certbot.py"
else
  cat > "$PROJECT_DIR/legacy/certbot.py" <<'PY'
print("certbot.py fehlt. Optional: lege es neben init-meowhome.sh, dann wird es nach legacy/ kopiert.")
PY
fi

# ----------------------------
# Abschluss
# ----------------------------
cat <<OUT

================================================================
✅ MeowHome erfolgreich erstellt/aktualisiert!
================================================================

Installation: $PROJECT_DIR

WICHTIGE SCHRITTE:
==================

WebUI: http://127.0.0.1:9090 (Default: admin/admin)
Nach dem ersten Start direkt in /setup die .env und Login-Daten anpassen.

1️⃣  KONFIGURATION
   nano $PROJECT_DIR/.env

   Wichtig:
   - DOMAINS
   - LE_EMAIL
   - LE_ACCOUNT (optional; bei Erstinstallation leer lassen.
     Nur setzen wenn certbot "Please choose an account" meldet.
     Die Account-IDs stehen dann im Log: docker logs -f meowhome_certbot)
   - CERTBOT_ENABLED / DNS_UPDATER_ENABLED (optional)
   - ACME_CHALLENGE (dns=default / http=fallback)
   - CLOUDFLARE_API_TOKEN (nur noetig wenn ACME_CHALLENGE=dns oder DNS_UPDATER_ENABLED=true)
   - FTP_PUBLIC_HOST (oeffentliche IP/Domain!)
   - DB Passwoerter aendern

2️⃣  PORTS PRUeFEN
   - 80, 443 (HTTP/HTTPS)
   - 21 (FTP)
   - 21000-21010 (FTP Passive)

   Hinweis:
   - ACME_CHALLENGE=http benoetigt Port 80 extern erreichbar
   - HTTP-01 unterstuetzt KEIN Wildcard (*.domain)

3️⃣  SYSTEM STARTEN
   cd $PROJECT_DIR
   docker compose up -d --build

4️⃣  FTP BENUTZER ERSTELLEN
   cd $PROJECT_DIR
   ./tools/ftp/meowftp.py add webmaster example.com
   ./tools/ftp/meowftp.py add admin "" --allow-all
   sudo ./tools/ftp/meowftp.py apply

5️⃣  ZERTIFIKATE
   docker logs -f meowhome_certbot

   Ohne Cloudflare:
   - DNS_UPDATER_ENABLED=false
   - ACME_CHALLENGE=http
   - (Wildcard geht dann nicht)

   Fuer FTPS (nach erfolgreicher Cert-Erstellung):
   ./ftp/build-ftps-pem.sh example.com
   Dann in .env: FTP_TLS=YES setzen
   docker compose restart ftp

NUeTZLICHE BEFEHLE:
==================
docker compose ps
docker compose logs -f
./tools/warmup.sh
./tools/permissions_hardening.sh --apply
sudo ./tools/backup/backup.sh        # without htdocs
sudo ./tools/backup/backup.sh --with-htdocs
$PROJECT_DIR/tools/backup/restore.sh $PROJECT_DIR/backups/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz



OUT
