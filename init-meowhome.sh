#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# MeowHome Bootstrapper (Core + Tools + FTP Virtual Users)
# Version: 2.0 (Fixed FTP Authentication + Permissions Hardening)
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
# - Tool: ./tools/permissions_hardening.sh (wird bei Installation automatisch ausgefuehrt)
#
# NEW (Certbot/DNS optional):
# - CERTBOT_ENABLED / DNS_UPDATER_ENABLED toggles (container idles when disabled)
# - ACME_CHALLENGE=dns (default, Cloudflare DNS-01, wildcard) or ACME_CHALLENGE=http (HTTP-01 fallback, no wildcard)
# ============================================================

PROJECT_DIR="${1:-$HOME/meowhome}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$PROJECT_DIR"

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
if [ ! -f "$PROJECT_DIR/.env" ]; then
  cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
fi

# .env: PUID/PGID automatisch ergaenzen (falls fehlt)
if ! grep -q '^PUID=' "$PROJECT_DIR/.env"; then
  printf '\nPUID=%s\n' "$(id -u)" >> "$PROJECT_DIR/.env"
fi
if ! grep -q '^PGID=' "$PROJECT_DIR/.env"; then
  printf 'PGID=%s\n' "$(id -g)" >> "$PROJECT_DIR/.env"
fi

# .env: neue Toggle Keys ergaenzen (falls fehlt) – ueberschreibt NICHT bestehende Werte
append_env_if_missing() {
  local key="$1"
  local value="$2"
  if ! grep -qE "^${key}=" "$PROJECT_DIR/.env"; then
    printf '\n%s=%s\n' "$key" "$value" >> "$PROJECT_DIR/.env"
  fi
}

append_env_if_missing "CERTBOT_ENABLED" "true"
append_env_if_missing "DNS_UPDATER_ENABLED" "true"
append_env_if_missing "ACME_CHALLENGE" "dns"
append_env_if_missing "DNS_PROVIDER" "cloudflare"
append_env_if_missing "LE_ACCOUNT" ""
append_env_if_missing "MEOWHOME_UI_BIND" "127.0.0.1"
append_env_if_missing "MEOWHOME_UI_PORT" "9090"
append_env_if_missing "MEOWHOME_UI_USER" "admin"
append_env_if_missing "MEOWHOME_UI_PASS" "admin"


# ----------------------------
# Beispiel Webroot
# ----------------------------
cp "$SCRIPT_DIR/assets/htdocs/example.com/index.php" "$PROJECT_DIR/htdocs/example.com/index.php"

# ----------------------------
# Apache Snippets
# ----------------------------
cp "$SCRIPT_DIR/assets/apache/snippets/php-fpm.conf" "$PROJECT_DIR/apache/snippets/php-fpm.conf"

cp "$SCRIPT_DIR/assets/apache/snippets/ssl-common.conf" "$PROJECT_DIR/apache/snippets/ssl-common.conf"

cp "$SCRIPT_DIR/assets/apache/snippets/cf-safe-redirect.conf" "$PROJECT_DIR/apache/snippets/cf-safe-redirect.conf"

# ----------------------------
# Apache VHosts (Example)
# ----------------------------
cp "$SCRIPT_DIR/assets/apache/vhosts/10-example.conf" "$PROJECT_DIR/apache/vhosts/10-example.conf"

cp "$SCRIPT_DIR/assets/apache/vhosts/20-templates.conf" "$PROJECT_DIR/apache/vhosts/20-templates.conf"

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
    sed -i 's|^[[:space:]]*#__MEOWHOME_UI_SERVICE__.*$|  ui:\n    build:\n      context: ./meowhome-ui\n      dockerfile: Dockerfile\n    container_name: meowhome_ui\n    env_file: ./.env\n    environment:\n      MEOWHOME_PROJECT_DIR: /meowhome\n      MEOWHOME_UI_BIND: ${MEOWHOME_UI_BIND:-127.0.0.1}\n      MEOWHOME_UI_PORT: ${MEOWHOME_UI_PORT:-9090}\n      MEOWHOME_UI_USER: ${MEOWHOME_UI_USER:-admin}\n      MEOWHOME_UI_PASS: ${MEOWHOME_UI_PASS:-admin}\n    ports:\n      - \"${MEOWHOME_UI_BIND:-127.0.0.1}:${MEOWHOME_UI_PORT:-9090}:8000\"\n    volumes:\n      - ./:/meowhome:rw\n      - /var/run/docker.sock:/var/run/docker.sock\n    restart: unless-stopped|g' "$PROJECT_DIR/docker-compose.yml"

    # UI NICHT automatisch starten.
    # Der User soll nach .env Anpassung alles gesammelt starten:
    #   cd "$PROJECT_DIR" && docker compose up -d --build
    if docker ps -a --format '{{.Names}}' | grep -qx "meowhome_ui"; then
      echo "[ui] Entferne bestehenden Container meowhome_ui (Name-Konflikt vermeiden)..."
      docker rm -f meowhome_ui >/dev/null 2>&1 || true
    fi
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
# Automatisch: Permissions Hardening anwenden
# ----------------------------
"$PROJECT_DIR/tools/permissions_hardening.sh" --project "$PROJECT_DIR" --apply || true

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
   ./tools/ftp/meowftp.py add admin ""
   ./tools/ftp/meowftp.py apply

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
./tools/backup/backup.sh (without htdocs)
./tools/backup/backup.sh --with-htdocs
~/meowhome/tools/backup/restore.sh ~/meowhome/backups/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz



OUT
