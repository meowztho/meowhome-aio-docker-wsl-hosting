#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# MeowHome Bootstrapper (Core + Tools + FTP Virtual Users)
# Version: 2.0 (Fixed FTP Authentication)
# - erstellt ~/meowhome komplett
# - Tools unter ./tools (modular erweiterbar)
# - FTP: vsftpd Virtual Users + Tool (SQLite auf Host)
# - phpMyAdmin nur auf 127.0.0.1 gebunden
# - kopiert DNSUpdatecloudflare.py + certbot.py, wenn neben Script vorhanden
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
  "$PROJECT_DIR/tools/apache" \
  "$PROJECT_DIR/db" \
  "$PROJECT_DIR/letsencrypt" \
  "$PROJECT_DIR/state" \
  "$PROJECT_DIR/legacy"
  
# ----------------------------
# Tools: Warmup (WSL Mount Race Fix)
# - wartet auf Docker
# - optional: checkt ob /var/www Mount "steht"
# - restarted Container in definierter Reihenfolge
# ----------------------------
cat > "$PROJECT_DIR/tools/warmup.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

# Project root (…/tools -> project root)
BASE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$BASE"

LOG_DIR="$BASE/state"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/warmup.log"

ts() { date +"%Y-%m-%d %H:%M:%S"; }
log() { echo "[$(ts)] $*" | tee -a "$LOG"; }

log "warmup: start (base=$BASE)"

# 1) Wait for Docker daemon (WSL boot race)
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

# 2) Optional: wait a bit for mounts to settle (WSL /mnt / bind timing)
sleep 10

# 3) Restart in gewünschter Reihenfolge:
# db -> php -> web(apache) -> phpmyadmin -> dns_updater -> ftp -> certbot
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
SH
chmod +x "$PROJECT_DIR/tools/warmup.sh"

# ----------------------------
# .gitignore (Secrets + Persistenz schützen)
# ----------------------------
cat > "$PROJECT_DIR/.gitignore" <<'GIT'
.env
.env.local
.env.sebastian
state/
db/
letsencrypt/
ftp/ssl/
ftp/data/users.db
ftp/data/users.txt
ftp/users.sqlite
__pycache__/
*.pyc
GIT

# ----------------------------
# .env.example (weitergebbar)
# ----------------------------
cat > "$PROJECT_DIR/.env.example" <<'ENV'
# ============================================================
# MeowHome - Konfiguration (Template)
# ============================================================

# Windows/LAN Host-IP (für Reverse Proxy Ziele, z.B. Jellyfin)
WIN_HOST_IP=192.168.178.59

# Zonen (Comma-separated). Für Certs (Wildcard) und DNS-Updater.
DOMAINS=example.com,test.de

# Let's Encrypt Email
LE_EMAIL=admin@example.com

# Cloudflare API Token (Zone:DNS Edit)
CLOUDFLARE_API_TOKEN=PASTE_TOKEN_HERE

# DNS propagation wait (Sekunden)
CF_PROPAGATION_SECONDS=30

# Certbot Mode:
WILDCARD=true
HOSTS=example.com,www.example.com,shop.example.com,test.de,www.test.de,shop.test.de

# DNS Updater: A-Records pro Zone (Slug = domain klein, sonderzeichen -> _)
A_RECORDS_example_com=example.com,www.example.com,shop.example.com
A_RECORDS_test_de=test.de,www.test.de,shop.test.de

SPF_UPDATE_example_com=false
SPF_UPDATE_test_de=false

PROXIED_DEFAULT=true
PROXIED_OVERRIDES=mail.example.com=false

FORCE_UPDATE_HOUR=6
CHECK_INTERVAL_SECONDS=600
RETRY_INTERVAL_SECONDS=300

# MariaDB
DB_ROOT_PASSWORD=change-me
DB_NAME=app
DB_USER=app
DB_PASSWORD=change-me

# ------------------------------------------------------------
# FTP / FTPS (vsftpd Virtual Users)
# ------------------------------------------------------------
FTP_ENABLED=true

# Passive Ports (müssen am Router weitergeleitet werden)
FTP_PASV_MIN=21000
FTP_PASV_MAX=21010

# WICHTIG:
# FTP_PUBLIC_HOST ist NICHT deine interne IP.
# Setze hier die öffentliche IP oder einen DNS Namen, unter dem du extern erreichbar bist.
# (192.168.178.59 ist intern und nur für LAN-Tests geeignet.)
FTP_PUBLIC_HOST=CHANGE-ME.example.com

# FTPS (TLS) aktivieren?
# vsftpd erwartet YES/NO (nicht true/false)
FTP_TLS=NO

# Domain, deren Let's Encrypt Certs für FTPS genutzt werden
FTP_CERT_DOMAIN=example.com

# Dateirechte: Host UID/GID für Ordner unter htdocs (WSL meist 1000:1000)
FTP_HOST_UID=1000
FTP_HOST_GID=1000

# WICHTIG für vsftpd: Berechtigungen setzen
# Ordner unter /var/www müssen korrekte Berechtigungen haben
# Beispiel: chown -R ftp:ftp /var/www/example.com
ENV

# ----------------------------
# .env anlegen, falls nicht vorhanden
# ----------------------------
if [ ! -f "$PROJECT_DIR/.env" ]; then
  cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
fi

# ----------------------------
# Beispiel Webroot
# ----------------------------
cat > "$PROJECT_DIR/htdocs/example.com/index.php" <<'PHP'
<?php
echo "MeowHome OK: example.com";
PHP

# ----------------------------
# Apache Snippets
# ----------------------------
cat > "$PROJECT_DIR/apache/snippets/php-fpm.conf" <<'CONF'
<FilesMatch "\.php$">
    SetHandler "proxy:fcgi://meowhome_php:9000"
</FilesMatch>
DirectoryIndex index.php index.html
CONF

cat > "$PROJECT_DIR/apache/snippets/ssl-common.conf" <<'CONF'
SSLEngine on
RequestHeader set X-Forwarded-Proto "https"
RequestHeader set X-Forwarded-Ssl "on"
RequestHeader set X-Forwarded-Port "443"
CONF

cat > "$PROJECT_DIR/apache/snippets/cf-safe-redirect.conf" <<'CONF'
RewriteEngine On
RewriteCond %{HTTP:X-Forwarded-Proto} !https
RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [R=301,L]
CONF

# ----------------------------
# Apache VHosts (Example)
# Hinweis: SSL-Block kann fehlschlagen, wenn Certs noch nicht existieren.
# Wenn nötig, den 443-Block temporär auskommentieren.
# ----------------------------
cat > "$PROJECT_DIR/apache/vhosts/10-example.conf" <<'CONF'
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example.com

    <Directory /var/www/example.com>
        AllowOverride All
        Require all granted
    </Directory>

    Include /etc/apache2/snippets/cf-safe-redirect.conf
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /var/www/example.com

    <Directory /var/www/example.com>
        AllowOverride All
        Require all granted
    </Directory>

    Include /etc/apache2/snippets/ssl-common.conf
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

    Include /etc/apache2/snippets/php-fpm.conf
</VirtualHost>
CONF

cat > "$PROJECT_DIR/apache/vhosts/20-templates.conf" <<'CONF'
# Reverse Proxy Template (Windows/LAN Ziel)
#
# Beispiel Jellyfin:
#
# <VirtualHost *:80>
#     ServerName video.example.com
#     ProxyRequests Off
#     ProxyPreserveHost On
#     ProxyPass "/" "http://${WIN_HOST_IP}:8096/"
#     ProxyPassReverse "/" "http://${WIN_HOST_IP}:8096/"
# </VirtualHost>
#
# <VirtualHost *:443>
#     ServerName video.example.com
#     Include /etc/apache2/snippets/ssl-common.conf
#     SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
#     SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem
#     ProxyRequests Off
#     ProxyPreserveHost On
#     ProxyPass "/" "http://${WIN_HOST_IP}:8096/"
#     ProxyPassReverse "/" "http://${WIN_HOST_IP}:8096/"
# </VirtualHost>
CONF

# ----------------------------
# FTP Container: vsftpd Virtual Users (FIXED)
# ----------------------------
cat > "$PROJECT_DIR/ftp/Dockerfile" <<'DOCKER'
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    vsftpd db5.3-util openssl python3 \
    libpam-modules libpam-runtime \
 && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 21
ENTRYPOINT ["/entrypoint.sh"]
DOCKER

cat > "$PROJECT_DIR/ftp/entrypoint.sh" <<'SH'
#!/bin/sh
set -eu

mkdir -p /var/run/vsftpd/empty
chmod 755 /var/run/vsftpd/empty

CFG_DIR="/etc/vsftpd"
mkdir -p "$CFG_DIR/users.d"

resolve_ipv4() {
  v="$1"
  if echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "$v"
    return 0
  fi

  if command -v getent >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "$v" 2>/dev/null | awk 'NR==1{print $1}')"
    if [ -n "${ip:-}" ]; then
      echo "$ip"
      return 0
    fi
  fi

  if command -v python3 >/dev/null 2>&1; then
    ip="$(python3 - <<PY 2>/dev/null || true
import socket
try:
    print(socket.gethostbyname("$v"))
except Exception:
    pass
PY
)"
    if [ -n "${ip:-}" ]; then
      echo "$ip"
      return 0
    fi
  fi

  echo "$v"
}

PASV_HOST="${FTP_PUBLIC_HOST:-127.0.0.1}"
PASV_ADDR="$(resolve_ipv4 "$PASV_HOST")"

echo "[FTP] Starting vsftpd with PASV address: $PASV_ADDR"

# vsftpd.conf mit korrekten Einstellungen
cat > "$CFG_DIR/vsftpd.conf" <<EOF
# Daemon
listen=YES
listen_ipv6=NO
background=NO

# Logging (wichtig für Debug)
xferlog_enable=YES
log_ftp_protocol=YES
vsftpd_log_file=/var/log/vsftpd.log

# Security
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
use_localtime=YES
seccomp_sandbox=NO

# Chroot
chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty

# Virtual Users (KRITISCH!)
pam_service_name=vsftpd_virtual
guest_enable=YES
guest_username=ftp
virtual_use_local_privs=YES
user_config_dir=${CFG_DIR}/users.d

# Default local_root (wird per-user überschrieben)
local_root=/var/www

# Passive Mode
pasv_enable=YES
pasv_min_port=${FTP_PASV_MIN:-21000}
pasv_max_port=${FTP_PASV_MAX:-21010}
pasv_address=${PASV_ADDR}
pasv_addr_resolve=NO

# TLS/SSL
ssl_enable=${FTP_TLS:-NO}
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
force_local_logins_ssl=${FTP_TLS:-NO}
force_local_data_ssl=${FTP_TLS:-NO}
EOF

chown root:root "$CFG_DIR/vsftpd.conf"
chmod 600 "$CFG_DIR/vsftpd.conf"

# PAM Config (KRITISCH: crypt=crypt muss gesetzt sein!)
cat > /etc/pam.d/vsftpd_virtual <<EOF
auth required pam_userdb.so db=${CFG_DIR}/users crypt=crypt
account required pam_userdb.so db=${CFG_DIR}/users crypt=crypt
session required pam_loginuid.so
EOF

chown root:root /etc/pam.d/vsftpd_virtual
chmod 644 /etc/pam.d/vsftpd_virtual

echo "[FTP] PAM config:"
cat /etc/pam.d/vsftpd_virtual

# Guest user "ftp" erstellen
if ! id ftp >/dev/null 2>&1; then
  useradd -m -d /var/www -s /usr/sbin/nologin ftp || true
  echo "[FTP] Created user 'ftp'"
fi

# Warte auf users.db (max 30 Sekunden)
echo "[FTP] Waiting for users.db..."
for i in $(seq 1 30); do
  if [ -f "$CFG_DIR/users.db" ]; then
    echo "[FTP] users.db found"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "[FTP] WARNING: users.db not found after 30s, creating empty DB"
    touch "$CFG_DIR/users.txt"
    if command -v db5.3_load >/dev/null 2>&1; then
      db5.3_load -T -t hash -f "$CFG_DIR/users.txt" "$CFG_DIR/users.db" || true
    else
      db_load -T -t hash -f "$CFG_DIR/users.txt" "$CFG_DIR/users.db" || true
    fi
  fi
  sleep 1
done

# Permissions
chown root:root "$CFG_DIR/users.db" 2>/dev/null || true
chmod 600 "$CFG_DIR/users.db" 2>/dev/null || true

if [ -d "$CFG_DIR/users.d" ]; then
  chown root:root "$CFG_DIR/users.d" || true
  chmod 755 "$CFG_DIR/users.d" || true
  find "$CFG_DIR/users.d" -maxdepth 1 -type f -exec chown root:root {} \; 2>/dev/null || true
  find "$CFG_DIR/users.d" -maxdepth 1 -type f -exec chmod 600 {} \; 2>/dev/null || true
fi

# /var/www ownership
chown -R ftp:ftp /var/www 2>/dev/null || true

echo "[FTP] Config complete, starting vsftpd..."
echo "[FTP] users.db status:"
ls -la "$CFG_DIR/users.db" 2>/dev/null || echo "  (not found)"

exec /usr/sbin/vsftpd "$CFG_DIR/vsftpd.conf"
SH
chmod +x "$PROJECT_DIR/ftp/entrypoint.sh"

# ----------------------------
# FTPS PEM Builder (aus Let's Encrypt)
# ----------------------------
cat > "$PROJECT_DIR/ftp/build-ftps-pem.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

DOMAIN="${1:-}"
if [ -z "$DOMAIN" ]; then
  echo "Usage: ./ftp/build-ftps-pem.sh <domain>"
  exit 1
fi

CRT="letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY="letsencrypt/live/${DOMAIN}/privkey.pem"
OUT="ftp/ssl/vsftpd.pem"

if [ ! -f "$CRT" ] || [ ! -f "$KEY" ]; then
  echo "Error: certificate files not found:"
  echo "  $CRT"
  echo "  $KEY"
  exit 1
fi

cat "$CRT" "$KEY" > "$OUT"
chmod 600 "$OUT"
echo "OK: created $OUT"
SH
chmod +x "$PROJECT_DIR/ftp/build-ftps-pem.sh"

# ----------------------------
# Tools: FTP Tool (SQLite + apply) - FIXED VERSION
# ----------------------------
cat > "$PROJECT_DIR/tools/ftp/meowftp.py" <<'PY'
#!/usr/bin/env python3
import os
import sys
import sqlite3
import getpass
import subprocess
import time
from typing import Tuple

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(BASE, "ftp", "users.sqlite")
HTDOCS = os.path.join(BASE, "htdocs")
FTP_DATA = os.path.join(BASE, "ftp", "data")
ENV_PATH = os.path.join(BASE, ".env")

def sh(cmd: list[str]) -> None:
    subprocess.check_call(cmd)

def sh_out(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()

def read_env_value(key: str, default: str = "") -> str:
    if not os.path.exists(ENV_PATH):
        return default
    with open(ENV_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == key:
                return v.strip()
    return default

def host_uid_gid() -> Tuple[int, int]:
    uid = int(read_env_value("FTP_HOST_UID", "1000") or "1000")
    gid = int(read_env_value("FTP_HOST_GID", "1000") or "1000")
    return uid, gid

def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        pass_hash TEXT NOT NULL,
        home_rel TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1
      )
    """)
    con.commit()
    return con

def hash_pw_sha512_crypt(password: str) -> str:
    """Erstellt SHA512-crypt Hash (kompatibel mit PAM userdb crypt=crypt)"""
    out = sh_out(["openssl", "passwd", "-6", password])
    if not out.startswith("$6$"):
        raise RuntimeError("Password hash generation failed.")
    return out

def prompt_password() -> str:
    p1 = getpass.getpass("Passwort: ")
    p2 = getpass.getpass("Passwort (wiederholen): ")
    if not p1 or p1 != p2:
        raise SystemExit("Passwörter stimmen nicht überein oder sind leer.")
    return p1

def confirm(msg: str) -> None:
    ans = input(f"{msg} (yes/no): ").strip().lower()
    if ans != "yes":
        raise SystemExit("Abgebrochen.")

def normalize_home_rel(home_rel: str) -> str:
    home_rel = home_rel.strip().lstrip("/").replace("\\", "/")
    if home_rel in (".", "./"):
        home_rel = ""
    if ".." in home_rel.split("/"):
        raise SystemExit("Ungültiger Pfad (.. nicht erlaubt).")
    return home_rel

def ensure_home_dir(home_rel: str) -> None:
    if home_rel == "":
        return
    path = os.path.join(HTDOCS, home_rel)
    os.makedirs(path, exist_ok=True)
    uid, gid = host_uid_gid()
    try:
        os.chown(path, uid, gid)
        os.chmod(path, 0o775)
    except PermissionError:
        pass

def cmd_list() -> None:
    con = db()
    rows = list(con.execute("SELECT username, home_rel, enabled FROM users ORDER BY username"))
    if not rows:
        print("Keine User vorhanden.")
        return
    print(f"{'Username':<20} {'Enabled':<8} {'Path':<40}")
    print("-" * 70)
    for u, home_rel, enabled in rows:
        target = "htdocs/" + (home_rel if home_rel else "(all domains)")
        status = "✓" if enabled else "✗"
        print(f"{u:<20} {status:<8} {target:<40}")

def cmd_add(username: str, home_rel: str) -> None:
    username = username.strip()
    if not username:
        raise SystemExit("Username fehlt.")
    home_rel = normalize_home_rel(home_rel)

    if home_rel == "":
        confirm("⚠️  home_rel ist leer -> User sieht ALLE Domain-Ordner unter htdocs. Fortfahren?")

    pw = prompt_password()
    ph = hash_pw_sha512_crypt(pw)

    ensure_home_dir(home_rel)

    con = db()
    con.execute(
        "INSERT OR REPLACE INTO users(username, pass_hash, home_rel, enabled) VALUES(?,?,?,1)",
        (username, ph, home_rel),
    )
    con.commit()
    print(f"✓ User '{username}' gespeichert (home_rel='{home_rel or '(root)'}')")
    print("⚠️  Führe 'meowftp.py apply' aus um Änderungen zu aktivieren!")

def cmd_del(username: str) -> None:
    con = db()
    cur = con.execute("DELETE FROM users WHERE username=?", (username,))
    con.commit()
    if cur.rowcount == 0:
        print("❌ User nicht gefunden.")
    else:
        print(f"✓ User '{username}' gelöscht")
        print("⚠️  Führe 'meowftp.py apply' aus um Änderungen zu aktivieren!")

def cmd_enable(username: str, enabled: int) -> None:
    con = db()
    cur = con.execute("UPDATE users SET enabled=? WHERE username=?", (enabled, username))
    con.commit()
    if cur.rowcount == 0:
        print("❌ User nicht gefunden.")
    else:
        status = "aktiviert" if enabled else "deaktiviert"
        print(f"✓ User '{username}' {status}")
        print("⚠️  Führe 'meowftp.py apply' aus um Änderungen zu aktivieren!")

def cmd_passwd(username: str) -> None:
    con = db()
    row = con.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        raise SystemExit("❌ User nicht gefunden.")
    pw = prompt_password()
    ph = hash_pw_sha512_crypt(pw)
    con.execute("UPDATE users SET pass_hash=? WHERE username=?", (ph, username))
    con.commit()
    print(f"✓ User '{username}' password updated")
    print("⚠️  Führe 'meowftp.py apply' aus um Änderungen zu aktivieren!")

def cmd_home(username: str, home_rel: str) -> None:
    home_rel = normalize_home_rel(home_rel)
    if home_rel == "":
        confirm("⚠️  home_rel ist leer -> User sieht ALLE Domain-Ordner unter htdocs. Fortfahren?")
    ensure_home_dir(home_rel)
    con = db()
    cur = con.execute("UPDATE users SET home_rel=? WHERE username=?", (home_rel, username))
    con.commit()
    if cur.rowcount == 0:
        print("❌ User nicht gefunden.")
    else:
        print(f"✓ User '{username}' home_rel='{home_rel or '(root)'}'")
        print("⚠️  Führe 'meowftp.py apply' aus um Änderungen zu aktivieren!")

def docker_compose_up_ftp() -> None:
    compose_file = os.path.join(BASE, "docker-compose.yml")
    sh(["docker", "compose", "-f", compose_file, "up", "-d", "ftp"])

def wait_for_container(max_wait: int = 30) -> None:
    """Warte bis FTP Container bereit ist"""
    print("⏳ Warte auf FTP Container...")
    for i in range(max_wait):
        try:
            subprocess.run(
                ["docker", "exec", "meowhome_ftp", "test", "-d", "/etc/vsftpd"],
                capture_output=True, check=True, timeout=5
            )
            print("✓ Container ist bereit")
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            if i == max_wait - 1:
                raise SystemExit("❌ Container startet nicht korrekt")
            time.sleep(1)

def apply() -> None:
    """Aktiviert User-Änderungen im FTP Server"""
    
    # Root check
    if os.geteuid() != 0:
        print("⚠️  apply benötigt sudo/root")
        print("Starte erneut mit sudo...")
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

    print("=" * 60)
    print("MeowFTP Apply - Aktiviere User-Änderungen")
    print("=" * 60)
    print()

    # 1. Container starten
    print("1️⃣  Starte FTP Container...")
    docker_compose_up_ftp()
    wait_for_container()

    # 2. Lade Users aus DB
    con = db()
    rows = list(con.execute(
        "SELECT username, pass_hash, home_rel FROM users WHERE enabled=1 ORDER BY username"
    ))

    if not rows:
        print("⚠️  Keine aktiven User in Datenbank")
        return

    print(f"2️⃣  Gefunden: {len(rows)} aktive User")

    # 3. Erstelle users.txt content
    users_txt_content = ""
    for username, pass_hash, _ in rows:
        users_txt_content += f"{username}\n{pass_hash}\n"

    # 4. Schreibe users.txt direkt in Container
    print("3️⃣  Schreibe users.txt in Container...")
    subprocess.run(
        ["docker", "exec", "-i", "meowhome_ftp", "sh", "-c", 
         "cat > /etc/vsftpd/users.txt"],
        input=users_txt_content.encode(),
        check=True
    )

    # 5. Konvertiere zu Berkeley DB
    print("4️⃣  Erstelle users.db...")
    
    # Prüfe welcher db_load verfügbar ist
    try:
        subprocess.run(
            ["docker", "exec", "meowhome_ftp", "which", "db5.3_load"],
            capture_output=True, check=True
        )
        db_cmd = "db5.3_load"
    except subprocess.CalledProcessError:
        db_cmd = "db_load"
    
    subprocess.run([
        "docker", "exec", "meowhome_ftp", "sh", "-c",
        f"cd /etc/vsftpd && {db_cmd} -T -t hash -f users.txt users.db"
    ], check=True)

    # 6. Erstelle User-Configs
    print("5️⃣  Erstelle User-Configs...")
    for username, _, home_rel in rows:
        local_root = "/var/www" if not home_rel else f"/var/www/{home_rel}"
        config_content = f"local_root={local_root}\n"
        
        subprocess.run([
            "docker", "exec", "-i", "meowhome_ftp", "sh", "-c",
            f"cat > /etc/vsftpd/users.d/{username}"
        ], input=config_content.encode(), check=True)
        
        ensure_home_dir(home_rel)

    # 7. Setze Permissions
    print("6️⃣  Setze Permissions...")
    subprocess.run([
        "docker", "exec", "meowhome_ftp", "sh", "-c",
        """
        chown root:root /etc/vsftpd/vsftpd.conf /etc/vsftpd/users.txt /etc/vsftpd/users.db
        chmod 600 /etc/vsftpd/vsftpd.conf /etc/vsftpd/users.txt /etc/vsftpd/users.db
        chown root:root /etc/vsftpd/users.d
        chmod 755 /etc/vsftpd/users.d
        find /etc/vsftpd/users.d -type f -exec chmod 600 {} \\;
        chown -R ftp:ftp /var/www
        """
    ], check=True)

    # 8. Restart FTP
    print("7️⃣  Restart FTP Service...")
    subprocess.run([
        "docker", "compose", "-f", os.path.join(BASE, "docker-compose.yml"),
        "restart", "ftp"
    ], check=True)

    # Warte kurz
    time.sleep(2)

    # 9. Verify
    print()
    print("=" * 60)
    print("✅ Apply erfolgreich!")
    print("=" * 60)
    print()
    print(f"Aktive User: {len(rows)}")
    for username, _, home_rel in rows:
        path = f"htdocs/{home_rel}" if home_rel else "htdocs/ (all)"
        print(f"  • {username:<20} → {path}")
    print()
    print("Debug mit: docker logs meowhome_ftp")
    print()

def usage() -> None:
    print("\n".join([
        "",
        "MeowFTP - FTP User Management",
        "=" * 50,
        "",
        "Usage:",
        "  meowftp.py list",
        "  meowftp.py add <user> <htdocs_subfolder_or_empty>",
        "  meowftp.py del <user>",
        "  meowftp.py enable <user>",
        "  meowftp.py disable <user>",
        "  meowftp.py passwd <user>",
        "  meowftp.py home <user> <htdocs_subfolder_or_empty>",
        "  meowftp.py apply",
        "",
        "Beispiele:",
        "  meowftp.py add admin \"\"              # Vollzugriff auf alle Domains",
        "  meowftp.py add webmaster example.com  # Nur example.com Ordner",
        "  meowftp.py passwd admin               # Passwort ändern",
        "  meowftp.py apply                      # Änderungen aktivieren (benötigt sudo)",
        ""
    ]))

def main() -> int:
    if len(sys.argv) < 2:
        usage()
        return 2
    
    cmd = sys.argv[1].lower()
    
    try:
        if cmd == "list":
            cmd_list()
        elif cmd == "add":
            if len(sys.argv) < 4:
                raise SystemExit("add benötigt: <user> <htdocs_subfolder_or_empty>")
            cmd_add(sys.argv[2], sys.argv[3])
        elif cmd == "del":
            if len(sys.argv) < 3:
                raise SystemExit("del benötigt: <user>")
            cmd_del(sys.argv[2])
        elif cmd == "enable":
            if len(sys.argv) < 3:
                raise SystemExit("enable benötigt: <user>")
            cmd_enable(sys.argv[2], 1)
        elif cmd == "disable":
            if len(sys.argv) < 3:
                raise SystemExit("disable benötigt: <user>")
            cmd_enable(sys.argv[2], 0)
        elif cmd == "passwd":
            if len(sys.argv) < 3:
                raise SystemExit("passwd benötigt: <user>")
            cmd_passwd(sys.argv[2])
        elif cmd == "home":
            if len(sys.argv) < 4:
                raise SystemExit("home benötigt: <user> <htdocs_subfolder_or_empty>")
            cmd_home(sys.argv[2], sys.argv[3])
        elif cmd == "apply":
            apply()
        else:
            usage()
            return 2
        return 0
    except subprocess.CalledProcessError as e:
        print(f"❌ Command failed: {e}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
PY
chmod +x "$PROJECT_DIR/tools/ftp/meowftp.py"

# ----------------------------
# Debug Scripts für FTP
# ----------------------------
cat > "$PROJECT_DIR/tools/ftp/debug-ftp.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

echo "======================================"
echo "MeowFTP Debug Report"
echo "======================================"
echo ""

# Container Status
echo "1️⃣  Container Status:"
echo "--------------------------------------"
if docker ps --format '{{.Names}}' | grep -q meowhome_ftp; then
  echo "✓ Container läuft"
  docker ps --filter name=meowhome_ftp --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
else
  echo "❌ Container läuft NICHT"
fi
echo ""

# Logs
echo "2️⃣  FTP Logs (letzte 30 Zeilen):"
echo "--------------------------------------"
docker logs --tail 30 meowhome_ftp 2>&1 || echo "Keine Logs verfügbar"
echo ""

# vsftpd.conf
echo "3️⃣  vsftpd.conf:"
echo "--------------------------------------"
docker exec meowhome_ftp cat /etc/vsftpd/vsftpd.conf 2>/dev/null | head -30 || echo "❌ Nicht lesbar"
echo ""

# PAM Config
echo "4️⃣  PAM Config:"
echo "--------------------------------------"
docker exec meowhome_ftp cat /etc/pam.d/vsftpd_virtual 2>/dev/null || echo "❌ Nicht lesbar"
echo ""

# DB Files
echo "5️⃣  Database Files:"
echo "--------------------------------------"
docker exec meowhome_ftp ls -la /etc/vsftpd/ 2>/dev/null | grep -E "users|\.db|\.txt" || echo "❌ Nicht verfügbar"
echo ""

# DB Content (ersten 10 Einträge)
echo "6️⃣  User Database Content:"
echo "--------------------------------------"
docker exec meowhome_ftp sh -c "db5.3_dump /etc/vsftpd/users.db 2>/dev/null || db_dump /etc/vsftpd/users.db 2>/dev/null" | head -20 || echo "❌ Kann DB nicht lesen"
echo ""

# User Configs
echo "7️⃣  User Configs:"
echo "--------------------------------------"
docker exec meowhome_ftp ls -la /etc/vsftpd/users.d/ 2>/dev/null || echo "❌ Nicht verfügbar"
echo ""

# Ports
echo "8️⃣  Port Bindings:"
echo "--------------------------------------"
netstat -tlnp 2>/dev/null | grep -E ":21 |:2100" || ss -tlnp 2>/dev/null | grep -E ":21 |:2100" || echo "⚠️  netstat/ss nicht verfügbar"
echo ""

# Test Login (wenn curl verfügbar)
if command -v curl >/dev/null 2>&1; then
  echo "9️⃣  FTP Connection Test:"
  echo "--------------------------------------"
  timeout 5 curl -v ftp://localhost:21 2>&1 | grep -E "220|Connected" || echo "⚠️  Keine Antwort"
  echo ""
fi

# Permissions
echo "🔟 /var/www Permissions:"
echo "--------------------------------------"
docker exec meowhome_ftp ls -la /var/www 2>/dev/null | head -10 || echo "❌ Nicht verfügbar"
echo ""

echo "======================================"
echo "Tipps:"
echo "  - Login Test: ftp -p <your-ip> 21"
echo "  - Live Logs:  docker logs -f meowhome_ftp"
echo "  - Shell:      docker exec -it meowhome_ftp sh"
echo "======================================"
SH
chmod +x "$PROJECT_DIR/tools/ftp/debug-ftp.sh"

cat > "$PROJECT_DIR/tools/ftp/fix-permissions.sh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../.."

echo "Fixing FTP permissions..."

# Host permissions
sudo chown -R 1000:1000 htdocs/ 2>/dev/null || true
sudo find htdocs/ -type d -exec chmod 755 {} \; 2>/dev/null || true
sudo find htdocs/ -type f -exec chmod 644 {} \; 2>/dev/null || true

# Container permissions
docker exec meowhome_ftp chown -R ftp:ftp /var/www 2>/dev/null || true

# vsftpd config
docker exec meowhome_ftp chown root:root /etc/vsftpd/vsftpd.conf 2>/dev/null || true
docker exec meowhome_ftp chmod 600 /etc/vsftpd/vsftpd.conf 2>/dev/null || true

echo "Done. Restarting FTP..."
docker compose restart ftp
SH
chmod +x "$PROJECT_DIR/tools/ftp/fix-permissions.sh"

# ----------------------------
# docker-compose.yml (inkl. phpMyAdmin nur lokal)
# ----------------------------
cat > "$PROJECT_DIR/docker-compose.yml" <<'YAML'
services:
  web:
    build:
      context: ./web
      dockerfile: Dockerfile
    container_name: meowhome_apache
    env_file: ./.env
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./htdocs:/var/www:rw
      - ./apache/vhosts:/etc/apache2/sites-enabled:rw
      - ./apache/snippets:/etc/apache2/snippets:ro
      - ./letsencrypt:/etc/letsencrypt:ro
    depends_on:
      - php
    restart: unless-stopped

  php:
    build:
      context: ./php
      dockerfile: Dockerfile
    container_name: meowhome_php
    volumes:
      - ./htdocs:/var/www:rw
      - ./php/custom.ini:/usr/local/etc/php/conf.d/99-custom.ini:ro
    restart: unless-stopped

  mariadb:
    image: mariadb:10.11
    container_name: meowhome_db
    env_file: ./.env
    environment:
      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}
      MYSQL_DATABASE: ${DB_NAME}
      MYSQL_USER: ${DB_USER}
      MYSQL_PASSWORD: ${DB_PASSWORD}
    volumes:
      - ./db:/var/lib/mysql
    restart: unless-stopped

  phpmyadmin:
    image: phpmyadmin:5
    container_name: meowhome_pma
    env_file: ./.env
    environment:
      PMA_HOST: mariadb
      PMA_USER: root
      PMA_PASSWORD: ${DB_ROOT_PASSWORD}
    ports:
      - "127.0.0.1:8080:80"
    depends_on:
      - mariadb
    restart: unless-stopped

  certbot:
    build:
      context: ./certbot
      dockerfile: Dockerfile
    container_name: meowhome_certbot
    env_file: ./.env
    volumes:
      - ./letsencrypt:/etc/letsencrypt
      - ./state:/state
      - /var/run/docker.sock:/var/run/docker.sock
    restart: unless-stopped

  dns_updater:
    build:
      context: ./dns-updater
      dockerfile: Dockerfile
    container_name: meowhome_dns_updater
    env_file: ./.env
    volumes:
      - ./state:/state
    restart: unless-stopped

  ftp:
    build:
      context: ./ftp
      dockerfile: Dockerfile
    container_name: meowhome_ftp
    env_file: ./.env
    volumes:
      - ./htdocs:/var/www:rw
      - ./ftp/data:/etc/vsftpd:rw
      - ./ftp/ssl:/etc/ssl/private:ro
    ports:
      - "21:21"
      - "${FTP_PASV_MIN}-${FTP_PASV_MAX}:${FTP_PASV_MIN}-${FTP_PASV_MAX}"
    restart: unless-stopped
YAML

# ----------------------------
# web/Dockerfile (Apache)
# ----------------------------
cat > "$PROJECT_DIR/web/Dockerfile" <<'DOCKER'
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 apache2-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite headers ssl http2 proxy proxy_http proxy_wstunnel proxy_fcgi setenvif
RUN mkdir -p /etc/apache2/snippets

RUN { \
  echo "ServerName localhost"; \
  echo ""; \
  echo "<Directory /var/www>"; \
  echo "  AllowOverride All"; \
  echo "  Require all granted"; \
  echo "</Directory>"; \
  echo ""; \
  echo "Protocols h2 http/1.1"; \
} > /etc/apache2/conf-enabled/00-global.conf

EXPOSE 80 443
CMD ["apachectl","-D","FOREGROUND"]
DOCKER

# ----------------------------
# php/Dockerfile + ini
# ----------------------------
cat > "$PROJECT_DIR/php/Dockerfile" <<'DOCKER'
FROM php:8.3-fpm-alpine

RUN apk add --no-cache \
    icu-dev libzip-dev oniguruma-dev zlib-dev \
    libpng-dev libjpeg-turbo-dev freetype-dev \
    bash curl git unzip

RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j$(nproc) intl pdo pdo_mysql zip opcache mbstring gd

WORKDIR /var/www
DOCKER

cat > "$PROJECT_DIR/php/custom.ini" <<'INI'
memory_limit=1024M
upload_max_filesize=128M
post_max_size=128M
max_execution_time=300
date.timezone=Europe/Berlin
opcache.enable=1
INI

# ----------------------------
# certbot (Dockerfile + run.sh)
# ----------------------------
cat > "$PROJECT_DIR/certbot/Dockerfile" <<'DOCKER'
FROM certbot/certbot:latest
RUN pip install --no-cache-dir certbot-dns-cloudflare
COPY run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
DOCKER

cat > "$PROJECT_DIR/certbot/run.sh" <<'SH'
#!/bin/sh
set -eu

if [ -z "${CLOUDFLARE_API_TOKEN:-}" ]; then
  echo "CLOUDFLARE_API_TOKEN fehlt"
  exit 1
fi
if [ -z "${LE_EMAIL:-}" ]; then
  echo "LE_EMAIL fehlt"
  exit 1
fi
if [ -z "${DOMAINS:-}" ]; then
  echo "DOMAINS fehlt"
  exit 1
fi

PROP="${CF_PROPAGATION_SECONDS:-30}"

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

reload_apache() {
  echo "[certbot] apache reload/restart"
  if docker exec meowhome_apache apachectl -k graceful >/dev/null 2>&1; then
    return 0
  fi
  docker restart meowhome_apache >/dev/null 2>&1 || true
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

reload_apache

while true; do
  echo "[certbot] renew start"
  certbot renew --non-interactive --quiet || true
  reload_apache
  echo "[certbot] renew done, sleeping 12h"
  sleep 12h
done
SH
chmod +x "$PROJECT_DIR/certbot/run.sh"

# ----------------------------
# dns-updater (Dockerfile + run.sh)
# ----------------------------
cat > "$PROJECT_DIR/dns-updater/Dockerfile" <<'DOCKER'
FROM python:3.12-slim
WORKDIR /app
RUN pip install --no-cache-dir requests python-dotenv urllib3
COPY DNSUpdatecloudflare.py /app/DNSUpdatecloudflare.py
COPY run.sh /run.sh
RUN chmod +x /run.sh
ENTRYPOINT ["/run.sh"]
DOCKER

cat > "$PROJECT_DIR/dns-updater/run.sh" <<'SH'
#!/bin/sh
set -eu
mkdir -p /state
export STATE_PATH="${STATE_PATH:-/state/state.json}"
export LOG_PATH="${LOG_PATH:-/state/dns_updater.log}"
exec python /app/DNSUpdatecloudflare.py
SH
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
print("DNSUpdatecloudflare.py fehlt. Bitte neben init-meowhome.sh legen und Script erneut ausführen.")
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
✅ MeowHome v2.0 erfolgreich erstellt/aktualisiert!
================================================================

Installation: $PROJECT_DIR

WICHTIGE SCHRITTE:
==================

1️⃣  KONFIGURATION
   Öffne und fülle die .env Datei aus:
   
   nano $PROJECT_DIR/.env
   
   Wichtig:
   - DOMAINS (deine Domains)
   - LE_EMAIL (für Let's Encrypt)
   - CLOUDFLARE_API_TOKEN
   - FTP_PUBLIC_HOST (deine öffentliche IP/Domain!)
   - DB Passwörter ändern

2️⃣  PORTS PRÜFEN
   Stelle sicher dass diese Ports frei sind:
   - 80, 443 (HTTP/HTTPS)
   - 21 (FTP)
   - 21000-21010 (FTP Passive)
   
   Diese Ports müssen auch am Router weitergeleitet sein!

3️⃣  SYSTEM STARTEN
   cd $PROJECT_DIR
   docker compose up -d --build

4️⃣  FTP BENUTZER ERSTELLEN
   cd $PROJECT_DIR
   
   # User für eine spezifische Domain:
   ./tools/ftp/meowftp.py add webmaster example.com
   
   # User mit Vollzugriff auf alle Domains:
   ./tools/ftp/meowftp.py add admin ""
   
   # Änderungen aktivieren (benötigt sudo!):
   ./tools/ftp/meowftp.py apply
   
   #DB Host mariadb

5️⃣  ZERTIFIKATE
   Certbot läuft automatisch, prüfe die Logs:
   docker logs -f meowhome_certbot
   
   Für FTPS (nach erfolgreicher Cert-Erstellung):
   ./ftp/build-ftps-pem.sh example.com
   
   Dann in .env: FTP_TLS=YES setzen
   docker compose restart ftp

NÜTZLICHE BEFEHLE:
==================

📊 Status prüfen:
   docker compose ps
   docker compose logs -f

🔍 FTP Debug:
   ./tools/ftp/debug-ftp.sh
   docker logs -f meowhome_ftp

👥 FTP User verwalten:
   ./tools/ftp/meowftp.py list
   ./tools/ftp/meowftp.py passwd <user>
   ./tools/ftp/meowftp.py home <user> <path>

🗄️  phpMyAdmin (nur lokal):
   http://127.0.0.1:8080

🔧 Permissions Fix:
   ./tools/ftp/fix-permissions.sh
   
   Restart nach Änderungen (vhost, ftp)
   docker compose restart php
   docker compose restart web
   docker compose restart ftp

FEHLERBEHEBUNG:
===============

FTP Login schlägt fehl?
→ ./tools/ftp/debug-ftp.sh
→ Prüfe ob apply ausgeführt wurde
→ Prüfe docker logs meowhome_ftp

Apache startet nicht?
→ Kommentiere SSL-VHosts aus bis Certs da sind
→ docker logs meowhome_apache

================================================================
📚 Dokumentation: https://github.com/your-repo/meowhome
💬 Support: Issues auf GitHub
================================================================

OUT
