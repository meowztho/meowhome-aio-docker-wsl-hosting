# 🐱 MeowHome

**All-in-One Docker-based Web Hosting Stack with FTP, SSL, DNS, backups, and a local control plane**

Current release: **2.5.2**

MeowHome is a lightweight multi-domain hosting stack for Linux/WSL2. Apache, PHP, MariaDB, FTPS, Let's Encrypt, DNS automation, and the Web UI run in Docker, while persistent website and service data stays directly in the project directory as WSL/Linux bind-mounted files rather than Docker named volumes.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
![Python in Docker](https://img.shields.io/badge/Python%20in-Docker-blue?logo=python&logoColor=white)
[![FTP](https://img.shields.io/badge/FTP-vsftpd-green.svg)](https://security.appspot.com/vsftpd.html)

---

## 📋 Table of Contents

- [Features](#-features)
- [Web UI](#-web-ui-meowhome-ui)
- [Backup & Restore](#backup--restore)
- [Requirements](#-requirements)
- [Quick Start](#-quick-start)
- [Architecture](#%EF%B8%8F-architecture)
- [Configuration](#%EF%B8%8F-configuration)
- [FTP Management](#-ftp-management)
- [SSL/TLS Certificates](#-ssltls-certificates)
- [Troubleshooting](#-troubleshooting)
- [Best Practices](#-best-practices)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🌐 Web Stack
- **Apache 2.4** with HTTP/2 support
- **PHP 8.3-FPM** (Alpine-based, optimized)
- **MariaDB 10.11** for databases
- **phpMyAdmin** (localhost-only, secured)

### 🔒 SSL & DNS
- **Let's Encrypt** wildcard certificates via Cloudflare DNS
- **Automatic renewal** every 12 hours
- **DNS updater** for dynamic IPs (Cloudflare)
- **Reusable TLS configuration** for Apache virtual hosts

### 📁 FTP Server
- **vsftpd** with virtual users (PAM-based)
- **Per-user access scopes**: one domain, multiple selected domains, or all domains
- **FTPS** support (TLS/SSL)
- **Password management tool** (`meowftp.py`)
- **SQLite user database** on the host

### 🛠️ Management Tools
- **meowftp.py**: convenient user management
- **debug-ftp.sh**: comprehensive diagnostics
- **fix-permissions.sh**: explicit permission-repair helper (never run automatically during upgrades)
- **build-ftps-pem.sh**: SSL cert converter
- **backup.sh**: Backup Tool
- **restore.sh**: Restore Tool
- **meowhome.py**: stable operational CLI (`doctor`, `status`, lifecycle, logs)

---
## 🔧 Web UI (MeowHome UI)

MeowHome includes an optional local-only Web UI designed as a control center for administrators who prefer not to work directly with the shell.

The UI is not exposed to the internet by default and is intended to be used only:

locally (127.0.0.1)

or from the same network / via VPN

### Features

- **Dashboard**
  - Overview of all meowhome_* containers
  - Start / Stop / Restart individual containers
  - Quick access to container logs
  - Health Check
  - Docker availability check
  - Status and health of all MeowHome containers
  - Restart count and quick log access
  - Useful for diagnosing startup or restart issues

- **FTP Management (UI-backed)**
  - Create, delete, enable and disable FTP users
  - Assign one domain, multiple selected domains, or explicit full access per user
  - Uses structured state from the existing `meowftp.py`/SQLite core instead of parsing terminal text
  - Automatically reconciles generated vsftpd auth state and isolated multi-domain views

- **Setup / Network**
  - Edit HTTP/HTTPS, phpMyAdmin and FTP published ports/bind addresses
  - Configure passive FTP range, FTPS certificate domain, DNS/ACME and database settings
  - `PUID/PGID` and the host project path remain protected runtime contracts instead of casual UI settings

- **VHost Management**
  - Edit Apache VirtualHost files directly in the browser
  - Automatic config test (apachectl -t)
  - Safe rollback on invalid configuration
  - Graceful reload without full container restart
 
- **Backup (UI-triggered, restore via shell)**
  - One-click creation of full system backups
  - Includes:
    - All MariaDB databases
    - All MariaDB users and privileges (including user-created DBs via phpMyAdmin)
    - Apache vhosts & snippets
    - FTP user database
    - Let’s Encrypt certificates
    - .env configuration
  - Optional inclusion of htdocs/ (disabled by default)
  - Backups are stored under:
```bash
~/meowhome/backups/
```

### 🔒 Restore is intentionally not available via the UI
Restoring a backup is done via a dedicated shell script to avoid accidental data loss and to ensure safe container shutdown.

---
## Backup & Restore
### Create a Backup (via UI or CLI)

- **Via Web UI:**
```bash
http://127.0.0.1:9090/backup
```

- **Via CLI:**
```bash
cd ~/meowhome
sudo ./tools/backup/backup.sh
```

- **With webroot included:**
```bash
cd ~/meowhome
sudo ./tools/backup/backup.sh --with-htdocs
```

The installed tool derives the project root from its own location, so using `sudo` does not redirect backups to `/root/meowhome`. On older releases, set `MEOWHOME_PROJECT_DIR="$PWD"` explicitly when invoking a newer backup helper before the upgrade.
- **Restore a Backup (CLI only)**
```bash
cd /path/to/meowhome
./tools/backup/restore.sh ./backups/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz
```

This will:

1. Stop all containers
2. Restore configuration and data
3. Start MariaDB and import all databases including users/grants
4. Start the full stack again


## 🔧 Requirements

### System
- **Linux** (tested on Ubuntu 22.04/24.04, Debian 12)
- **Docker** ≥ 20.10
- **Docker Compose** ≥ 2.0
- **Root access** (required for FTP user management)

### Network
- **Ports**: 80, 443, 21, 21000-21010 must be available
- **Port forwarding** on your router for external reachability
- **Cloudflare account** with API token (Zone: DNS Edit) (only required if ACME_CHALLENGE=dns or DNS_UPDATER_ENABLED=true)

### Optional
- **WSL2** (Windows users can run MeowHome in WSL2)
---
---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone repository (or download the script)
git clone https://github.com/meowztho/meowhome-aio-docker-wsl-hosting.git
cd meowhome-aio-docker-wsl-hosting

# Run init script
chmod +x init-meowhome.sh
./init-meowhome.sh ~/meowhome
```

### 2. Configuration
### You can configure MeowHome either manually via .env or via the Web UI.

### Option A: Manual .env configuration (CLI)


```bash
cd ~/meowhome
nano .env
```

**Minimal configuration:**

```bash
# Your domains (comma-separated)
DOMAINS=example.com,example.net

# Let's Encrypt email
LE_EMAIL=admin@example.com

# Optional: only needed when certbot reports
# "Please choose an account" in non-interactive mode
LE_ACCOUNT=

# Cloudflare API token
CLOUDFLARE_API_TOKEN=your_cloudflare_token_here

# Enable certbot, but use HTTP-01 instead of DNS-01
CERTBOT_ENABLED=true
ACME_CHALLENGE=http

# DNS updater off (no Cloudflare needed)
DNS_UPDATER_ENABLED=false

# FTP: public IP or domain
FTP_PUBLIC_HOST=ftp.example.com

# Database passwords
DB_ROOT_PASSWORD=secure_password_here
DB_PASSWORD=app_password_here
```

### 3. Start the system

```bash
# Build and start containers
docker compose up -d --build

# Follow logs
docker compose logs -f
```

### 4. Create FTP users

```bash
# User for a specific domain
./tools/ftp/meowftp.py add webmaster example.com

# Restrict the same user to a selected multi-domain view
./tools/ftp/meowftp.py assign webmaster example.com example.net

# Explicit full access to every domain
./tools/ftp/meowftp.py add admin "" --allow-all

# Apply generated auth/view state (requires sudo!)
sudo ./tools/ftp/meowftp.py apply
```

### 5. Check certificates

```bash
# View certbot logs
docker logs -f meowhome_certbot

# If certificates were created successfully:
ls -la letsencrypt/live/

```
### Option B: Web UI

After the initial setup, you can build and start the system immediately and complete the configuration using the Web UI.

```bash
cd ~/meowhome
docker compose up -d --build
```
Then open the Web UI in your browser:
```bash
http://127.0.0.1:9090
```
Default login:
```bash
Username: admin
Password: admin
```

The guided setup flow allows you to:
- **Configure the full .env file via the browser**
- **Enable or disable Certbot and DNS updater**
- **Configure domains, published ports, email, FTP/FTPS, DNS/ACME, and database credentials**
- **Manage FTP domain assignments, VHosts, backups, services and logs from the same control plane**

This approach is ideal if you:
- **Prefer a graphical setup**
- **Are running MeowHome for the first time**
- **Want to avoid editing .env manually**

---

## 🏗️ Architecture

### Core-first contract

MeowHome 2.5 treats `.env`, Compose service names, persistent-data boundaries, and `tools/meowhome.py` as the stable operational contract. `ftp/users.sqlite` is the source of truth for FTP identities; `ftp/data/` is generated and can be rebuilt. Existing `htdocs/` content and Apache VHost files are user-owned and are not replaced by installer upgrades.

For diagnosis, prefer:

```bash
./tools/meowhome.py status --json
./tools/meowhome.py doctor --json
```

See `ARCHITECTURE.md` for ownership, persistence, extension, and restore rules.


```
┌─────────────────────────────────────────────────────────────┐
│                         Internet                             │
└────────────┬───────────────────────────────┬─────────────────┘
             │                               │
        ┌────▼────┐                     ┌────▼────┐
        │ Port 80 │                     │ Port 21 │
        │   443   │                     │ 21000-  │
        └────┬────┘                     │  21010  │
             │                          └────┬────┘
             │                               │
    ┌────────▼──────────┐          ┌─────────▼────────┐
    │  Apache Container │          │  FTP Container   │
    │  (meowhome_apache)│          │ (meowhome_ftp)   │
    └────────┬──────────┘          └─────────┬────────┘
             │                               │
             │ proxy:fcgi                    │
             │                               │
    ┌────────▼──────────┐                   │
    │   PHP Container   │                   │
    │  (meowhome_php)   │                   │
    └────────┬──────────┘                   │
             │                               │
             │ pdo_mysql                     │
             │                               │
    ┌────────▼──────────┐                   │
    │ MariaDB Container │                   │
    │  (meowhome_db)    │                   │
    └───────────────────┘                   │
                                             │
    ┌────────────────────────────────────────▼────┐
    │       Shared WSL/Linux bind mount: htdocs/    │
    │  ├── example.com/                            │
    │  │   └── index.php                           │
    │  └── example.net/                            │
    │      └── index.php                           │
    └──────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│               Background Services                            │
├──────────────────────────────────────────────────────────────┤
│  Certbot (meowhome_certbot)    │ Let's Encrypt Certs        │
│  DNS Updater (meowhome_dns_updater) │ Cloudflare A-Record Update │
│  phpMyAdmin (127.0.0.1:8080)        │ DB Management (local only) │
│  Web UI (127.0.0.1:9090)            │ Local control plane         │
└──────────────────────────────────────────────────────────────┘
```

### Container Overview

| Container | Image | Ports | Description |
|-----------|-------|-------|-------------|
| `meowhome_apache` | Custom (Debian) | 80, 443 | Web server |
| `meowhome_php` | php:8.3-fpm-alpine | - | PHP-FPM |
| `meowhome_db` | mariadb:10.11 | - | Database |
| `meowhome_ftp` | Custom (Debian) | 21, 21000-21010 | FTP server |
| `meowhome_certbot` | certbot/certbot | - | SSL certificates |
| `meowhome_dns_updater` | python:3.12-slim | - | DNS updates |
| `meowhome_pma` | phpmyadmin:5 | 127.0.0.1:8080 | phpMyAdmin |
| `meowhome_ui` | Custom (Python/FastAPI) | 127.0.0.1:9090 | Local control plane |

---

## ⚙️ Configuration

### `.env` File – All Options

```bash
# ============================================================
# Windows/LAN Integration
# ============================================================
WIN_HOST_IP=192.168.178.59  # For reverse proxy to Windows apps

# ============================================================
# Domains & DNS
# ============================================================
DOMAINS=example.com,example.net
A_RECORDS_example_com=example.com,www.example.com,shop.example.com
A_RECORDS_example_net=example.net,www.example.net

# # Cloudflare Settings (only required if ACME_CHALLENGE=dns or DNS_UPDATER_ENABLED=true)
CLOUDFLARE_API_TOKEN=your_token_here
PROXIED_DEFAULT=true
PROXIED_OVERRIDES=mail.example.com=false

# DNS Updater
FORCE_UPDATE_HOUR=6
CHECK_INTERVAL_SECONDS=600
RETRY_INTERVAL_SECONDS=300

# ============================================================
# Let's Encrypt
# ============================================================
LE_EMAIL=admin@example.com
LE_ACCOUNT=
CF_PROPAGATION_SECONDS=30
CERTBOT_RETRY_SECONDS=300

# Wildcard Mode (recommended)
WILDCARD=true

# Alternative: specific hosts
# WILDCARD=false
# HOSTS=example.com,www.example.com,shop.example.com

# ============================================================
# FTP / FTPS
# ============================================================
# Host ownership used by PHP-FPM and FTP guest mapping
PUID=1000
PGID=1000

# Installer/restore-managed absolute WSL path. Do not hand-edit.
MEOWHOME_HOST_PROJECT_DIR=/home/your-user/meowhome

# Published host bindings / ports
HTTP_BIND=0.0.0.0
HTTP_PORT=80
HTTPS_BIND=0.0.0.0
HTTPS_PORT=443
PHPMYADMIN_BIND=127.0.0.1
PHPMYADMIN_PORT=8080
FTP_BIND=0.0.0.0
FTP_PORT=21

FTP_PASV_MIN=21000
FTP_PASV_MAX=21010

# IMPORTANT: public IP or DNS name!
FTP_PUBLIC_HOST=ftp.example.com

# FTPS (after cert creation)
FTP_TLS=NO
FTP_CERT_DOMAIN=example.com

# ============================================================
# Database
# ============================================================
# Host mariadb
DB_ROOT_PASSWORD=super_secure_root_password
DB_NAME=app
DB_USER=app
DB_PASSWORD=secure_app_password

# ============================================================
# Optional: Certbot + DNS Updater toggles
# ============================================================

# Enable/disable certbot container (container will idle when disabled)
CERTBOT_ENABLED=true

# Enable/disable DNS updater (container will idle when disabled)
DNS_UPDATER_ENABLED=true

# ACME challenge method:
# - dns  = DNS-01 (default; wildcard possible; needs DNS provider token)
# - http = HTTP-01 (fallback; requires port 80; no wildcard)
ACME_CHALLENGE=dns

# DNS provider for DNS-01 (currently implemented: cloudflare)
DNS_PROVIDER=cloudflare

# ============================================================
# MeowHome Web UI
# ============================================================
# Keep localhost-only unless you intentionally expose it on LAN/VPN.
MEOWHOME_UI_BIND=127.0.0.1
MEOWHOME_UI_PORT=9090
MEOWHOME_UI_USER=admin
MEOWHOME_UI_PASS=change-me
```

### Apache VHosts

Create VHost files in `apache/vhosts/`:

```apache
# apache/vhosts/10-mysite.conf
<VirtualHost *:80>
    ServerName mysite.com
    ServerAlias www.mysite.com
    DocumentRoot /var/www/mysite.com

    <Directory /var/www/mysite.com>
        AllowOverride All
        Require all granted
    </Directory>

    Include /etc/apache2/snippets/php-fpm.conf
    Include /etc/apache2/snippets/cf-safe-redirect.conf
</VirtualHost>

<VirtualHost *:443>
    ServerName mysite.com
    ServerAlias www.mysite.com
    DocumentRoot /var/www/mysite.com

    <Directory /var/www/mysite.com>
        AllowOverride All
        Require all granted
    </Directory>

    Include /etc/apache2/snippets/ssl-common.conf
    SSLCertificateFile /etc/letsencrypt/live/mysite.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/mysite.com/privkey.pem

    Include /etc/apache2/snippets/php-fpm.conf
</VirtualHost>
```

**Reverse proxy example (Jellyfin):**

```apache
# apache/vhosts/20-jellyfin.conf
<VirtualHost *:443>
    ServerName video.example.com

    Include /etc/apache2/snippets/ssl-common.conf
    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem

    ProxyRequests Off
    ProxyPreserveHost On
    ProxyPass "/" "http://192.168.178.59:8096/"
    ProxyPassReverse "/" "http://192.168.178.59:8096/"
</VirtualHost>
```

---

## 📁 FTP Management

### `meowftp.py` – User Management Tool

The tool manages FTP virtual users in a SQLite database and synchronizes them with `vsftpd`.

#### Commands

```bash
# List users
./tools/ftp/meowftp.py list

# Add user (domain-specific)
./tools/ftp/meowftp.py add webmaster example.com

# Assign selected domains to an existing user
./tools/ftp/meowftp.py assign webmaster example.com example.net

# Give an existing user explicit full access
./tools/ftp/meowftp.py all webmaster

# Add user with full access to all domains
./tools/ftp/meowftp.py add admin "" --allow-all

# Delete user
./tools/ftp/meowftp.py del username

# Disable user (without deleting)
./tools/ftp/meowftp.py disable username

# Enable user
./tools/ftp/meowftp.py enable username

# Change password
./tools/ftp/meowftp.py passwd username

# Legacy/single-path home mode remains available
./tools/ftp/meowftp.py home username example.net

# Apply changes (IMPORTANT!)
sudo ./tools/ftp/meowftp.py apply
```

#### Example Workflow

```bash
# 1. Create user for example.com
./tools/ftp/meowftp.py add alice example.com
# Enter password: ********

# 2. Expand alice to an isolated two-domain view
./tools/ftp/meowftp.py assign alice example.com example.net

# 3. Create admin with explicit full access
./tools/ftp/meowftp.py add admin "" --allow-all

# 4. Apply changes
sudo ./tools/ftp/meowftp.py apply

# 5. Check status
./tools/ftp/meowftp.py list
# alice ... mode=domains access=example.com, example.net
# admin ... mode=all     access=all domains
```

### FTP Directory Structure

```
htdocs/
├── example.com/          ← User "alice" can only see this folder
│   ├── index.php
│   └── .htaccess
└── example.net/          ← User "bob" can only see this folder
    └── index.php

User "admin" (home_rel="") sees:
htdocs/
├── example.com/
└── example.net/
```

### FileZilla Connection

```
Host:      ftp.example.com (or your public IP)
Port:      21
Protocol:  FTP (or FTPS if enabled)
User:      alice
Password:  ********
```

**For FTPS:**
```
Protocol:  FTP - File Transfer Protocol (Explicit TLS)
Port:      21
```

---

## 🔒 SSL/TLS Certificates

### Let's Encrypt Wildcard Certificates

### Challenge Modes (DNS-01 vs HTTP-01)

**DNS-01 (Default, recommended):**
- `ACME_CHALLENGE=dns`
- supports wildcard certificates (`*.domain`)
- requires `CLOUDFLARE_API_TOKEN` (current implementation: Cloudflare)
- if multiple Let's Encrypt accounts exist, set `LE_ACCOUNT=<id>`

**HTTP-01 (Fallback, no DNS API required):**
- `ACME_CHALLENGE=http`
- **no wildcard** support
- requires inbound **port 80** reachable from the internet
- Certbot uses the webroot under: `htdocs/<domain>/.well-known/acme-challenge/`

Recommended settings for HTTP-01:
```bash
ACME_CHALLENGE=http
DNS_UPDATER_ENABLED=false
WILDCARD=false
```

#### Manual Certbot Restart

```bash
docker compose restart certbot
docker logs -f meowhome_certbot
```

#### Certificate Directory

```
letsencrypt/
└── live/
    ├── example.com/
    │   ├── fullchain.pem
    │   ├── privkey.pem
    │   └── chain.pem
    └── example.net/
        ├── fullchain.pem
        └── privkey.pem
```

### Enable FTPS

```bash
# 1. Wait until certbot succeeded
docker logs meowhome_certbot | grep "Successfully"

# 2. Create vsftpd PEM from Let's Encrypt cert
./ftp/build-ftps-pem.sh example.com

# 3. Enable TLS in .env
nano .env
# FTP_TLS=YES

# 4. Restart FTP container
docker compose restart ftp

# 5. In FileZilla: use "FTP - Explicit TLS"
```

---

## 🐛 Troubleshooting

### FTP login fails (530 Login incorrect)

```bash
# 1. Run debug report
./tools/ftp/debug-ftp.sh

# 2. Check whether apply was executed
./tools/ftp/meowftp.py list
# If users exist but login fails:
sudo ./tools/ftp/meowftp.py apply

# 3. Live logs during login attempt
docker logs -f meowhome_ftp

# 4. Check PAM config
docker exec meowhome_ftp cat /etc/pam.d/vsftpd_virtual
# Should contain: crypt=crypt

# 5. Check user database
docker exec meowhome_ftp db5.3_dump /etc/vsftpd/users.db | head -10
```

### Apache doesn't start / SSL error

```bash
# If certificates do not exist yet:
# 1. Temporarily disable SSL VHosts
mv apache/vhosts/10-example.conf apache/vhosts/10-example.conf.disabled

# 2. Restart Apache
docker compose restart web

# 3. Wait for certbot
docker logs -f meowhome_certbot

# 4. After successful cert creation, enable VHost again
mv apache/vhosts/10-example.conf.disabled apache/vhosts/10-example.conf
docker compose restart web
```
### Certbot: "Please choose an account" (non-interactive)

If certbot logs contain:
- `Missing command line flag or config entry for this setting`
- `Please choose an account`

set `LE_ACCOUNT` in `.env` to one of the shown IDs and restart certbot.

```bash
# Example (use one of your real IDs from the certbot log)
LE_ACCOUNT=70e6

docker compose restart certbot
docker logs -f meowhome_certbot
```

### Permission denied on FTP upload

MeowHome maps the FTP guest user to the canonical host UID/GID to prevent write-permission issues on bind mounts.
- PHP-FPM runs as the host user (`PUID:PGID`)
- FTP guest user is mapped to the host UID/GID
- Apache runs as root (required for `/var/run/apache2` and ports 80/443)

```bash
# 1. Diagnose first; do not recursively chown as a first reaction
./tools/meowhome.py doctor

# 2. Check the canonical host IDs
grep -E '^(PUID|PGID)=' .env
id -u
id -g

# 3. Inspect numeric ownership on host and in FTP
stat -c '%u:%g %a %n' htdocs htdocs/example.com
docker exec meowhome_ftp sh -lc 'id ftp; ls -ldn /var/www /var/www/example.com'

# 4. Only if doctor/inspection confirms ownership drift, normalize explicitly
./tools/ftp/fix-permissions.sh
```

On the WSL host, files normally appear owned by the configured numeric `PUID:PGID` (for example your regular Linux user), even though the matching account inside the FTP container is named `ftp`.

### DNS updater not working

```bash
# Check logs
docker logs meowhome_dns_updater

# Verify Cloudflare token
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Check state file
cat state/state.json
```

### Container does not start

```bash
# Status of all containers
docker compose ps

# Logs for a specific container
docker compose logs web
docker compose logs php
docker compose logs ftp

# FTPS compatibility
# MeowHome keeps encrypted logins/data mandatory but disables vsftpd TLS-session
# reuse (`require_ssl_reuse=NO`) so common clients such as Windows curl can open
# the protected data channel without a 522 error.

# Rebuild containers
docker compose build --no-cache
docker compose up -d
```

### 🔁 Automatic Execution After Startup (Optional)

If your system is affected by the WSL / Docker startup race condition, you may configure the warmup script to run automatically after startup.

⚠️ Important: cron is NOT enabled by default in WSL

Unlike traditional Linux systems:
WSL does not enable cron by default
in many cases, cron is not installed
even if installed, it may not start automatically
To use @reboot cron jobs in WSL, systemd must be enabled manually.

### 1️⃣ Enable systemd in WSL

Edit or create /etc/wsl.conf:
```bash
[boot]
systemd=true
```


Then restart WSL from Windows:
```bash
wsl --shutdown
```

### 2️⃣ Install and enable cron inside WSL
```bash
sudo apt-get update
sudo apt-get install -y cron
sudo systemctl enable --now cron
```

### 3️⃣ Add the warmup cron job (copy & paste)
```bash
( crontab -l 2>/dev/null | grep -v 'meowhome-warmup' ; \
  echo "@reboot /bin/bash -lc 'sleep 20; \$HOME/meowhome/tools/warmup.sh' # meowhome-warmup" \
) | crontab -
```

This will:

wait 20 seconds after WSL / system startup
run the warmup script once
restart containers safely in the correct order
Safe to run multiple times (no duplicate entries).

### 🔍 What this command does (short & precise)
```bash
crontab -l → lists existing cron jobs
grep -v 'meowhome-warmup' → removes an old warmup entry if present
echo "@reboot …" → adds the warmup job
| crontab - → installs the updated crontab
```
### ➖ Remove the cron job again

If you no longer need the warmup restart, remove it with:
```bash
crontab -l | grep -v 'meowhome-warmup' | crontab -
```

This removes only the warmup entry and leaves all other cron jobs untouched.

### ⚠️ Note

This project does not enable cron automatically.
All system-level changes are intentionally left to the user.

### ❗ Why this is not enabled by default

Not all systems are affected
WSL startup behavior differs between Windows versions
Docker Desktop startup timing varies
Automatically modifying cron or system services would be intrusive
For these reasons, the warmup mechanism is opt-in.

### ✅ When you need this workaround

You likely need this if:
containers work only after a manual restart
bind mounts are empty on first boot
restarting Docker “fixes” the issue
Docker starts faster than WSL filesystem readiness

### 🧠 Technical Background (Short)

Docker only checks container runtime availability
Docker does not validate host mount readiness
WSL mounts Windows paths asynchronously
Result: containers may bind to paths that exist but are not yet fully initialized.

---

## 🎯 Best Practices

### Security

1. **Passwords**: Never use default passwords
2. **FTP users**: One user per developer
3. **phpMyAdmin**: Only use via SSH tunnel (`ssh -L 8080:localhost:8080 user@server`)
4. **.env**: Never commit to Git (it is in `.gitignore`)
5. **Firewall**: Configure UFW or iptables
6. **Updates**: Regularly run `docker compose pull && docker compose up -d`

### Performance

1. **PHP OPcache**: Enabled in `php/custom.ini`
2. **Apache HTTP/2**: Enabled
3. **MariaDB**: Adjust InnoDB buffer pool for high traffic

### Backup

Use the canonical backup tool so MariaDB is dumped logically and FTP/configuration state is captured consistently:

```bash
cd ~/meowhome

# Configuration + MariaDB + FTP/cert/runtime configuration
sudo ./tools/backup/backup.sh

# Full upgrade/disaster-recovery backup including website files
sudo ./tools/backup/backup.sh --with-htdocs
```

Backups are written to `~/meowhome/backups/` by default with owner-only permissions. Raw `db/` files and generated `ftp/data/` state are intentionally not treated as portable sources of truth.

### Monitoring

```bash
# Container stats
docker stats

# Disk usage
docker system df

# Save a recent log snapshot
docker compose logs --tail=100 > logs.txt

# Core diagnostics
./tools/meowhome.py status
./tools/meowhome.py doctor
```

---

## 📂 Directory Structure

```
meowhome/
├── AGENTS.md                 # Agent/operator rules
├── ARCHITECTURE.md           # Core-first ownership + persistence contract
├── VERSION                   # Installed release version
├── apache/
│   ├── vhosts/              # Apache VirtualHost Configs
│   │   ├── 10-example.conf
│   │   └── 20-templates.conf
│   └── snippets/            # Reusable configs
│       ├── php-fpm.conf
│       ├── ssl-common.conf
│       └── cf-safe-redirect.conf
├── certbot/
│   ├── Dockerfile
│   └── run.sh               # Let's Encrypt automation
├── dns-updater/
│   ├── Dockerfile
│   ├── run.sh
│   └── DNSUpdatecloudflare.py
├── ftp/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── build-ftps-pem.sh   # FTPS cert builder
│   ├── data/                # Generated FTP auth/config state; rebuilt from users.sqlite
│   │   ├── users.d/         # Per-user configs (generated)
│   │   ├── users.db         # Berkeley DB (generated)
│   │   └── users.txt        # Hash input (generated)
│   ├── ssl/                 # FTPS certificates
│   │   └── vsftpd.pem
│   └── users.sqlite         # User database (host)
├── htdocs/                  # Web root (direct host/WSL bind mount)
│   ├── example.com/
│   │   └── index.php
│   └── example.net/
│       └── index.php
├── php/
│   ├── Dockerfile
│   └── custom.ini           # PHP settings
├── web/
│   └── Dockerfile           # Apache image
├── tools/
│   ├── meowhome.py          # Stable operational CLI / diagnostics
│   ├── backup/              # Backup + restore contract
│   ├── ftp/
│   │   ├── meowftp.py      # FTP user management
│   │   ├── debug-ftp.sh    # Diagnostic tool
│   │   └── fix-permissions.sh
│   └── apache/
├── db/                      # MariaDB data (direct host/WSL bind mount, gitignored)
├── letsencrypt/            # Let's Encrypt certs (direct host/WSL bind mount)
├── state/                   # Runtime state (gitignored)
├── legacy/                  # Old scripts
├── docker-compose.yml
├── .env                     # Configuration (gitignored!)
├── .env.example             # Template
└── .gitignore
```

---

## 🔄 Update / Upgrade

```bash
# 1. Back up the installed runtime (including web content)
cd ~/meowhome
sudo ./tools/backup/backup.sh --with-htdocs

# 2. Update the complete source checkout. The installer depends on assets/,
#    meowhome-ui/, and the contract documents next to init-meowhome.sh.
cd ~/meowhome-aio-docker-wsl-hosting
git pull --ff-only

# 3. Overlay system/runtime files. Existing .env, htdocs and VHosts are preserved.
./init-meowhome.sh ~/meowhome

# 4. Reconcile the stack with the updated images/configuration.
cd ~/meowhome
docker compose build --pull
docker compose up -d

# 5. Rebuild generated FTP auth state from ftp/users.sqlite and verify.
sudo ./tools/ftp/meowftp.py apply
./tools/meowhome.py doctor --json
```

## 🕹️ USEFUL COMMANDS

```bash
📊 Check status:  
docker compose ps  
docker compose logs -f

🔍 FTP debugging:  
./tools/ftp/debug-ftp.sh  
docker logs -f meowhome_ftp

👥 Manage FTP users:  
./tools/ftp/meowftp.py list  
./tools/ftp/meowftp.py passwd <user>  
./tools/ftp/meowftp.py assign <user> <domain> [domain ...]
./tools/ftp/meowftp.py all <user>

🗄️ phpMyAdmin (local only):  
http://127.0.0.1:8080

🔧 Fix permissions:  
./tools/ftp/fix-permissions.sh

Restart after changes (vhost, ftp):
docker compose restart php  
docker compose restart web  
docker compose restart ftp

💾 Backup & Restore

./tools/backup/backup.sh                 # without htdocs
./tools/backup/backup.sh --with-htdocs
./tools/backup/restore.sh ./backups/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz

🩺 Core diagnostics

./tools/meowhome.py status --json
./tools/meowhome.py doctor --json

```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Developer Setup

```bash
# Clone repository
git clone https://github.com/meowztho/meowhome-aio-docker-wsl-hosting.git
cd meowhome-aio-docker-wsl-hosting

# Create your own .env
cp .env.example .env
nano .env

# Start dev environment
docker compose up --build
```

---

## 📝 Changelog

The authoritative release history is maintained in [`CHANGELOG.md`](CHANGELOG.md).

Current release: **2.5.2** — includes the Core-First runtime contract, the modernized Web UI/control plane, multi-domain FTP access, safer upgrade/backup behavior, FTPS client compatibility, and the Backup-page layout hotfix.

---

## ❓ FAQ

<details>
<summary><strong>Can I use MeowHome without Docker?</strong></summary>

No, MeowHome is fully Docker-based. This greatly simplifies installation, isolation, and updates.
</details>

<details>
<summary><strong>Which PHP extensions are available?</strong></summary>

Default: `intl`, `pdo`, `pdo_mysql`, `zip`, `opcache`, `mbstring`, `gd`

Additional extensions can be added in `php/Dockerfile`.
</details>

<details>
<summary><strong>Can I run multiple PHP versions at the same time?</strong></summary>

Yes, create multiple PHP containers in `docker-compose.yml`:
```yaml
php81:
  build: ./php-8.1/
php83:
  build: ./php-8.3/
```
Then use different proxy targets in Apache VHosts.
</details>

<details>
<summary><strong>Does MeowHome work with DNS providers other than Cloudflare?</strong></summary>

Not out of the box. MeowHome's current DNS updater and DNS-01 integration are implemented for Cloudflare. Certbot itself supports other providers, but using one requires extending the image/configuration deliberately, for example:
```dockerfile
RUN pip install certbot-dns-route53  # Example AWS
```
</details>

<details>
<summary><strong>How can I install WordPress?</strong></summary>

```bash
# 1. Download WordPress
cd ~/meowhome/htdocs/
mkdir mysite.com
cd mysite.com
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz --strip-components=1
rm latest.tar.gz

# 2. Create database
docker exec -it meowhome_db mysql -u root -p
# CREATE DATABASE mysite_wp;
# GRANT ALL ON mysite_wp.* TO 'app'@'%';

# 3. Create Apache VHost (see Configuration)
# 4. Browser: http://mysite.com/wp-admin/install.php
```
</details>

---

## 🙏 Credits

- **vsftpd**: [https://security.appspot.com/vsftpd.html](https://security.appspot.com/vsftpd.html)
- **Let's Encrypt**: [https://letsencrypt.org/](https://letsencrypt.org/)
- **Cloudflare**: [https://www.cloudflare.com/](https://www.cloudflare.com/)
- **Docker**: [https://www.docker.com/](https://www.docker.com/)

---

## 📄 License

MIT License – see the [LICENSE](LICENSE) file

---

## 📧 Support

- **Issues**: [GitHub Issues](https://github.com/meowztho/meowhome-aio-docker-wsl-hosting/issues)
---

<div align="center">

**MeowHome** - Built with ❤️ for the self-hosting community

## 💖 Support this project

If MeowHome saves you time or helps you run your servers, please consider supporting development:

- [**GitHub Sponsors**](https://github.com/sponsors/meowztho)
- [**Paypal**](paypal.me/farrnbacher)

⭐ **Star this repo if it helped you!** ⭐

</div>
