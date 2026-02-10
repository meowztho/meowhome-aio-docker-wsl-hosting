# 🐱 MeowHome

**All-in-One Docker-based Web Hosting Stack with FTP, SSL, and DNS Management**

A fully automated hosting setup for multiple domains with Apache, PHP, MariaDB, Let's Encrypt SSL certificates, a Cloudflare DNS updater, and FTP virtual users.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
![Python in Docker](https://img.shields.io/badge/Python%20in-Docker-blue?logo=python&logoColor=white)
[![FTP](https://img.shields.io/badge/FTP-vsftpd-green.svg)](https://security.appspot.com/vsftpd.html)

---

## 📋 Table of Contents

- [Features](#-features)
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
- **HSTS** and modern SSL configuration

### 📁 FTP Server
- **vsftpd** with virtual users (PAM-based)
- **Per-domain isolation** or full access
- **FTPS** support (TLS/SSL)
- **Password management tool** (`meowftp.py`)
- **SQLite user database** on the host

### 🛠️ Management Tools
- **meowftp.py**: convenient user management
- **debug-ftp.sh**: comprehensive diagnostics
- **fix-permissions.sh**: auto-repair for permissions
- **build-ftps-pem.sh**: SSL cert converter
- **backup.sh**: Backup Tool
- **restore.sh**: Restore Tool

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
  - Uses the existing meowftp.py tool internally
  - Automatically applies changes after modifications
  - Safe handling of container restarts (race-condition aware)

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
## Backup & Restore (New)
### Create a Backup (via UI or CLI)

- **Via Web UI:**
```bash
http://127.0.0.1:9090/backup
```

- **Via CLI:**
```bash
~/meowhome/tools/backup/backup.sh
```

- **With webroot included:**
```bash
~/meowhome/tools/backup/backup.sh --with-htdocs
```
- **Restore a Backup (CLI only)**
```bash
~/meowhome/tools/backup/restore.sh \
  ~/meowhome/backups/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz
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
cd meowhome

# Run init script
chmod +x init-meowhome.sh
./init-meowhome.sh ~/meowhome
```

### 2. Configuration

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

# User with full access
./tools/ftp/meowftp.py add admin ""

# Apply changes (requires sudo!)
sudo ./tools/ftp/meowftp.py apply
```

### 5. Check certificates

```bash
# View certbot logs
docker logs -f meowhome_certbot

# If certificates were created successfully:
ls -la letsencrypt/live/
```

---

## 🏗️ Architecture

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
    │          Shared Volume: htdocs/              │
    │  ├── example.com/                            │
    │  │   └── index.php                           │
    │  └── example.net/                            │
    │      └── index.php                           │
    └──────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│               Background Services                            │
├──────────────────────────────────────────────────────────────┤
│  Certbot (meowhome_certbot)    │ Let's Encrypt Certs        │
│  DNS Updater (meowhome_dns)    │ Cloudflare A-Record Update │
│  phpMyAdmin (127.0.0.1:8080)   │ DB Management (local only) │
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
CF_PROPAGATION_SECONDS=30

# Wildcard Mode (recommended)
WILDCARD=true

# Alternative: specific hosts
# WILDCARD=false
# HOSTS=example.com,www.example.com,shop.example.com

# ============================================================
# FTP / FTPS
# ============================================================
FTP_ENABLED=true
FTP_PASV_MIN=21000
FTP_PASV_MAX=21010

# IMPORTANT: public IP or DNS name!
FTP_PUBLIC_HOST=ftp.example.com

# FTPS (after cert creation)
FTP_TLS=NO
FTP_CERT_DOMAIN=example.com

# File permissions
FTP_HOST_UID=1000
FTP_HOST_GID=1000

# ============================================================
# Database
# ============================================================
# Host mariadb
DB_ROOT_PASSWORD=super_secure_root_password
DB_NAME=app
DB_USER=app
DB_PASSWORD=secure_app_password

# ============================================================
# Optional: Certbot + DNS Updater toggles (v2.2.0)
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

# Add user (full access to all domains)
./tools/ftp/meowftp.py add admin ""

# Delete user
./tools/ftp/meowftp.py del username

# Disable user (without deleting)
./tools/ftp/meowftp.py disable username

# Enable user
./tools/ftp/meowftp.py enable username

# Change password
./tools/ftp/meowftp.py passwd username

# Change home directory
./tools/ftp/meowftp.py home username example.net

# Apply changes (IMPORTANT!)
sudo ./tools/ftp/meowftp.py apply
```

#### Example Workflow

```bash
# 1. Create user for example.com
./tools/ftp/meowftp.py add alice example.com
# Enter password: ********

# 2. Create admin with full access
./tools/ftp/meowftp.py add admin ""
# WARNING appears, confirm with "yes"

# 3. Apply changes
sudo ./tools/ftp/meowftp.py apply

# 4. Check status
./tools/ftp/meowftp.py list
# alice                enabled=✓ path=htdocs/example.com
# admin                enabled=✓ path=htdocs/(all domains)
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

### Permission denied on FTP upload

**v2.2.0 note (UID/GID mismatch fix):**
MeowHome maps the FTP guest user to the host UID/GID to prevent write permission issues on bind mounts.
- PHP-FPM runs as the host user (`PUID:PGID`)
- FTP guest user is mapped to the host UID/GID
- Apache runs as root (required for `/var/run/apache2` and ports 80/443)

```bash
# 1. Use fix permissions tool
./tools/ftp/fix-permissions.sh

# 2. Check manually
docker exec meowhome_ftp ls -la /var/www/example.com

# Should be: drwxrwxr-x ftp ftp

# 3. Check UID/GID in .env
cat .env | grep FTP_HOST
# FTP_HOST_UID=1000
# FTP_HOST_GID=1000

# 4. Find host UID
id -u
id -g
```

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

crontab -l → lists existing cron jobs
grep -v 'meowhome-warmup' → removes an old warmup entry if present
echo "@reboot …" → adds the warmup job
| crontab - → installs the updated crontab

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

```bash
# Database backup
docker exec meowhome_db mysqldump -u root -p$DB_ROOT_PASSWORD --all-databases > backup.sql

# Webroot backup
tar -czf htdocs-backup.tar.gz htdocs/

# FTP user DB backup
cp ftp/users.sqlite ftp-users-backup.sqlite

# Complete backup
tar -czf meowhome-backup-$(date +%Y%m%d).tar.gz \
  --exclude='db/*' \
  --exclude='state/*' \
  ~/meowhome/
```

### Monitoring

```bash
# Container stats
docker stats

# Disk usage
docker system df

# Rotate logs (if too large)
docker compose logs --tail=100 > logs.txt
docker compose down
docker system prune -a
docker compose up -d
```

---

## 📂 Directory Structure

```
meowhome/
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
│   ├── data/                # FTP config (volume)
│   │   ├── users.d/         # Per-user configs
│   │   ├── users.db         # Berkeley DB (generated)
│   │   └── users.txt        # Plaintext user list (temp)
│   ├── ssl/                 # FTPS certificates
│   │   └── vsftpd.pem
│   └── users.sqlite         # User database (host)
├── htdocs/                  # Web root (volume)
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
│   ├── ftp/
│   │   ├── meowftp.py      # FTP user management
│   │   ├── debug-ftp.sh    # Diagnostic tool
│   │   └── fix-permissions.sh
│   └── apache/
├── db/                      # MariaDB data (volume, gitignored)
├── letsencrypt/            # Let's Encrypt certs (volume)
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
cd ~/meowhome

# 1. Create a backup
docker compose down
tar -czf backup-$(date +%Y%m%d).tar.gz \
  .env htdocs/ ftp/users.sqlite apache/vhosts/

# 2. Fetch the latest init script
wget https://raw.githubusercontent.com/yourusername/meowhome/main/init-meowhome.sh
chmod +x init-meowhome.sh

# 3. Run update (overwrites only system files, not your data)
./init-meowhome.sh ~/meowhome

# 4. Rebuild containers
docker compose build --no-cache
docker compose up -d

# 5. Re-apply FTP users
sudo ./tools/ftp/meowftp.py apply
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
./tools/ftp/meowftp.py home <user> <path>

🗄️ phpMyAdmin (local only):  
http://127.0.0.1:8080

🔧 Fix permissions:  
./tools/ftp/fix-permissions.sh

Restart after changes (vhost, ftp):
docker compose restart php  
docker compose restart web  
docker compose restart ftp

💾 Backup & Restore

./tools/backup/backup.sh (without htdocs)
./tools/backup/backup.sh --with-htdocs
~/meowhome/tools/backup/restore.sh ~/meowhome/backups/meowhome-backup-YYYYmmdd-HHMMSS.tar.gz

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
git clone https://github.com/yourusername/meowhome.git
cd meowhome

# Create your own .env
cp .env.example .env
nano .env

# Start dev environment
docker compose up --build
```

---

## 📝 Changelog

### Version 2.0 (2024-02)
- ✅ **FIX**: FTP Virtual Users Authentication (PAM crypt=crypt)
- ✅ **NEW**: Robust `meowftp.py` with container readiness
- ✅ **NEW**: Comprehensive debug tools
- ✅ **IMPROVED**: Documentation and error handling

### Version 1.0 (2024-01)
- Initial release

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

Certbot supports many providers. Adjust `certbot/Dockerfile`, for example:
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

- **Issues**: [GitHub Issues](https://github.com/yourusername/meowhome/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/meowhome/discussions)
- **Email**: admin@example.com

---

<div align="center">

**MeowHome** - Built with ❤️ for the self-hosting community

## 💖 Support this project

If MeowHome saves you time or helps you run your servers, please consider supporting development:

- [**GitHub Sponsors**](https://github.com/sponsors/meowztho)
- [**Paypal**](paypal.me/farrnbacher)

⭐ **Star this repo if it helped you!** ⭐

</div>
