# 🐱 MeowHome

**All-in-One Docker-based Web Hosting Stack with FTP, SSL, and DNS Management**

A fully automated hosting setup für mehrere Domains mit Apache, PHP, MariaDB, Let's Encrypt SSL-Zertifikaten, Cloudflare DNS-Updater und FTP Virtual Users.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![FTP](https://img.shields.io/badge/FTP-vsftpd-green.svg)](https://security.appspot.com/vsftpd.html)

---

## 📋 Table of Contents

- [Features](#-features)
- [Requirements](#-voraussetzungen)
- [Quick Start](#-quick-start)
- [Architecture](#-architektur)
- [Configuration](#-konfiguration)
- [FTP Management](#-ftp-management)
- [SSL/TLS Zertifikate](#-ssltls-zertifikate)
- [Troubleshooting](#-fehlerbehebung)
- [Best Practices](#-best-practices)
- [Contributing](#-contributing)
- [License](#-lizenz)

---

## ✨ Features

### 🌐 Web Stack
- **Apache 2.4** mit HTTP/2 Support
- **PHP 8.3-FPM** (Alpine-basiert, optimiert)
- **MariaDB 10.11** für Databaseen
- **phpMyAdmin** (localhost-only, sicher)

### 🔒 SSL & DNS
- **Let's Encrypt** Wildcard-Zertifikate via Cloudflare DNS
- **Automatische Renewal** alle 12 Stunden
- **DNS Updater** für dynamische IPs (Cloudflare)
- **HSTS** und moderne SSL-Configuration

### 📁 FTP Server
- **vsftpd** mit Virtual Users (PAM-basiert)
- **Pro-Domain Isolation** oder Full Access
- **FTPS** Support (TLS/SSL)
- **Passwort-Management Tool** (meowftp.py)
- **SQLite User Database** auf Host

### 🛠️ Management Tools
- **meowftp.py**: Komfortables User-Management
- **debug-ftp.sh**: Umfassende Diagnose
- **fix-permissions.sh**: Auto-Repair für Permissions
- **build-ftps-pem.sh**: SSL-Cert Converter

---

## 🔧 Requirements

### System
- **Linux** (getestet auf Ubuntu 22.04/24.04, Debian 12)
- **Docker** ≥ 20.10
- **Docker Compose** ≥ 2.0
- **Root-Zugriff** (für FTP User Management)

### Netzwerk
- **Ports**: 80, 443, 21, 21000-21010 müssen frei sein
- **Port-Forwarding** am Router für externe Erreichbarkeit
- **Cloudflare Account** mit API Token (Zone:DNS Edit)

### Optional
- **WSL2** (Windows-User können MeowHome in WSL2 betreiben)

---

## 🚀 Quick Start

### 1. Installation

```bash
# Repository klonen (oder Script herunterladen)
git clone https://github.com/yourusername/meowhome.git
cd meowhome

# Init-Script ausführen
chmod +x init-meowhome.sh
./init-meowhome.sh ~/meowhome
```

### 2. Configuration

```bash
cd ~/meowhome
nano .env
```

**Minimal-Configuration:**

```bash
# Deine Domains (komma-separiert)
DOMAINS=example.com,example.net

# Let's Encrypt Email
LE_EMAIL=admin@example.com

# Cloudflare API Token
CLOUDFLARE_API_TOKEN=dein_cloudflare_token_hier

# FTP: Öffentliche IP oder Domain
FTP_PUBLIC_HOST=ftp.example.com

# Database Passwörter
DB_ROOT_PASSWORD=sicheres_passwort_hier
DB_PASSWORD=app_passwort_hier
```

### 3. System starten

```bash
# Container bauen und starten
docker compose up -d --build

# Logs verfolgen
docker compose logs -f
```

### 4. FTP User erstellen

```bash
# User für spezifische Domain
./tools/ftp/meowftp.py add webmaster example.com

# User mit Vollzugriff
./tools/ftp/meowftp.py add admin ""

# Änderungen aktivieren (benötigt sudo!)
sudo ./tools/ftp/meowftp.py apply
```

### 5. Zertifikate prüfen

```bash
# Certbot Logs anschauen
docker logs -f meowhome_certbot

# Wenn Zertifikate erfolgreich erstellt wurden:
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

### Container Übersicht

| Container | Image | Ports | Beschreibung |
|-----------|-------|-------|--------------|
| `meowhome_apache` | Custom (Debian) | 80, 443 | Web Server |
| `meowhome_php` | php:8.3-fpm-alpine | - | PHP-FPM |
| `meowhome_db` | mariadb:10.11 | - | Database |
| `meowhome_ftp` | Custom (Debian) | 21, 21000-21010 | FTP Server |
| `meowhome_certbot` | certbot/certbot | - | SSL Zertifikate |
| `meowhome_dns_updater` | python:3.12-slim | - | DNS Updates |
| `meowhome_pma` | phpmyadmin:5 | 127.0.0.1:8080 | phpMyAdmin |

---

## ⚙️ Configuration

### .env Datei - Alle Optionen

```bash
# ============================================================
# Windows/LAN Integration
# ============================================================
WIN_HOST_IP=192.168.178.59  # Für Reverse Proxy zu Windows-Apps

# ============================================================
# Domains & DNS
# ============================================================
DOMAINS=example.com,example.net
A_RECORDS_example_com=example.com,www.example.com,shop.example.com
A_RECORDS_example_net=example.net,www.example.net

# Cloudflare Settings
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

# Wildcard Mode (empfohlen)
WILDCARD=true

# Alternativ: Spezifische Hosts
# WILDCARD=false
# HOSTS=example.com,www.example.com,shop.example.com

# ============================================================
# FTP / FTPS
# ============================================================
FTP_ENABLED=true
FTP_PASV_MIN=21000
FTP_PASV_MAX=21010

# WICHTIG: Öffentliche IP oder DNS Name!
FTP_PUBLIC_HOST=ftp.example.com

# FTPS (nach Cert-Erstellung)
FTP_TLS=NO
FTP_CERT_DOMAIN=example.com

# File Permissions
FTP_HOST_UID=1000
FTP_HOST_GID=1000

# ============================================================
# Database
# ============================================================
#Host mariadb
DB_ROOT_PASSWORD=super_secure_root_password
DB_NAME=app
DB_USER=app
DB_PASSWORD=secure_app_password
```

### Apache VHosts

Erstelle VHost-Dateien in `apache/vhosts/`:

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

**Reverse Proxy Beispiel (Jellyfin):**

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

### meowftp.py - User Management Tool

Das Tool verwaltet FTP Virtual Users in einer SQLite-Database und synchronisiert sie mit vsftpd.

#### Befehle

```bash
# User auflisten
./tools/ftp/meowftp.py list

# User hinzufügen (Domain-spezifisch)
./tools/ftp/meowftp.py add webmaster example.com

# User hinzufügen (Vollzugriff auf alle Domains)
./tools/ftp/meowftp.py add admin ""

# User löschen
./tools/ftp/meowftp.py del username

# User deaktivieren (ohne zu löschen)
./tools/ftp/meowftp.py disable username

# User aktivieren
./tools/ftp/meowftp.py enable username

# Passwort ändern
./tools/ftp/meowftp.py passwd username

# Home-Verzeichnis ändern
./tools/ftp/meowftp.py home username example.net

# Änderungen aktivieren (WICHTIG!)
sudo ./tools/ftp/meowftp.py apply
```

#### Workflow Beispiel

```bash
# 1. User für example.com erstellen
./tools/ftp/meowftp.py add alice example.com
# Passwort eingeben: ********

# 2. Admin mit Vollzugriff erstellen
./tools/ftp/meowftp.py add admin ""
# WARNUNG erscheint, mit "yes" bestätigen

# 3. Änderungen aktivieren
sudo ./tools/ftp/meowftp.py apply

# 4. Status prüfen
./tools/ftp/meowftp.py list
# alice                enabled=✓ path=htdocs/example.com
# admin                enabled=✓ path=htdocs/(all domains)
```

### FTP Directory Structure

```
htdocs/
├── example.com/          ← User "alice" sieht nur diesen Ordner
│   ├── index.php
│   └── .htaccess
└── example.net/          ← User "bob" sieht nur diesen Ordner
    └── index.php

User "admin" (home_rel="") sieht:
htdocs/
├── example.com/
└── example.net/
```

### FileZilla Verbindung

```
Host:      ftp.example.com (oder deine öffentliche IP)
Port:      21
Protokoll: FTP (oder FTPS wenn aktiviert)
User:      alice
Passwort:  ********
```

**Für FTPS:**
```
Protokoll: FTP - File Transfer Protocol (Explizites TLS)
Port:      21
```

---

## 🔒 SSL/TLS Zertifikate

### Let's Encrypt Wildcard Zertifikate

MeowHome nutzt **Cloudflare DNS-01 Challenge** für Wildcard-Zertifikate:

```bash
# Certbot läuft automatisch und erstellt Certs für:
# - example.com
# - *.example.com
# - example.net
# - *.example.net
```

#### Manueller Certbot Restart

```bash
docker compose restart certbot
docker logs -f meowhome_certbot
```

#### Zertifikat-Verzeichnis

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

### FTPS aktivieren

```bash
# 1. Warte bis Certbot erfolgreich war
docker logs meowhome_certbot | grep "Successfully"

# 2. Erstelle vsftpd PEM aus Let's Encrypt Cert
./ftp/build-ftps-pem.sh example.com

# 3. Aktiviere TLS in .env
nano .env
# FTP_TLS=YES

# 4. FTP Container neustarten
docker compose restart ftp

# 5. In FileZilla: "FTP - Explizites TLS" nutzen
```

---

## 🐛 Troubleshooting

### FTP Login schlägt fehl (530 Login incorrect)

```bash
# 1. Debug Report ausführen
./tools/ftp/debug-ftp.sh

# 2. Prüfe ob apply ausgeführt wurde
./tools/ftp/meowftp.py list
# Wenn User da sind, aber Login fehlschlägt:
sudo ./tools/ftp/meowftp.py apply

# 3. Live Logs während Login-Versuch
docker logs -f meowhome_ftp

# 4. PAM Config prüfen
docker exec meowhome_ftp cat /etc/pam.d/vsftpd_virtual
# Sollte enthalten: crypt=crypt

# 5. User Database prüfen
docker exec meowhome_ftp db5.3_dump /etc/vsftpd/users.db | head -10
```

### Apache startet nicht / SSL Fehler

```bash
# Wenn Zertifikate noch nicht existieren:
# 1. SSL VHosts temporär deaktivieren
mv apache/vhosts/10-example.conf apache/vhosts/10-example.conf.disabled

# 2. Apache neustarten
docker compose restart web

# 3. Auf Certbot warten
docker logs -f meowhome_certbot

# 4. Nach erfolgreicher Cert-Erstellung VHost wieder aktivieren
mv apache/vhosts/10-example.conf.disabled apache/vhosts/10-example.conf
docker compose restart web
```

### Permission Denied beim FTP Upload

```bash
# 1. Fix Permissions Tool nutzen
./tools/ftp/fix-permissions.sh

# 2. Manuell prüfen
docker exec meowhome_ftp ls -la /var/www/example.com

# Sollte sein: drwxrwxr-x ftp ftp

# 3. UID/GID in .env prüfen
cat .env | grep FTP_HOST
# FTP_HOST_UID=1000
# FTP_HOST_GID=1000

# 4. Host UID herausfinden
id -u
id -g
```

### DNS Updater funktioniert nicht

```bash
# Logs prüfen
docker logs meowhome_dns_updater

# Cloudflare Token testen
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# State-File prüfen
cat state/state.json
```

### Container startet nicht

```bash
# Alle Container Status
docker compose ps

# Logs eines spezifischen Containers
docker compose logs web
docker compose logs php
docker compose logs ftp

# Container neu bauen
docker compose build --no-cache
docker compose up -d
```

---

## 🎯 Best Practices

### Sicherheit

1. **Passwörter**: Niemals default Passwörter nutzen
2. **FTP Users**: Pro Developer einen eigenen User
3. **phpMyAdmin**: Nur über SSH Tunnel nutzen (`ssh -L 8080:localhost:8080 user@server`)
4. **.env**: Niemals in Git committen (ist in .gitignore)
5. **Firewall**: UFW oder iptables einrichten
6. **Updates**: Regelmäßig `docker compose pull && docker compose up -d`

### Performance

1. **PHP OPcache**: Ist aktiviert in `php/custom.ini`
2. **Apache HTTP/2**: Ist aktiviert
3. **MariaDB**: InnoDB Buffer Pool bei viel Traffic anpassen

### Backup

```bash
# Database Backup
docker exec meowhome_db mysqldump -u root -p$DB_ROOT_PASSWORD --all-databases > backup.sql

# Webroot Backup
tar -czf htdocs-backup.tar.gz htdocs/

# FTP User DB Backup
cp ftp/users.sqlite ftp-users-backup.sqlite

# Complete Backup
tar -czf meowhome-backup-$(date +%Y%m%d).tar.gz \
  --exclude='db/*' \
  --exclude='state/*' \
  ~/meowhome/
```

### Monitoring

```bash
# Alle Container Status
docker stats

# Disk Usage
docker system df

# Logs rotieren (wenn zu groß)
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
│   └── snippets/            # Wiederverwendbare Configs
│       ├── php-fpm.conf
│       ├── ssl-common.conf
│       └── cf-safe-redirect.conf
├── certbot/
│   ├── Dockerfile
│   └── run.sh               # Let's Encrypt Automation
├── dns-updater/
│   ├── Dockerfile
│   ├── run.sh
│   └── DNSUpdatecloudflare.py
├── ftp/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── build-ftps-pem.sh   # FTPS Cert Builder
│   ├── data/                # FTP Config (Volume)
│   │   ├── users.d/         # Per-User Configs
│   │   ├── users.db         # Berkeley DB (generiert)
│   │   └── users.txt        # Plaintext User List (temp)
│   ├── ssl/                 # FTPS Certificates
│   │   └── vsftpd.pem
│   └── users.sqlite         # User Database (Host)
├── htdocs/                  # Web Root (Volume)
│   ├── example.com/
│   │   └── index.php
│   └── example.net/
│       └── index.php
├── php/
│   ├── Dockerfile
│   └── custom.ini           # PHP Settings
├── web/
│   └── Dockerfile           # Apache Image
├── tools/
│   ├── ftp/
│   │   ├── meowftp.py      # FTP User Management
│   │   ├── debug-ftp.sh    # Diagnose Tool
│   │   └── fix-permissions.sh
│   └── apache/
├── db/                      # MariaDB Data (Volume, gitignored)
├── letsencrypt/            # Let's Encrypt Certs (Volume)
├── state/                   # Runtime State (gitignored)
├── legacy/                  # Alte Scripts
├── docker-compose.yml
├── .env                     # Configuration (gitignored!)
├── .env.example             # Template
└── .gitignore
```

---

## 🔄 Update / Upgrade

```bash
cd ~/meowhome

# 1. Backup erstellen
docker compose down
tar -czf backup-$(date +%Y%m%d).tar.gz \
  .env htdocs/ ftp/users.sqlite apache/vhosts/

# 2. Neuestes init-Script holen
wget https://raw.githubusercontent.com/yourusername/meowhome/main/init-meowhome.sh
chmod +x init-meowhome.sh

# 3. Update ausführen (überschreibt nur System-Dateien, nicht deine Daten)
./init-meowhome.sh ~/meowhome

# 4. Container neu bauen
docker compose build --no-cache
docker compose up -d

# 5. FTP User neu applyen
sudo ./tools/ftp/meowftp.py apply
```

---

## 🤝 Contributing

Contributions sind willkommen! Bitte:

1. Fork das Repository
2. Feature Branch erstellen (`git checkout -b feature/AmazingFeature`)
3. Änderungen committen (`git commit -m 'Add some AmazingFeature'`)
4. Branch pushen (`git push origin feature/AmazingFeature`)
5. Pull Request öffnen

### Entwickler Setup

```bash
# Repository klonen
git clone https://github.com/yourusername/meowhome.git
cd meowhome

# Eigene .env erstellen
cp .env.example .env
nano .env

# Dev-Umgebung starten
docker compose up --build
```

---

## 📝 Changelog

### Version 2.0 (2024-02)
- ✅ **FIX**: FTP Virtual Users Authentication (PAM crypt=crypt)
- ✅ **NEW**: Robustes meowftp.py mit Container-Readiness
- ✅ **NEW**: Umfassende Debug-Tools
- ✅ **IMPROVED**: Dokumentation und Error Handling

### Version 1.0 (2024-01)
- Initial Release

---

## ❓ FAQ

<details>
<summary><strong>Kann ich MeowHome ohne Docker nutzen?</strong></summary>

Nein, MeowHome ist vollständig Docker-basiert. Das vereinfacht Installation, Isolation und Updates erheblich.
</details>

<details>
<summary><strong>Welche PHP Extensions sind verfügbar?</strong></summary>

Standard: `intl`, `pdo`, `pdo_mysql`, `zip`, `opcache`, `mbstring`, `gd`

Weitere Extensions können in `php/Dockerfile` hinzugefügt werden.
</details>

<details>
<summary><strong>Kann ich mehrere PHP Versionen gleichzeitig nutzen?</strong></summary>

Ja, erstelle mehrere PHP Container in docker-compose.yml:
```yaml
php81:
  build: ./php-8.1/
php83:
  build: ./php-8.3/
```
Dann in Apache VHosts unterschiedliche Proxy-Targets nutzen.
</details>

<details>
<summary><strong>Funktioniert MeowHome mit anderen DNS Providern als Cloudflare?</strong></summary>

Certbot unterstützt viele Provider. Passe `certbot/Dockerfile` an:
```dockerfile
RUN pip install certbot-dns-route53  # Beispiel AWS
```
</details>

<details>
<summary><strong>Wie kann ich WordPress installieren?</strong></summary>

```bash
# 1. WordPress herunterladen
cd ~/meowhome/htdocs/
mkdir mysite.com
cd mysite.com
wget https://wordpress.org/latest.tar.gz
tar -xzf latest.tar.gz --strip-components=1
rm latest.tar.gz

# 2. Database erstellen
docker exec -it meowhome_db mysql -u root -p
# CREATE DATABASE mysite_wp;
# GRANT ALL ON mysite_wp.* TO 'app'@'%';

# 3. Apache VHost erstellen (siehe Configuration)
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

## 📜 License

MIT – see [LICENSE](LICENSE) for details.

---

---

<div align="center">

**MeowHome** - Built with ❤️ for the self-hosting community

## 💖 Support this project

If DGSM saves you time or helps you run your servers, please consider supporting development:

- [**GitHub Sponsors**](https://github.com/sponsors/meowztho)
- [**Paypal**](paypal.me/farrnbacher)
⭐ **Star this repo if it helped you!** ⭐

</div>
