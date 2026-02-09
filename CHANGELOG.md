# Changelog

## v2.3.1
- FIX: FTP `home_rel` Validation angepasst, um legitime relative Pfade korrekt zu akzeptieren
- FIX: Vermeidung von False-Positives bei `home_rel` (z. B. durch naive `..` Erkennung)
- IMPROVED: Robustere Input-Validierung ohne Beeinträchtigung der bestehenden UI-Funktionalität
- SECURITY: Validation bleibt strikt gegen Path Traversal und absolute Pfade


## v2.3.0
- NEW: Local Web UI (MeowHome UI) as a central control panel
- NEW: Dashboard with container status and lifecycle controls
- NEW: Health check page for Docker and all MeowHome services
- NEW: Web-based FTP user management (powered by existing meowftp.py)
- NEW: Web-based Apache VHost editor with config test and safe rollback
- NEW: Full backup system (UI-triggered)
  - Includes all MariaDB databases
  - Includes MariaDB system database (users, privileges, grants)
  - Includes Apache config, FTP user DB, certificates, .env
  - Optional inclusion of htdocs/
- NEW: Dedicated restore script (CLI-only for safety)
- IMPROVED: FTP apply logic hardened against container restart race conditions
- IMPROVED: UI auto-refresh handling after long-running actions


### Version 2.2.0
- FIX: FTP write permissions caused by UID/GID mismatch (FTP guest user mapped to host UID/GID)
- FIX: Avoid bind-mount ownership corruption (no recursive `chown -R` inside containers)
- CHANGE: PHP-FPM runs as host user (`PUID:PGID`), Apache remains root (required for `/var/run/apache2` and ports 80/443)
- NEW: Optional Certbot / DNS updater via `.env` toggles:
  - `CERTBOT_ENABLED=true|false`
  - `DNS_UPDATER_ENABLED=true|false`
- NEW: Select ACME challenge mode via `.env`:
  - `ACME_CHALLENGE=dns` (Cloudflare DNS-01, wildcard)
  - `ACME_CHALLENGE=http` (HTTP-01 fallback, port 80 required, no wildcard)


### Changed
- FTP guest user mapped to host UID/GID
- Apache runs as root, PHP-FPM as host user
- FTP umask set to 002
- 
## v2.1.0
- Added optional warmup restart workaround for WSL2 + Docker startup race conditions
- Documented optional cron @reboot setup and removal
- README improvements and clarifications

## v2.0,0
- Initial public release
