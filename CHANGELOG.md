# Changelog

## v2.3.2
### Fixed
- Certbot non-interactive account selection now works reliably when multiple Let's Encrypt accounts exist
- Prevented startup failure with `Please choose an account` by supporting explicit account selection

## v2.3.1
### Fixed
- FTP `home_rel` validation adjusted to correctly accept legitimate relative paths
- Prevention of false positives in `home_rel` validation (e.g. naive `..` detection)
- Edge cases where valid FTP paths were rejected by overly strict checks

### Improved
- `meowftp` refactored and aligned with Web UI logic
- Shared validation and behavior between CLI and UI
- More robust input validation without impacting existing UI functionality

### Added
- Dark mode for MeowHome Web UI
- Guided setup flow in the Web UI
  - Full `.env` configuration via browser
  - Reduced need for manual file editing
  - Suitable for first-time installations

### Security
- FTP path validation remains strict against:
  - Path traversal
  - Absolute paths
  - Escaping the intended FTP root


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
