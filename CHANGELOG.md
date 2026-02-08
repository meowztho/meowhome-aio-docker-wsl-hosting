# Changelog

### Version 2.2.0
- ✅ FIX: FTP write permissions caused by UID/GID mismatch (FTP guest user mapped to host UID/GID)
- ✅ FIX: Avoid bind-mount ownership corruption (no recursive `chown -R` inside containers)
- ✅ CHANGE: PHP-FPM runs as host user (`PUID:PGID`), Apache remains root (required for `/var/run/apache2` and ports 80/443)
- ✅ NEW: Optional Certbot / DNS updater via `.env` toggles:
  - `CERTBOT_ENABLED=true|false`
  - `DNS_UPDATER_ENABLED=true|false`
- ✅ NEW: Select ACME challenge mode via `.env`:
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
