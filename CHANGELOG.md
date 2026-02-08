# Changelog

## v2.0.1
### Fixed
- FTP write permissions broken by UID/GID mismatch
- Apache startup failure when running as non-root
- Bind-mount ownership corruption caused by recursive chown

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
