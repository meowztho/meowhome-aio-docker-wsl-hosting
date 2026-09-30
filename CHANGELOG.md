# Changelog

## v2.6.1
### Fixed
- WSL/Docker startup warmup no longer treats `docker info` exit status as sufficient readiness evidence. It requires an actual Docker server version plus a fresh bind-mount probe of the installed MeowHome project.
- After readiness is proven, warmup recreates the Compose services with `up -d --force-recreate --no-build` instead of merely restarting existing containers, preventing stale Docker Desktop WSL bind-mount mirrors from surviving the boot race.
- The readiness window is extended to 180 seconds and fails closed without touching containers if Docker Desktop WSL integration never becomes healthy.

### Verified
- Live Windows 11 / WSL2 recovery reproduced the race: FTP and StreamGuide restart loops, stale Apache certificate mount, and a file-bind mirror created as a directory. After restoring Docker Desktop's user-distro proxy and recreating affected containers, FTP and PHP were `Up`, StreamGuide was `healthy`, Apache retained both `meowhome_default` and `streamguide_proxy`, and public HTTPS returned HTTP 200.

## v2.6.0
### Added
- Declarative external reverse-proxy network support via `MEOWHOME_WEB_EXTERNAL_NETWORKS`; Apache network membership is rendered into the Compose model instead of relying on one-time `docker network connect`.
- `doctor` validates external network names and, at runtime, verifies that `meowhome_apache` is actually attached to every configured external network.
- Recovery guidance now treats Docker Desktop/WSL bind-mount integration failure separately from real Unix permission drift.

### Security / Hardening
- Documents Cloudflare Authenticated Origin Pulls as the preferred opt-in origin-authentication path. Enforcement is intentionally not enabled automatically because Cloudflare-side AOP must be configured and verified first.

## v2.5.2
### Fixed
- Backup control-plane cards now support the intended 5/7-column split. The shared 12-column grid defines `col-5`/`col-7` and collapses them correctly on narrow screens, preventing the Backup page from shrinking both cards into single grid tracks.
- README/release documentation was reconciled with the 2.5 Core-First behavior: direct WSL bind mounts, canonical backup tooling, UI configuration keys, current container names, and authoritative CHANGELOG linkage.

## v2.5.1
### Fixed
- FTPS data-channel compatibility: generated `vsftpd.conf` now sets `require_ssl_reuse=NO`. This keeps TLS mandatory for login and data transfers while avoiding vsftpd `522` failures with clients that cannot reuse the control-channel TLS session (confirmed with Windows `curl.exe`).

### Verified
- Live upgrade validation confirmed FTPS login, directory listing, upload to a WSL bind-mounted domain, and resulting host ownership `1001:1001` with mode `664`.

## v2.5.0
### Added
- FTP access modes now support one domain, multiple selected domains, or all domains per virtual user. Single-domain users land directly in that domain; multi-domain users see only their assigned domain folders.
- Multi-domain isolation uses a generated Compose override with bind mounts to the existing WSL `htdocs/` folders; no Docker named volumes, ACL/FUSE layer, or copied web data are introduced.
- Published HTTP, HTTPS, phpMyAdmin, and FTP control ports/bind addresses are first-class `.env` settings and editable from the Setup UI.
- The Web UI is modernized into a consistent control plane for services, setup, FTP/domain access, VHosts, backups, health, and logs.
- `MEOWHOME_HOST_PROJECT_DIR` records the absolute WSL installation path so Compose actions launched from inside the UI container still bind the real host files.

### Changed
- FTP UI consumes structured JSON from `meowftp.py` instead of parsing CLI text, keeping SQLite/CLI/UI on one core contract.
- Existing FTP SQLite databases are migrated additively; legacy `home_rel` users remain valid.
- Installer upgrades best-effort migrate hard-coded published ports from older managed Compose files into the new `.env` keys before replacing the managed Compose definition.
- Installer and restore rebind location-specific host-path metadata to the actual target directory; installed backup/restore tools derive their default project from their own location rather than `$HOME`, fixing `sudo` accidentally targeting `/root/meowhome`.
- UI-created config/VHost files and root-run backup archives are handed back to the canonical `PUID:PGID` owner.

### Safety
- Existing `.env`, VHosts, certificates, databases, `htdocs`, and FTP identities remain user/runtime-owned and are not replaced during upgrade.
- Installer upgrades no longer run recursive permission hardening implicitly; ownership repair remains an explicit operator action after `doctor`/inspection.
- Custom `docker-compose.override.yml` files are never overwritten by FTP multi-domain generation.
- UI stack actions deliberately exclude the UI container itself to avoid self-recreate races.

## v2.4.2
### Fixed
- Ownership-related `.env` readers now consistently use the last assignment, matching the effective dotenv value instead of allowing duplicate `PUID`/`PGID` lines to make FTP, backup/restore, FTPS PEM generation, or permission hardening disagree.
- Installer upgrades collapse duplicate `PUID`/`PGID` entries while preserving the last configured value.

### Improved
- `meowhome.py doctor` reports duplicate `.env` keys, stale generated FTP user state, enabled all-domain FTP users, and top-level webroot ownership drift without modifying permissions.

## v2.4.1
### Fixed
- Upgrade migration preserves legacy `FTP_HOST_UID`/`FTP_HOST_GID` as canonical `PUID`/`PGID` when an existing `.env` predates those keys, preventing ownership changes for existing FTP/web bind mounts.

## v2.4.0
### Added
- Core-first operational contract documented in `ARCHITECTURE.md` and `AGENTS.md`
- Stdlib-only `tools/meowhome.py` CLI with `schema`, `status`, `doctor`, `up`, targeted `restart`, and `logs`; diagnostics include sensitive-file permission checks
- Automated regression tests and GitHub Actions verification

### Fixed
- Backup includes the canonical FTP user database (`ftp/users.sqlite`) while excluding generated `ftp/data/` state and raw MariaDB files; generated archives are owner-only (`0600` via `umask 077`)
- Restore is overlay-only, supports empty disaster-recovery targets, preserves web content when `htdocs` was not backed up, validates tar paths, and rebuilds FTP auth state after restore
- Installer upgrades no longer overwrite existing example webroot/VHost files or mutate running containers
- Fresh installs use the invoking host UID/GID for `PUID`/`PGID`; legacy FTP UID/GID keys are no longer emitted
- Fresh `.env` files, UI-created `.env` backups, FTP user SQLite state, and backup archives use owner-only permissions for sensitive data
- FTP validation is consistent between CLI/UI, stale auth files are removed on apply, and an empty active-user set produces an empty auth DB instead of leaving old users active
- UI FTP password creation no longer exposes plaintext passwords in process arguments; `openssl passwd` also receives plaintext via stdin
- Setup UI applies changed UI login credentials immediately instead of attempting to recreate its own container
- DNS updater only commits state after all requested changes succeed and selects the SPF TXT record instead of an arbitrary TXT record
- Certbot retries failed initial issuance instead of falling into renew-only loops and includes the Docker CLI required to reload Apache after certificate changes
- Apache receives only the `WIN_HOST_IP` variable required by shipped reverse-proxy templates instead of the entire `.env`
- The shipped HTTP example VHost now routes `.php` through PHP-FPM instead of potentially serving PHP source as a static file before TLS is configured

### Improved
- Compose lifecycle handling prefers Compose v2 with compatibility fallback where appropriate; the Web UI ships Compose v2 from the official Docker CLI image
- Permissions repair has one canonical implementation and preserves existing file executable bits
- FTPS PEM creation validates its domain input and can use `FTP_CERT_DOMAIN` from `.env`
- FTP hostname resolution no longer interpolates configuration values into embedded Python source
- SQLite connections in the FTP tool are explicitly closed after each operation

## v2.3.3
### Added
- VHost delete action in the Web UI (`/vhosts`) with per-file delete button and confirmation prompt

### Fixed
- Certbot startup loop when multiple Let's Encrypt accounts exist but `LE_ACCOUNT` is not set
- Certbot now auto-selects the account from existing renewal configs when this is unambiguous

### Improved
- Installer output now clearly explains when `LE_ACCOUNT` is required and where to find account IDs

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
