# Changelog

## v2.9.6 — Private-use stabilization

- Fresh-install ownership follows the invoking WSL user, including sudo installs;
  incomplete packages fail before modifying the target. Existing data and `.env`
  values remain intact during upgrades.
- New installations generate separate database/UI secrets, bind FTP to localhost,
  and require opt-in for DNS/Certbot automation.
- FTP UID/GID mapping fails on collisions instead of silently starting with a
  different identity; domain assignment rejects symlink roots.
- Run FTP under Docker's init process: repeated FTPS sessions no longer crash
  the listener when it reaps orphaned session processes as PID 1.
- File-manager operations use directory descriptors and refuse symlink traversal
  and hard-linked write targets. New content uses the configured PHP/FTP identity.
- Restore preflights protected paths and FTPS material before stopping services;
  valid matching certificate/key pairs produce a private, atomically replaced PEM.
- Fresh-database restore waits for authenticated TCP readiness before SQL import.
- Upgrades no longer recreate example sites removed by the operator; audit events
  retain only actor/action/target/outcome and omit diagnostic details.
- Updated UI dependencies and migrated template calls to the current API, with
  authenticated real-route and CSRF regression coverage.
- Configurable control-service Docker socket for hosts with multiple engines.
- This is a private administrator release; untrusted customer isolation is pending.
- Verified in WSL on 2026-10-31: 144 regression tests (4 environment-dependent
  skips), all 13 installer tests as root, and separate real Docker FTPS/recovery
  tests. Live checks covered authenticated UI pages, CSRF rejection, file-manager
  writes shared with PHP, an HTTPS/PHP response, repeated FTPS sessions, and UI
  backup creation. Customer isolation is not included in this acceptance.

## v2.9.5 — Config and access diagnostics
- Safe preview/opt-in cleanup for obsolete FTP_ENABLED/FTP_HOST_UID/FTP_HOST_GID variables, preserving PUID/PGID, FTP identities, and credentials; private exact-byte backup.
- Read-only FTP scope and webroot owner review for deliberate access decisions.
- FTP all-domain and noncanonical webroot warnings remain visible until authorization/ownership is deliberately changed.
- Deliberately leaves existing UI administrator password unchanged.

## v2.9.4 — Sichere Apache VHost-Verwaltung

- Geführtes Erstellen und manuelle Diff-Vorschau für VHosts.
- Löschbestätigung mit Revisionsprüfung und Rückfall nach Apache-Test.
- Certbot, DNS und Benutzerdaten bleiben unverändert.
- Release-Abnahme: 109 lokale Unit-/Regressionstests, frischer Installer und Docker Compose erfolgreich;
  temporärer VHost über authentifizierte Live-UI erstellt und gelöscht; Bestands-VHosts unverändert.
- GitHub-basierte Git-Historie und CI-Test-Workflow im Release-Paket enthalten.
- Quellstand korrigiert: kein Docker-Client im UI-Image, Apache Directory-Listing deaktiviert,
  Installationsvorlage enthält notwendige Runtime-.gitignore.

## v2.9.3
- Read-only preview and guarded ServerAlias editing of custom Apache VHosts. Unrelated directives preserved.
- Existing DNS, certbot and Apache owners remain unchanged.

## v2.9.2
- Guided settings for unequivocally generated Apache VHosts: aliases, PHP-FPM, reverse-proxy target, and existing TLS certificate selection.
- Custom VHosts remain read-only here and editable through the Advanced VHost editor; conflict detection, revision checks and rollback protect changes.
- DNS updater and Certbot retain their existing automation/ownership, with no new DNS records or certificates created by the UI.
- Apache ServerAlias glob conflicts are distinguished from TLS SAN wildcard coverage.

## v2.9.1
- Domain/TLS health coverage, existing certificate auto-selection, read-only DNS overview, and bounded audit history.

## v2.9.0

- Added per-site hosting detail pages that combine hosting type, aliases, document root/reverse-proxy target, PHP detection, TLS status, and shortcuts without rewriting custom VHosts.
- Added a webroot-scoped File Manager for listing, UTF-8 text editing, uploads up to 8 MiB, directory creation, and non-recursive deletion. Control-side canonical path checks reject traversal, absolute paths, and symlink escapes.
- Added MariaDB user/grant inventory plus database-scoped user creation with a generated one-time password and explicit user removal. System users and raw SQL remain outside the browser API.
- Extended the private control adapter with fixed file and database-user capabilities only; no generic shell, exec, or arbitrary scheduled-command route was introduced.
- Kept DNS provider-neutral: no Cloudflare-specific DNS management semantics were added to the Core/UI.

## v2.8.0

- Reframed the local UI as a resource-oriented hosting control panel instead of a container/file-first interface.
- Added Websites & Domains inventory with structured provisioning for webroots and reverse proxies while preserving raw VHost editing for advanced cases.
- Added provider-neutral SSL/TLS inventory with certificate expiry visibility and existing Certbot renewal flow.
- Added MariaDB database inventory plus narrowly scoped create/drop operations through the existing private control adapter; system schemas remain hidden/protected.
- Added Doctor-backed dashboard tasks, hosting KPIs, and clearer service/administration navigation.
- Resource inventories ignore Apache helper configs without `ServerName` and non-certificate entries under `letsencrypt/live`, keeping normal hosting views free of control-plane noise.
- Extended the control adapter only with fixed doctor, database, and webroot capabilities; no generic exec/shell route was introduced.

## v2.7.0
### Security
- Every state-changing Web UI route now requires a same-origin check plus a signed CSRF form token. UI responses also set `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, and `Cache-Control: no-store`.
- Fresh installs generate a random initial `MEOWHOME_UI_PASS` instead of shipping `admin`; existing installations are never silently re-keyed. The generated credential is printed once by the installer and remains stored only in the owner-only `.env`.
- `meowhome_ui` and `meowhome_certbot` no longer mount `/var/run/docker.sock`. Privileged Docker operations are isolated behind the non-published `meowhome_control` adapter on an internal Docker network.
- The control adapter exposes only fixed MeowHome operations; there is no generic shell/exec endpoint. UI and Certbot use separate secrets, and the Certbot credential is restricted to Apache reload only.
- State-changing UI operations append a secret-free JSONL audit trail to `state/control-audit.jsonl`.
- `doctor` detects direct UI/Certbot Docker-socket exposure, missing/weak control tokens, insecure historical `.env` backup modes, suspicious proxy overrides, and incomplete SPF reconciliation configuration.

### DNS / Apache hardening
- SPF rewriting is opt-in and declarative. When enabled, `SPF_TEMPLATE_<zone>` defines the complete desired SPF record and `{PUBLIC_IP}` is reconciled to the current address; historical IP mechanisms are no longer appended indefinitely.
- Apache disables directory listing by default with `Options -Indexes +FollowSymLinks` while preserving `.htaccess` compatibility for existing applications. No global CSP is imposed.

### Architecture
- The UI remains an adapter over existing Core owners. The private control service delegates to Compose, `tools/meowhome.py`, `meowftp.py`, backup tooling, Certbot, and Apache rather than creating parallel configuration state.
- Control secrets live under `control/` with mode `0600`; the directory is `0700`. They are generated on install/upgrade and excluded from Git.

### Verified
- Security regression suite covers CSRF on all POST routes/forms, control-route restrictions, split UI/Certbot credentials, socket isolation, safe fresh-install credentials, DNS/SPF guards, secret permission diagnostics, and upgrade preservation.

## v2.6.2
### Fixed
- Apache VHost control-plane ownership is now canonicalized to `PUID:PGID`; the UI repairs historical `root:root` active `.conf` drift before VHost operations without touching webroots or database data.
- VHost files use mode `0664` consistently, including rollback paths.
- The official Cloudflare Authenticated Origin Pull CA is shipped as the managed snippet `apache/snippets/cloudflare-origin-pull-ca.pem`, so opt-in AOP VHosts have a deterministic CA path.
- VHost saves preflight managed `SSLCACertificateFile` dependencies and report a precise missing-asset error instead of relying on a generic Apache rollback.
- `doctor` reports Apache control-plane ownership drift and missing referenced AOP CA assets.
- Added `./tools/meowhome.py repair-control-plane` for an explicit Core-owned repair path.

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
- Live upgrade validation confirmed FTPS login, directory listing, upload to a WSL bind-mounted domain, and resulting host ownership matching the configured `PUID:PGID` with mode `664`.

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
