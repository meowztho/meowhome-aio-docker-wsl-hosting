# MeowHome architecture

## Core-first contract

MeowHome is split into a small operational core and replaceable adapters.

The **core contract** is the installed project layout, `.env` configuration, Compose service names, persistent-data boundaries, and the `tools/meowhome.py` control interface. Web UI, FTP tooling, backup/restore, DNS and certificate automation are adapters around that contract; they must not invent incompatible state or lifecycle rules.

### Stable runtime contract

- Runtime project root: `${MEOWHOME_PROJECT_DIR}` (inside the privileged control adapter this is `/meowhome`; the UI receives only the specific bind mounts it manages)
- Host project root: `.env:MEOWHOME_HOST_PROJECT_DIR` (absolute WSL path, installer/restore managed)
- Configuration: `.env`
- Orchestration: `docker-compose.yml`
- Web content: `htdocs/`
- Database persistence: `db/`
- Certificates: `letsencrypt/`
- DNS/runtime state: `state/`
- FTP source of truth: `ftp/users.sqlite`
- Generated FTP domain-view orchestration: `docker-compose.override.yml` (only when a user has multiple assigned domains)
- Operational interface: `tools/meowhome.py`

Container names and Compose service names are compatibility contracts because tools and the UI address them directly.

The installer owns shipped tooling, container definitions, snippets, and templates. Files under `htdocs/` and existing files under `apache/vhosts/` are user-owned runtime content: examples are seeded only in a clean installation. Upgrades must neither overwrite existing content nor recreate examples that the operator removed.

## Ownership

| Concern | Source of truth | Consumers |
|---|---|---|
| Configuration | `.env` | Compose, UI, certbot, DNS updater, FTP |
| Host bind-mount location | `MEOWHOME_HOST_PROJECT_DIR` | Compose, control-adapter Compose operations, FTP domain-view override |
| Service lifecycle | Compose | CLI, private control adapter, UI, warmup |
| External reverse-proxy networks | `.env:MEOWHOME_WEB_EXTERNAL_NETWORKS` rendered into Compose | Apache, `doctor` |
| FTP identities + domain assignments | `ftp/users.sqlite` | `meowftp.py`, UI, vsftpd generated DB |
| Apache vhosts | `apache/vhosts/*.conf` | Apache, UI editor |
| Web content | `htdocs/` | Apache, PHP, FTP |
| Certificates | `letsencrypt/` | Apache, certbot, FTPS builder |
| Backup format | `tools/backup/{backup,restore}.sh` + manifest | CLI/UI operator |
| Health/diagnostics | `tools/meowhome.py status/doctor` | humans and agents |
| Privileged Docker operations | `meowhome_control` fixed operation adapter | UI, Certbot |
| Browser mutation protection | UI same-origin + signed CSRF token | all UI POST forms/routes |
| Control-plane audit trail | `state/control-audit.jsonl` | operator diagnostics |

The entire `ftp/data/` directory is generated runtime state. Authentication files such as `users.db`, `users.txt`, and `users.d/*` are rebuilt from `ftp/users.sqlite` by `meowftp.py apply`; `vsftpd.conf` is rebuilt by the FTP container entrypoint. A MeowHome-marked `docker-compose.override.yml` is also generated only when an FTP user needs an isolated view containing multiple assigned domains. It bind-mounts the existing WSL `htdocs/<domain>` directories into that user view; it never copies web data and is not a second source of truth. A pre-existing custom override is never overwritten.

`MEOWHOME_HOST_PROJECT_DIR` is location metadata rather than a user-tunable hosting setting. The installer always binds it to the actual installation directory, and restore rebinds it to the restore destination. This lets Compose run either from the host shell or from the UI container while the Docker daemon always receives the real WSL bind-mount paths. Build contexts stay relative to the mounted runtime; persistent data remains direct WSL bind-mounted data, not Docker named volumes.


## Privilege boundary

### Private-use release and customer isolation

Version 2.9.6 retains one trusted administrator and a shared PHP/FTP Unix identity.
`.env` owns `PUID:PGID`; virtual FTP usernames are authentication/access scopes,
not separate Unix users. The installer establishes ownership only for a new
installation; upgrades preserve existing webroots. New file-manager content uses
the configured identity, directories 2775 and files 0664. Symlink paths are not
editable through the file manager.

Untrusted multi-customer hosting remains a subsequent architecture migration.
Before enabling customer access it needs one canonical customer/resource ownership
model, authenticated customer authorization on every operation, separate PHP
execution identities and mounts/networks, scoped FTP and database privileges,
resource limits, and tenant-scoped backup/recovery. Shared-UID FTP chroot alone
does not establish this boundary. Existing sites stay in the administrator's
private scope until an explicit migration; customer endpoints must not be enabled
on the current shared runtime.

The first customer-isolation target is Docker Desktop/WSL. Keep the validated
private release as a separate checkpoint. Migration must initially be opt-in for
new customer resources; existing operator sites and credentials remain unchanged.
Customer acceptance must prove that uploaded PHP code, FTP logins, browser/API
requests, and database credentials cannot read or change another customer's data
or the administrator's control plane. Merely filtering lists in the UI is not
an isolation implementation.

`MEOWHOME_DOCKER_SOCKET` selects the host engine socket mounted only by control;
the default remains `/var/run/docker.sock`. It supports WSL installations where
native Docker and Docker Desktop coexist without changing global host settings.
Operator CLI commands must address the same engine.

`meowhome_ui` and `meowhome_certbot` must not mount `/var/run/docker.sock`. The only MeowHome service permitted to own that socket is `meowhome_control`, which has no published host port and is attached only to the internal `control_net`. It exposes a fixed operation vocabulary; adding a generic shell, arbitrary container exec, or arbitrary Docker-command endpoint is forbidden.

The UI receives the admin control token. Certbot receives a distinct reload-only token accepted only for `/v1/apache-reload`. Both files are generated under `control/`, owner-only, excluded from Git, and included in owner-only/operator-protected disaster-recovery backups with the rest of project configuration.

Browser-originated mutations are additionally protected at the UI boundary by HTTP Basic authentication, a same-origin Origin/Referer check, and a signed CSRF form token. The UI remains bound to `127.0.0.1` by default.

## Persistence and backup boundaries

A normal backup contains project configuration/tooling plus a logical MariaDB dump. `db/` is intentionally excluded because raw database files are not a portable backup. Generated `ftp/data/` is excluded and rebuilt from its owners after restore. `htdocs/` is optional because it can be large. `backups/` and `.git/` are never nested into backups. Installed backup/restore tools derive the project root from their own location so `sudo` cannot silently redirect operations to `/root/meowhome`; an explicit `MEOWHOME_PROJECT_DIR` remains available for alternate restore targets.

Restore is overlay-only for project configuration. It must never delete paths merely because an older backup did not contain them. Database restore remains explicit and uses the logical dump.

## Extension rules

New capabilities should extend the core contract rather than duplicate it:

1. Add configuration to `.env.example` and validation to `tools/meowhome.py doctor`.
2. Add a Compose service only when a separate runtime process is required.
3. Prefer a tool/subcommand over another independent state store.
4. Preserve stable service/container names unless a migration is provided.
5. Destructive operations require an explicit command and must be reversible from backup.
6. UI actions should call the private control adapter or the same underlying file/tool contracts used by CLI workflows; never reintroduce direct Docker-socket access into the UI.
7. Web content remains host/WSL bind-mounted data. Do not replace `htdocs/` with Docker named volumes without an explicit architecture migration.

## Verification contract

At minimum, changes should pass:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile DNSUpdatecloudflare.py meowhome-ui/app/main.py assets/tools/ftp/meowftp.py assets/tools/meowhome.py
bash -n init-meowhome.sh assets/tools/backup/backup.sh assets/tools/backup/restore.sh assets/tools/permissions_hardening.sh assets/tools/warmup.sh
```

When Docker is available, additionally run an installer smoke test and `docker compose config`, then use `tools/meowhome.py doctor` against the installed project.

The disposable integration tests require prebuilt local `meowhome-ftp` and
`mariadb:10.11` images and the intended Docker engine selected explicitly:

```bash
MEOWHOME_DOCKER_TESTS=1 python3 -m unittest tests.test_ftp_integration tests.test_restore_integration -v
```

They publish no ports. FTPS tests cover repeated sessions, assigned domain views,
writes and UID collision rejection. Recovery tests run the normal backup/restore
scripts with a fixture-only database-container name translation, a real MariaDB
with a fresh data directory, optional webroot data and synthetic certificates.
The recovery fixture omits full-stack startup and FTP auth regeneration; those
remain separate integration boundaries.

## UI projection and generated hosting settings (2.9.1–2.9.2)
Domain/TLS health is read-only over canonical Apache VHosts and installed certificate SANs. The DNS screen displays configured zones/updater process state, not verified public records. Activity history reads the existing audit JSONL; no second event store exists.

The settings editor can rewrite only files that match the exact known MeowHome VHost generator output. Handwritten VHosts remain Advanced-only. Saves recheck the source revision, reject overlapping Apache aliases (glob semantics), validate existing certificate SANs (one-label TLS wildcards), make a VHost backup, and call the existing Apache test/reload with rollback. No DNS-record creation, Certbot issuance, or credential mutation is performed by this UI.

## Custom VHost alias editing (2.9.3)
Custom VHosts remain canonical Apache files. A conservative ServerAlias-only preview preserves all other bytes; apply rechecks source revision and invokes existing backup/Apache validation/reload. Complex syntax stays Advanced-only. Certbot and DNS updater remain the owners of their own configuration and runtime.

## VHost lifecycle (2.9.4)
Apache .conf files remain canonical. The UI uses one VHost transaction for guided creation, raw save and deletion: version check, backup, Apache test/reload and rollback. Removal keeps webroots, database, DNS and certificates. Certbot and DNS updater remain the owners of automation.

## Legacy FTP configuration and access diagnostics (2.9.5)
.env PUID/PGID are authoritative identities. FTP_HOST_UID, FTP_HOST_GID, and
FTP_ENABLED are obsolete fallback variables once canonical keys exist.
meowhome.py cleanup-legacy-ftp-env previews an exact-line removal; --apply
writes a private byte-for-byte backup before atomically removing only those keys.
No runtime service is restarted and FTP SQLite access assignments do not change.

meowhome.py access-review --json is a read-only projection over canonical
FTP SQLite and top-level webroot metadata. A broad FTP entitlement and owner
mismatch remain genuine warnings until reviewed; diagnostics never grant
access, recursively chown user content, or suppress warnings by default.
