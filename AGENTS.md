# MeowHome agent guide

Start with `ARCHITECTURE.md`, `VERSION`, `CHANGELOG.md`, and the current diff. Preserve the core runtime contract and existing user data.

Before changing behavior, identify the source of truth. Prefer fixing or extending that owner rather than adding another implementation. In particular, `.env` owns configuration, Compose owns service lifecycle, `ftp/users.sqlite` owns FTP identities, and backup/restore owns persistence transfer.

Use the smallest reversible change. Never make restore more destructive, never replace user `.env` values during installation, never recursively change webroot ownership from inside a container, and never require `777` permissions.

For operational diagnosis use, in order:

```bash
./tools/meowhome.py status --json
./tools/meowhome.py doctor --json
```

Then inspect only the affected service logs or restart the affected service. Do not restart the entire stack as a first diagnostic step.

## Security boundaries

Browser POST routes require both authentication and the existing CSRF dependency; every POST form must include the CSRF token. Do not add an unguarded mutation route.

`meowhome_ui` and `meowhome_certbot` must never regain a direct Docker socket mount. Privileged lifecycle operations go through `meowhome_control`, and new control routes must be fixed semantic operations rather than generic shell/exec/Docker pass-throughs. Certbot's token remains reload-only.

Do not log or return `.env` secrets, control tokens, FTP passwords, or database passwords. Audit events record actor/action/target/outcome only. DNS changes must reconcile declared desired state; do not append historical SPF IPs.
