#!/usr/bin/env python3
"""MeowHome operational CLI.

This module is intentionally stdlib-only so it remains usable on a fresh host
before optional Python dependencies are installed.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
from dataclasses import asdict, dataclass
from typing import Any, Iterable

VERSION = "2.6.2"
SERVICE_NAMES = (
    "web",
    "php",
    "mariadb",
    "phpmyadmin",
    "certbot",
    "dns_updater",
    "ftp",
    "ui",
)
CONTAINER_BY_SERVICE = {
    "web": "meowhome_apache",
    "php": "meowhome_php",
    "mariadb": "meowhome_db",
    "phpmyadmin": "meowhome_pma",
    "certbot": "meowhome_certbot",
    "dns_updater": "meowhome_dns_updater",
    "ftp": "meowhome_ftp",
    "ui": "meowhome_ui",
}
CORE_PATHS = (
    "docker-compose.yml",
    ".env",
    "apache/vhosts",
    "htdocs",
    "tools/ftp/meowftp.py",
    "tools/backup/backup.sh",
    "tools/backup/restore.sh",
)
PLACEHOLDER_VALUES = {
    "change-me",
    "admin",
    "PASTE_TOKEN_HERE",
    "CHANGE-ME.example.com",
}


@dataclass(frozen=True)
class Issue:
    severity: str
    code: str
    message: str
    remediation: str = ""


def project_path(value: str | None = None) -> pathlib.Path:
    if value:
        return pathlib.Path(value).expanduser().resolve()
    env_value = os.environ.get("MEOWHOME_PROJECT_DIR")
    if env_value:
        return pathlib.Path(env_value).expanduser().resolve()
    installed_candidate = pathlib.Path(__file__).resolve().parent.parent
    if (installed_candidate / "docker-compose.yml").is_file():
        return installed_candidate
    return pathlib.Path(os.path.expanduser("~/meowhome")).resolve()


def read_env(path: pathlib.Path) -> dict[str, str]:
    result: dict[str, str] = {}
    if not path.is_file():
        return result
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        result[key.strip()] = value
    return result


def duplicate_env_keys(path: pathlib.Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    if not path.is_file():
        return counts
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key:
            counts[key] = counts.get(key, 0) + 1
    return {key: count for key, count in counts.items() if count > 1}


def bool_value(value: str, default: bool = False) -> bool:
    if value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "yes"}


def compose_command(project: pathlib.Path) -> list[str] | None:
    docker = shutil.which("docker")
    if docker:
        try:
            proc = subprocess.run(
                [docker, "compose", "version"],
                cwd=project if project.is_dir() else None,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )
            if proc.returncode == 0:
                return [docker, "compose"]
        except (OSError, subprocess.SubprocessError):
            pass
    standalone = shutil.which("docker-compose")
    if standalone:
        return [standalone]
    return None


def run(cmd: list[str], project: pathlib.Path, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=project,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def _int_range(env: dict[str, str], key: str, low: int, high: int, issues: list[Issue]) -> int | None:
    raw = env.get(key, "")
    if raw == "":
        return None
    try:
        value = int(raw)
    except ValueError:
        issues.append(Issue("error", "numeric_value", f"{key} must be an integer."))
        return None
    if not (low <= value <= high):
        issues.append(Issue("error", "numeric_range", f"{key}={value} is outside {low}..{high}."))
    return value


def canonical_host_ids(project: pathlib.Path) -> tuple[int, int] | None:
    env = read_env(project / ".env")
    puid = env.get("PUID", "")
    pgid = env.get("PGID", "")
    if not (puid.isdigit() and pgid.isdigit()):
        return None
    return int(puid), int(pgid)


def _set_control_plane_metadata(path: pathlib.Path, mode: int, ids: tuple[int, int]) -> None:
    os.chmod(path, mode)
    st = path.stat()
    if (st.st_uid, st.st_gid) == ids:
        return
    if os.geteuid() != 0:
        raise PermissionError(
            f"{path} is owned by {st.st_uid}:{st.st_gid}; root is required to change it to {ids[0]}:{ids[1]}"
        )
    os.chown(path, ids[0], ids[1])


def repair_control_plane_permissions(project: pathlib.Path) -> dict[str, Any]:
    """Normalize only MeowHome-owned Apache control-plane metadata.

    This deliberately does not recurse into htdocs, database data, certificates,
    or user content. Active vhost files are editable configuration owned by the
    canonical host identity from PUID/PGID.
    """
    ids = canonical_host_ids(project)
    if ids is None:
        raise RuntimeError("PUID/PGID must be numeric before repairing control-plane permissions")

    changed: list[str] = []
    targets: list[tuple[pathlib.Path, int]] = []
    vhost_dir = project / "apache/vhosts"
    snippets_dir = project / "apache/snippets"
    if vhost_dir.is_dir():
        targets.append((vhost_dir, 0o2775))
        targets.extend((p, 0o664) for p in sorted(vhost_dir.glob("*.conf")) if p.is_file())
    if snippets_dir.is_dir():
        targets.append((snippets_dir, 0o755))
        for name in (
            "php-fpm.conf",
            "ssl-common.conf",
            "cf-safe-redirect.conf",
            "cloudflare-origin-pull-ca.pem",
        ):
            candidate = snippets_dir / name
            if candidate.is_file():
                targets.append((candidate, 0o644))

    for path, mode in targets:
        before = path.stat()
        _set_control_plane_metadata(path, mode, ids)
        after = path.stat()
        if (before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)) != (
            after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)
        ):
            changed.append(str(path.relative_to(project)))

    return {
        "project": str(project),
        "owner": f"{ids[0]}:{ids[1]}",
        "changed": changed,
    }


def validate_config(project: pathlib.Path) -> list[Issue]:
    issues: list[Issue] = []
    env_path = project / ".env"
    env = read_env(env_path)

    for rel in CORE_PATHS:
        if not (project / rel).exists():
            issues.append(Issue("error", "missing_core_path", f"Missing core path: {rel}"))

    if not env:
        issues.append(Issue("error", "env_missing", f"Missing or empty configuration: {env_path}"))
        return issues

    # Newer published-port keys have stable Compose defaults so older .env files
    # remain valid until the installer persists the explicit values.
    for key, default in {
        "HTTP_BIND": "0.0.0.0", "HTTP_PORT": "80",
        "HTTPS_BIND": "0.0.0.0", "HTTPS_PORT": "443",
        "PHPMYADMIN_BIND": "127.0.0.1", "PHPMYADMIN_PORT": "8080",
        "FTP_BIND": "0.0.0.0", "FTP_PORT": "21",
        "MEOWHOME_UI_BIND": "127.0.0.1", "MEOWHOME_UI_PORT": "9090",
    }.items():
        env.setdefault(key, default)

    duplicates = duplicate_env_keys(env_path)
    for key, count in sorted(duplicates.items()):
        severity = "error" if key in {"PUID", "PGID"} else "warning"
        issues.append(Issue(
            severity,
            "duplicate_env_key",
            f".env contains {count} assignments for {key}; the last value wins.",
            "Keep exactly one assignment for each configuration key.",
        ))

    if os.name == "posix":
        for rel in (".env", "ftp/users.sqlite"):
            sensitive = project / rel
            if sensitive.is_file():
                mode = stat.S_IMODE(sensitive.stat().st_mode)
                if mode & 0o077:
                    issues.append(Issue(
                        "warning",
                        "sensitive_permissions",
                        f"{rel} is readable/writable by group or others (mode {mode:04o}).",
                        f"Review ownership, then run: chmod 600 {rel}",
                    ))

    for key in ("PUID", "PGID"):
        raw = env.get(key, "")
        if not raw.isdigit():
            issues.append(Issue("error", "numeric_value", f"{key} must be a numeric host id."))

    host_project = env.get("MEOWHOME_HOST_PROJECT_DIR", "").strip()
    if not host_project:
        issues.append(Issue(
            "error",
            "host_project_dir_missing",
            "MEOWHOME_HOST_PROJECT_DIR is required so container-initiated Compose actions bind the real host project path.",
            "Run the current init-meowhome.sh against this installation to persist its absolute host path.",
        ))
    elif not pathlib.Path(host_project).expanduser().is_absolute():
        issues.append(Issue(
            "error",
            "host_project_dir_relative",
            "MEOWHOME_HOST_PROJECT_DIR must be an absolute host path.",
            "Run the current init-meowhome.sh against this installation.",
        ))


    external_networks = [x.strip() for x in env.get("MEOWHOME_WEB_EXTERNAL_NETWORKS", "").split(",") if x.strip()]
    invalid_networks = [n for n in external_networks if not re.fullmatch(r"[A-Za-z0-9_.-]+", n)]
    if invalid_networks:
        issues.append(Issue("error", "external_network_name", "Invalid MEOWHOME_WEB_EXTERNAL_NETWORKS entries: " + ", ".join(invalid_networks)))
    if len(set(external_networks)) != len(external_networks):
        issues.append(Issue("warning", "external_network_duplicate", "MEOWHOME_WEB_EXTERNAL_NETWORKS contains duplicate names."))

    domains = [x.strip() for x in env.get("DOMAINS", "").split(",") if x.strip()]
    if not domains or any(re.search(r"[\s/]", d) for d in domains):
        issues.append(Issue("error", "domains_invalid", "DOMAINS must contain valid comma-separated hostnames."))

    cert_enabled = bool_value(env.get("CERTBOT_ENABLED", "true"), True)
    dns_enabled = bool_value(env.get("DNS_UPDATER_ENABLED", "true"), True)
    challenge = env.get("ACME_CHALLENGE", "dns").lower()
    if challenge not in {"dns", "http"}:
        issues.append(Issue("error", "acme_challenge", "ACME_CHALLENGE must be 'dns' or 'http'."))

    if cert_enabled and not env.get("LE_EMAIL", ""):
        issues.append(Issue("error", "le_email_missing", "LE_EMAIL is required while Certbot is enabled."))

    provider = env.get("DNS_PROVIDER", "cloudflare").lower()
    needs_cf = dns_enabled or (cert_enabled and challenge == "dns" and provider == "cloudflare")
    token = env.get("CLOUDFLARE_API_TOKEN", "")
    if needs_cf and (not token or token == "PASTE_TOKEN_HERE"):
        issues.append(Issue("error", "cloudflare_token_missing", "Cloudflare API token is required for the enabled DNS workflow."))
    if cert_enabled and challenge == "dns" and provider != "cloudflare":
        issues.append(Issue("error", "dns_provider_unsupported", f"DNS_PROVIDER={provider!r} is not implemented for Certbot."))

    for key in ("DB_ROOT_PASSWORD", "DB_PASSWORD"):
        value = env.get(key, "")
        if not value or value == "change-me":
            issues.append(Issue("error", "default_secret", f"{key} still uses the shipped placeholder."))

    bind = env.get("MEOWHOME_UI_BIND", "127.0.0.1")
    ui_pass = env.get("MEOWHOME_UI_PASS", "admin")
    ui_default = not ui_pass or ui_pass == "admin"
    if ui_default:
        severity = "warning" if bind in {"127.0.0.1", "localhost", "::1"} else "error"
        issues.append(Issue(severity, "ui_default_password", "MEOWHOME_UI_PASS still uses the default password."))

    for key in ("HTTP_PORT", "HTTPS_PORT", "PHPMYADMIN_PORT", "FTP_PORT", "MEOWHOME_UI_PORT"):
        _int_range(env, key, 1, 65535, issues)

    for key in ("HTTP_BIND", "HTTPS_BIND", "PHPMYADMIN_BIND", "FTP_BIND", "MEOWHOME_UI_BIND"):
        value = env.get(key, "").strip()
        if not value or any(ch.isspace() for ch in value) or ":" in value:
            issues.append(Issue("error", "bind_invalid", f"{key} must contain a non-empty IPv4/hostname bind value without whitespace or ':'."))

    host = env.get("FTP_PUBLIC_HOST", "")
    if not host or host == "CHANGE-ME.example.com":
        issues.append(Issue("warning", "ftp_public_host", "FTP_PUBLIC_HOST still uses a placeholder or is empty."))

    tls = env.get("FTP_TLS", "NO").upper()
    if tls not in {"YES", "NO"}:
        issues.append(Issue("error", "ftp_tls", "FTP_TLS must be YES or NO."))

    pasv_min = _int_range(env, "FTP_PASV_MIN", 1024, 65535, issues)
    pasv_max = _int_range(env, "FTP_PASV_MAX", 1024, 65535, issues)
    if pasv_min is not None and pasv_max is not None and pasv_min > pasv_max:
        issues.append(Issue("error", "ftp_pasv_range", "FTP_PASV_MIN must be <= FTP_PASV_MAX."))

    for key, low, high in (
        ("CF_PROPAGATION_SECONDS", 0, 3600),
        ("CHECK_INTERVAL_SECONDS", 10, 86400),
        ("RETRY_INTERVAL_SECONDS", 10, 86400),
        ("FORCE_UPDATE_HOUR", 0, 23),
        ("CERTBOT_RETRY_SECONDS", 60, 86400),
    ):
        _int_range(env, key, low, high, issues)

    # FTP canonical/generated state consistency. SQLite is authoritative; users.d
    # is derived and must not contain stale virtual users.
    ftp_db = project / "ftp/users.sqlite"
    users_dir = project / "ftp/data/users.d"
    if ftp_db.is_file():
        try:
            import sqlite3
            con = sqlite3.connect(ftp_db)
            try:
                columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
                enabled_users = {
                    row[0] for row in con.execute(
                        "SELECT username FROM users WHERE enabled=1 ORDER BY username"
                    )
                }
                if "access_mode" in columns:
                    all_domain_users = {
                        row[0] for row in con.execute(
                            "SELECT username FROM users WHERE enabled=1 AND access_mode='all' ORDER BY username"
                        )
                    }
                    multi_domain_users = {
                        row[0] for row in con.execute(
                            "SELECT username FROM users WHERE enabled=1 AND access_mode='domains' "
                            "AND (SELECT COUNT(*) FROM user_domains d WHERE d.username=users.username) > 1 ORDER BY username"
                        )
                    } if "user_domains" in {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")} else set()
                else:
                    all_domain_users = {
                        row[0] for row in con.execute(
                            "SELECT username FROM users WHERE enabled=1 AND home_rel='' ORDER BY username"
                        )
                    }
                    multi_domain_users = set()
                    issues.append(Issue(
                        "warning",
                        "ftp_schema_legacy",
                        "FTP user database still uses the pre-2.5 access schema.",
                        "Run ./tools/ftp/meowftp.py list once to apply the additive schema migration.",
                    ))
            finally:
                con.close()
            if all_domain_users:
                issues.append(Issue(
                    "warning",
                    "ftp_all_domains",
                    "Enabled FTP users with access to all htdocs domains: " + ", ".join(sorted(all_domain_users)),
                    "Assign a home_rel if full multi-domain access is not intentional.",
                ))
            override = project / "docker-compose.override.yml"
            generated_override = False
            if override.is_file():
                try:
                    generated_override = override.read_text(encoding="utf-8", errors="replace").startswith(
                        "# MEOWHOME-GENERATED: ftp-domain-views-v1"
                    )
                except OSError:
                    pass
            if multi_domain_users and not generated_override:
                issues.append(Issue(
                    "warning",
                    "ftp_domain_override_missing",
                    "Multi-domain FTP assignments need the generated Compose override for isolated domain views.",
                    "Run: sudo ./tools/ftp/meowftp.py apply",
                ))
            elif generated_override and not multi_domain_users:
                issues.append(Issue(
                    "warning",
                    "ftp_domain_override_stale",
                    "Generated FTP domain-view Compose override is no longer required.",
                    "Run: sudo ./tools/ftp/meowftp.py apply",
                ))

            if users_dir.is_dir():
                generated = {p.name for p in users_dir.iterdir() if p.is_file()}
                if generated != enabled_users:
                    stale = sorted(generated - enabled_users)
                    missing = sorted(enabled_users - generated)
                    details = []
                    if stale:
                        details.append("stale=" + ",".join(stale))
                    if missing:
                        details.append("missing=" + ",".join(missing))
                    issues.append(Issue(
                        "warning",
                        "ftp_generated_state_drift",
                        "Generated FTP user configs differ from ftp/users.sqlite (" + "; ".join(details) + ").",
                        "Run: sudo ./tools/ftp/meowftp.py apply",
                    ))
        except (OSError, sqlite3.DatabaseError, sqlite3.OperationalError) as exc:
            issues.append(Issue("warning", "ftp_user_db", f"Could not inspect ftp/users.sqlite: {exc}"))

    if os.name == "posix":
        puid = env.get("PUID", "")
        pgid = env.get("PGID", "")
        if puid.isdigit() and pgid.isdigit():
            expected = (int(puid), int(pgid))
            htdocs = project / "htdocs"
            if htdocs.is_dir():
                drift = []
                try:
                    for child in htdocs.iterdir():
                        if not child.is_dir():
                            continue
                        st = child.stat()
                        if (st.st_uid, st.st_gid) != expected:
                            drift.append(f"{child.name}={st.st_uid}:{st.st_gid}")
                except OSError:
                    drift = []
                if drift:
                    issues.append(Issue(
                        "warning",
                        "webroot_owner_drift",
                        f"Top-level htdocs ownership differs from PUID:PGID {expected[0]}:{expected[1]}: " + ", ".join(sorted(drift)),
                        "Verify ACL/intent before changing ownership; do not blindly chown recursively.",
                    ))

                vhost_dir = project / "apache/vhosts"
                if vhost_dir.is_dir():
                    control_drift = []
                    try:
                        dir_st = vhost_dir.stat()
                        if (dir_st.st_uid, dir_st.st_gid) != expected or stat.S_IMODE(dir_st.st_mode) != 0o2775:
                            control_drift.append(
                                f"apache/vhosts={dir_st.st_uid}:{dir_st.st_gid}/{stat.S_IMODE(dir_st.st_mode):04o}"
                            )
                        for conf in sorted(vhost_dir.glob("*.conf")):
                            if not conf.is_file():
                                continue
                            st = conf.stat()
                            mode = stat.S_IMODE(st.st_mode)
                            if (st.st_uid, st.st_gid) != expected or mode != 0o664:
                                control_drift.append(f"{conf.name}={st.st_uid}:{st.st_gid}/{mode:04o}")
                    except OSError:
                        control_drift = []
                    if control_drift:
                        issues.append(Issue(
                            "warning",
                            "apache_control_plane_owner_drift",
                            f"Apache VHost control-plane metadata differs from PUID:PGID {expected[0]}:{expected[1]} and canonical modes: "
                            + ", ".join(control_drift),
                            "Run: sudo ./tools/meowhome.py repair-control-plane (or open VHosts in the MeowHome UI, which runs the same repair).",
                        ))

    aop_ca = project / "apache/snippets/cloudflare-origin-pull-ca.pem"
    vhost_dir = project / "apache/vhosts"
    if vhost_dir.is_dir():
        aop_referenced = False
        try:
            for conf in vhost_dir.glob("*.conf"):
                if not conf.is_file():
                    continue
                text = conf.read_text(encoding="utf-8", errors="replace")
                if "/etc/apache2/snippets/cloudflare-origin-pull-ca.pem" in text:
                    aop_referenced = True
                    break
        except OSError:
            pass
        if aop_referenced and (not aop_ca.is_file() or aop_ca.stat().st_size == 0):
            issues.append(Issue(
                "error",
                "cloudflare_aop_ca_missing",
                "A VHost references the managed Cloudflare Authenticated Origin Pull CA, but apache/snippets/cloudflare-origin-pull-ca.pem is missing or empty.",
                "Run the current init-meowhome.sh upgrade before enabling SSLVerifyClient require.",
            ))

    if "FTP_ENABLED" in env:
        issues.append(Issue("warning", "legacy_ftp_enabled", "FTP_ENABLED is no longer used; remove it from .env."))
    legacy_uid = env.get("FTP_HOST_UID", "")
    legacy_gid = env.get("FTP_HOST_GID", "")
    if legacy_uid and legacy_uid != env.get("PUID", ""):
        issues.append(Issue("warning", "legacy_uid_drift", "FTP_HOST_UID differs from PUID; PUID is authoritative."))
    if legacy_gid and legacy_gid != env.get("PGID", ""):
        issues.append(Issue("warning", "legacy_gid_drift", "FTP_HOST_GID differs from PGID; PGID is authoritative."))

    return issues


def runtime_status(project: pathlib.Path) -> tuple[dict[str, Any], list[Issue]]:
    issues: list[Issue] = []
    compose = compose_command(project)
    if not compose:
        return {"available": False, "services": []}, [Issue("error", "compose_missing", "Docker Compose v2/compatible command not found.")]

    proc = run(compose + ["ps", "--format", "json"], project, timeout=30)
    if proc.returncode != 0:
        return {
            "available": True,
            "command": compose,
            "error": (proc.stderr or proc.stdout).strip(),
            "services": [],
        }, [Issue("error", "compose_status", "docker compose ps failed.")]

    services: list[dict[str, Any]] = []
    raw = proc.stdout.strip()
    if raw:
        try:
            parsed = json.loads(raw)
            services = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in raw.splitlines():
                try:
                    services.append(json.loads(line))
                except json.JSONDecodeError:
                    issues.append(Issue("warning", "compose_status_parse", "Could not parse docker compose ps JSON output."))
                    services = []
                    break

    mount_probe = run(["docker", "exec", "meowhome_apache", "sh", "-lc", "test -d /var/www && test -d /etc/letsencrypt"], project, timeout=15)
    if mount_probe.returncode != 0:
        issues.append(Issue(
            "error",
            "wsl_bind_mount_unavailable",
            "Apache cannot see expected WSL-backed bind mounts (/var/www and/or /etc/letsencrypt).",
            "Check Docker Desktop WSL integration/mount state before changing Unix ownership or permissions; recreate the affected container after integration is healthy.",
        ))

    env = read_env(project / ".env")
    expected_networks = [x.strip() for x in env.get("MEOWHOME_WEB_EXTERNAL_NETWORKS", "").split(",") if x.strip()]
    if expected_networks:
        inspect = run(["docker", "inspect", "meowhome_apache", "--format", "{{json .NetworkSettings.Networks}}"], project, timeout=15)
        if inspect.returncode == 0:
            try:
                attached = set(json.loads(inspect.stdout.strip() or "{}").keys())
                missing = [n for n in expected_networks if n not in attached]
                if missing:
                    issues.append(Issue("error", "web_external_network_missing", "Apache is missing configured external Docker networks: " + ", ".join(missing), "Recreate web from the declared Compose model; do not use one-time docker network connect as the durable fix."))
            except json.JSONDecodeError:
                issues.append(Issue("warning", "network_status_parse", "Could not parse Apache Docker network membership."))
        else:
            issues.append(Issue("warning", "network_status", "Could not inspect Apache Docker network membership."))

    return {"available": True, "command": compose, "services": services}, issues


def doctor(project: pathlib.Path, include_runtime: bool = True) -> dict[str, Any]:
    issues = validate_config(project)
    runtime: dict[str, Any] = {"skipped": True}
    if include_runtime:
        runtime, runtime_issues = runtime_status(project)
        issues.extend(runtime_issues)

    errors = sum(i.severity == "error" for i in issues)
    warnings = sum(i.severity == "warning" for i in issues)
    return {
        "ok": errors == 0,
        "version": VERSION,
        "project": str(project),
        "summary": {"errors": errors, "warnings": warnings},
        "issues": [asdict(i) for i in issues],
        "runtime": runtime,
    }


def schema() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "meowhome_version": VERSION,
        "services": list(SERVICE_NAMES),
        "containers": CONTAINER_BY_SERVICE,
        "sources_of_truth": {
            "configuration": ".env",
            "orchestration": "docker-compose.yml",
            "ftp_users": "ftp/users.sqlite",
            "web_content": "htdocs/",
            "apache_vhosts": "apache/vhosts/",
            "certificates": "letsencrypt/",
            "runtime_state": "state/",
        },
        "generated": ["ftp/data/", "docker-compose.override.yml (only for multi-domain FTP views)"],
    }


def print_value(value: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
        return
    if isinstance(value, dict):
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(value)


def require_compose(project: pathlib.Path) -> list[str]:
    cmd = compose_command(project)
    if not cmd:
        raise SystemExit("Docker Compose v2/compatible command not found.")
    return cmd


def valid_service(name: str) -> str:
    if name not in SERVICE_NAMES:
        raise SystemExit(f"Unknown service {name!r}. Expected one of: {', '.join(SERVICE_NAMES)}")
    return name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MeowHome operational interface")
    parser.add_argument("--project", help="MeowHome runtime directory (default: MEOWHOME_PROJECT_DIR, installed runtime root, or ~/meowhome)")
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("schema", "status", "doctor"):
        p = sub.add_parser(name)
        p.add_argument("--json", action="store_true")
        if name == "doctor":
            p.add_argument("--no-runtime", action="store_true", help="Validate files/config without calling Docker")

    p = sub.add_parser("up")
    p.add_argument("--build", action="store_true")

    p = sub.add_parser("restart")
    p.add_argument("service")

    p = sub.add_parser("logs")
    p.add_argument("service")
    p.add_argument("--lines", type=int, default=200)
    p.add_argument("--follow", action="store_true")

    p = sub.add_parser("repair-control-plane")
    p.add_argument("--json", action="store_true")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = build_parser().parse_args(list(argv) if argv is not None else None)
    project = project_path(args.project)

    if args.command == "schema":
        print_value(schema(), args.json)
        return 0
    if args.command == "doctor":
        report = doctor(project, include_runtime=not args.no_runtime)
        print_value(report, args.json)
        return 0 if report["ok"] else 1
    if args.command == "status":
        runtime, issues = runtime_status(project)
        result = {"project": str(project), "runtime": runtime, "issues": [asdict(i) for i in issues]}
        print_value(result, args.json)
        return 0 if not any(i.severity == "error" for i in issues) else 1
    if args.command == "repair-control-plane":
        try:
            result = repair_control_plane_permissions(project)
        except (OSError, RuntimeError) as exc:
            print(f"repair-control-plane failed: {exc}", file=sys.stderr)
            return 1
        print_value(result, args.json)
        return 0

    compose = require_compose(project)
    if args.command == "up":
        cmd = compose + ["up", "-d"]
        if args.build:
            cmd.append("--build")
        proc = subprocess.run(cmd, cwd=project, check=False)
        return proc.returncode
    if args.command == "restart":
        service = valid_service(args.service)
        proc = subprocess.run(compose + ["restart", service], cwd=project, check=False)
        return proc.returncode
    if args.command == "logs":
        service = valid_service(args.service)
        lines = min(max(args.lines, 10), 10000)
        cmd = compose + ["logs", "--tail", str(lines)]
        if args.follow:
            cmd.append("-f")
        cmd.append(service)
        proc = subprocess.run(cmd, cwd=project, check=False)
        return proc.returncode

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
