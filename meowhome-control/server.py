#!/usr/bin/env python3
from __future__ import annotations

import base64
import hmac
import json
import os
import pathlib
import re
import subprocess
import stat
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PROJECT_DIR = pathlib.Path(os.getenv("MEOWHOME_PROJECT_DIR", "/meowhome"))
ADMIN_TOKEN_FILE = pathlib.Path(os.getenv("MEOWHOME_CONTROL_TOKEN_FILE", "/run/secrets/meowhome-control-token"))
CERTBOT_TOKEN_FILE = pathlib.Path(os.getenv("MEOWHOME_CERTBOT_CONTROL_TOKEN_FILE", "/run/secrets/meowhome-certbot-control-token"))
MAX_BODY = 12 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_TEXT_BYTES = 1024 * 1024
MAX_OUTPUT = 128 * 1024
ALLOWED_CONTAINERS = {
    "meowhome_apache", "meowhome_php", "meowhome_db", "meowhome_pma",
    "meowhome_certbot", "meowhome_dns_updater", "meowhome_ftp", "meowhome_control", "meowhome_ui",
}
RUNTIME_SERVICES = ["web", "php", "mariadb", "phpmyadmin", "certbot", "dns_updater", "ftp"]
FTP_COMMANDS = {"list", "add", "assign", "all", "passwd", "del", "enable", "disable", "apply"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9_$-]{1,64}$")
DATABASE_USER_RE = re.compile(r"^[A-Za-z0-9_$-]{1,32}$")
DATABASE_PASSWORD_RE = re.compile(r"^[A-Za-z0-9_-]{20,128}$")
SYSTEM_DATABASES = {"information_schema", "mysql", "performance_schema", "sys"}


def read_token(path: pathlib.Path) -> str:
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 32:
        raise RuntimeError(f"control token is missing or too short: {path}")
    return value


def authorized_role(supplied: str) -> str | None:
    try:
        admin = "Bearer " + read_token(ADMIN_TOKEN_FILE)
        certbot = "Bearer " + read_token(CERTBOT_TOKEN_FILE)
    except Exception:
        return None
    if hmac.compare_digest(supplied, admin):
        return "admin"
    if hmac.compare_digest(supplied, certbot):
        return "certbot"
    return None


def run(cmd: list[str], *, timeout: int = 120, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=PROJECT_DIR, text=True, capture_output=True, input=input_text, timeout=timeout, check=False)


def compose(args: list[str], timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return run(["docker", "compose", *args], timeout=timeout)


def clipped(text: str) -> str:
    data = text or ""
    if len(data) <= MAX_OUTPUT:
        return data
    return data[-MAX_OUTPUT:] + "\n[output truncated]"


def proc_result(proc: subprocess.CompletedProcess[str]) -> dict:
    return {"ok": proc.returncode == 0, "returncode": proc.returncode, "stdout": clipped(proc.stdout), "stderr": clipped(proc.stderr)}


def apache_reload() -> dict:
    test = run(["docker", "exec", "meowhome_apache", "apachectl", "-t"], timeout=30)
    if test.returncode != 0:
        return {"ok": False, "step": "apachectl -t", **proc_result(test)}
    reloadp = run(["docker", "exec", "meowhome_apache", "apachectl", "-k", "graceful"], timeout=30)
    if reloadp.returncode == 0:
        return {"ok": True, "step": "apachectl -k graceful", **proc_result(reloadp)}
    restart = run(["docker", "restart", "meowhome_apache"], timeout=60)
    merged = {
        "ok": restart.returncode == 0,
        "step": "docker restart fallback",
        "returncode": restart.returncode,
        "stdout": clipped("\n".join(x for x in (reloadp.stdout, restart.stdout) if x)),
        "stderr": clipped("\n".join(x for x in (reloadp.stderr, restart.stderr) if x)),
    }
    return merged



def project_env() -> dict[str, str]:
    values: dict[str, str] = {}
    path = PROJECT_DIR / ".env"
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            values[key.strip()] = value.strip()
    except OSError:
        pass
    return values


def mariadb_sql(sql: str, *, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    # The root password stays inside the MariaDB container environment. SQL is passed as $1,
    # not interpolated into the shell program.
    script = 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mariadb -uroot --batch --skip-column-names --raw -e "$1"'
    return run(["docker", "exec", "meowhome_db", "sh", "-lc", script, "meowhome-db", sql], timeout=timeout)


def database_list() -> tuple[list[str], subprocess.CompletedProcess[str]]:
    proc = mariadb_sql("SHOW DATABASES")
    rows = []
    if proc.returncode == 0:
        rows = sorted(x.strip() for x in proc.stdout.splitlines() if x.strip() and x.strip() not in SYSTEM_DATABASES)
    return rows, proc


def database_user_list() -> tuple[list[dict], subprocess.CompletedProcess[str]]:
    sql = (
        "SELECT GRANTEE,TABLE_SCHEMA,GROUP_CONCAT(PRIVILEGE_TYPE ORDER BY PRIVILEGE_TYPE SEPARATOR ',') "
        "FROM information_schema.SCHEMA_PRIVILEGES "
        "WHERE TABLE_SCHEMA NOT IN ('information_schema','mysql','performance_schema','sys') "
        "GROUP BY GRANTEE,TABLE_SCHEMA ORDER BY TABLE_SCHEMA,GRANTEE"
    )
    proc = mariadb_sql(sql)
    rows: list[dict] = []
    if proc.returncode == 0:
        for line in proc.stdout.splitlines():
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            match = re.fullmatch(r"'([^']+)'@'([^']+)'", parts[0].strip())
            if not match:
                continue
            user, host = match.groups()
            if user in {"root", "mysql", "mariadb.sys"}:
                continue
            rows.append({"user": user, "host": host, "database": parts[1], "privileges": parts[2].split(",") if parts[2] else []})
    return rows, proc


def validate_database_user(user: str, password: str = "") -> str:
    user = (user or "").strip()
    if not DATABASE_USER_RE.fullmatch(user) or user in {"root", "mysql", "mariadb.sys"}:
        raise ValueError("invalid database user")
    if password and not DATABASE_PASSWORD_RE.fullmatch(password):
        raise ValueError("invalid database password")
    return user


def _site_root(host: str) -> pathlib.Path:
    host = (host or "").strip().lower().rstrip(".")
    if not HOSTNAME_RE.fullmatch(host):
        raise ValueError("invalid host")
    htdocs = PROJECT_DIR / "htdocs"
    if htdocs.is_symlink():
        raise ValueError("webroot base must not be a symlink")
    root = htdocs / host
    if not root.exists():
        raise ValueError("site webroot does not exist")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("site webroot must be a real directory")
    return root


def safe_site_path(host: str, rel: str = "", *, must_exist: bool = True) -> tuple[pathlib.Path, pathlib.Path]:
    root = _site_root(host)
    raw = (rel or "").strip().replace("\\", "/")
    pure = pathlib.PurePosixPath(raw or ".")
    if pure.is_absolute() or ".." in pure.parts or "\x00" in raw:
        raise ValueError("invalid site path")
    candidate = root
    parts = [p for p in pure.parts if p not in {"", "."}]
    for index, part in enumerate(parts):
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("symlink paths are not supported by the file manager")
        if must_exist or index < len(parts) - 1:
            candidate.stat()
    return root, candidate


@contextmanager
def site_parent(host: str, rel: str, *, must_exist: bool = True):
    """Anchor operations to directory descriptors, including across path swaps.

    The pathname check provides useful errors; O_NOFOLLOW on every open is the
    actual boundary. Never resolve a symlink and then operate on its referent.
    """
    root, path = safe_site_path(host, rel, must_exist=must_exist)
    parts = path.relative_to(root).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors = []
    try:
        base_fd = os.open(PROJECT_DIR / "htdocs", flags)
        descriptors.append(base_fd)
        fd = os.open(root.name, flags, dir_fd=base_fd)
        descriptors.append(fd)
        for part in parts[:-1]:
            fd = os.open(part, flags, dir_fd=fd)
            descriptors.append(fd)
        yield root, path, fd, parts[-1] if parts else "."
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def set_content_metadata(fd: int, mode: int) -> None:
    env = project_env()
    uid, gid = int(env.get("PUID", "1000")), int(env.get("PGID", "1000"))
    current = os.fstat(fd)
    if (current.st_uid, current.st_gid) != (uid, gid):
        os.fchown(fd, uid, gid)
    os.fchmod(fd, mode)


def relative_site_path(root: pathlib.Path, path: pathlib.Path) -> str:
    rel = path.relative_to(root).as_posix()
    return "" if rel == "." else rel


def list_site_files(host: str, rel: str) -> dict:
    entries = []
    with site_parent(host, rel) as (root, path, parent_fd, name):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            with os.scandir(fd) as children:
                for entry in children:
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    kind = "symlink" if stat.S_ISLNK(st.st_mode) else "dir" if stat.S_ISDIR(st.st_mode) else "file" if stat.S_ISREG(st.st_mode) else "other"
                    entries.append({"name": entry.name, "path": relative_site_path(root, path / entry.name), "kind": kind, "size": st.st_size, "mtime": int(st.st_mtime)})
        finally:
            os.close(fd)
    entries.sort(key=lambda item: (item["kind"] != "dir", item["name"].lower()))
    current = relative_site_path(root, path)
    parent = relative_site_path(root, path.parent) if path != root else ""
    return {"ok": True, "host": host, "path": current, "parent": parent, "entries": entries}


def read_site_file(host: str, rel: str) -> dict:
    with site_parent(host, rel) as (root, path, parent_fd, name):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        with os.fdopen(fd, "rb") as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode):
                raise ValueError("path is not a regular file")
            data = stream.read(MAX_TEXT_BYTES + 1)
    if len(data) > MAX_TEXT_BYTES:
        raise ValueError("file is too large for text editor")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("file is not UTF-8 text") from exc
    return {"ok": True, "path": relative_site_path(root, path), "content": text, "size": len(data)}


def store_site_file(host: str, rel: str, data: bytes, *, overwrite: bool) -> dict:
    with site_parent(host, rel, must_exist=False) as (root, path, parent_fd, name):
        flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        if not overwrite:
            flags |= os.O_EXCL
        fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
        with os.fdopen(fd, "wb") as stream:
            st = os.fstat(stream.fileno())
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError("target must be a regular file without hard links")
            set_content_metadata(stream.fileno(), 0o664)
            stream.truncate(0)
            stream.write(data)
    return {"ok": True, "path": relative_site_path(root, path), "size": len(data)}


def write_site_file(host: str, rel: str, content: str) -> dict:
    if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_TEXT_BYTES:
        raise ValueError("text file is too large")
    return store_site_file(host, rel, content.encode("utf-8"), overwrite=True)


def upload_site_file(host: str, directory: str, name: str, data_b64: str, overwrite: bool) -> dict:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise ValueError("invalid file name")
    try:
        data = base64.b64decode(data_b64.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError("invalid upload data") from exc
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("file exceeds upload limit")
    rel = str(pathlib.PurePosixPath(directory or ".") / name)
    return store_site_file(host, rel, data, overwrite=overwrite)


def mkdir_site(host: str, directory: str, name: str) -> dict:
    if not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name:
        raise ValueError("invalid directory name")
    rel = str(pathlib.PurePosixPath(directory or ".") / name)
    with site_parent(host, rel, must_exist=False) as (root, path, parent_fd, leaf):
        os.mkdir(leaf, mode=0o700, dir_fd=parent_fd)
        fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            set_content_metadata(fd, 0o2775)
        finally:
            os.close(fd)
    return {"ok": True, "path": relative_site_path(root, path)}


def delete_site_path(host: str, rel: str) -> dict:
    with site_parent(host, rel) as (root, path, parent_fd, name):
        if path == root:
            raise ValueError("webroot cannot be deleted")
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            os.rmdir(name, dir_fd=parent_fd)
        elif stat.S_ISREG(st.st_mode):
            os.unlink(name, dir_fd=parent_fd)
        else:
            raise ValueError("unsupported path type (symlinks cannot be deleted)")
    return {"ok": True, "path": rel}


def ensure_webroot(host: str, create_index: bool) -> dict:
    if not HOSTNAME_RE.fullmatch(host or ""):
        raise ValueError("invalid host")
    base = PROJECT_DIR / "htdocs"
    path = base / host
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    base_fd = os.open(base, flags)
    created = False
    try:
        try:
            os.mkdir(host, mode=0o700, dir_fd=base_fd)
            created = True
        except FileExistsError:
            pass
        fd = os.open(host, flags, dir_fd=base_fd)
        try:
            if created:
                set_content_metadata(fd, 0o2775)
            if create_index:
                try:
                    index_fd = os.open("index.html", os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                except FileExistsError:
                    pass  # Existing content, including links, is never overwritten.
                else:
                    with os.fdopen(index_fd, "w", encoding="utf-8") as stream:
                        set_content_metadata(stream.fileno(), 0o664)
                        stream.write(f"<!doctype html><meta charset=\"utf-8\"><title>{host}</title><h1>{host}</h1><p>Website bereitgestellt mit MeowHome.</p>\n")
        finally:
            os.close(fd)
    finally:
        os.close(base_fd)
    return {"ok": True, "path": str(path), "created": created}

def validate_ftp_args(args: object, input_text: object) -> tuple[list[str], str | None]:
    if not isinstance(args, list) or not args or not all(isinstance(x, str) for x in args):
        raise ValueError("invalid ftp args")
    cmd = args[0]
    if cmd not in FTP_COMMANDS or len(args) > 64:
        raise ValueError("ftp command is not allowed")
    if cmd in {"add", "passwd", "del", "enable", "disable", "assign", "all"}:
        if len(args) < 2 or not USERNAME_RE.fullmatch(args[1]):
            raise ValueError("invalid ftp username")
    if cmd == "assign":
        for domain in args[2:]:
            if not DOMAIN_RE.fullmatch(domain):
                raise ValueError("invalid ftp domain")
    stdin = None
    if input_text is not None:
        if cmd not in {"add", "passwd"} or not isinstance(input_text, str) or len(input_text) > 1024:
            raise ValueError("stdin is not allowed for this ftp command")
        stdin = input_text
    return args, stdin


class Handler(BaseHTTPRequestHandler):
    server_version = "MeowHomeControl/1.0"

    def log_message(self, fmt: str, *args) -> None:
        # Keep the adapter quiet; actionable failures are returned to the caller.
        return

    def _json(self, status: int, payload: dict) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _role(self) -> str | None:
        return authorized_role(self.headers.get("Authorization", ""))

    def _body(self) -> dict:
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            raise ValueError("invalid content length")
        if length < 0 or length > MAX_BODY:
            raise ValueError("request too large")
        raw = self.rfile.read(length) if length else b"{}"
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON object required")
        return value

    def _guard(self, *, admin_only: bool = False, allow_certbot_reload: bool = False) -> str | None:
        role = self._role()
        if role is None:
            self._json(401, {"ok": False, "error": "unauthorized"})
            return None
        if admin_only and role != "admin":
            self._json(403, {"ok": False, "error": "forbidden"})
            return None
        if not admin_only and not allow_certbot_reload and role != "admin":
            self._json(403, {"ok": False, "error": "forbidden"})
            return None
        return role

    def do_GET(self) -> None:
        if not self._guard(admin_only=True):
            return
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        try:
            if parts.path == "/v1/ping":
                proc = run(["docker", "info", "--format", "{{json .}}"], timeout=15)
                if proc.returncode != 0:
                    self._json(503, {"ok": False, **proc_result(proc)})
                    return
                info = json.loads(proc.stdout)
                self._json(200, {"ok": True, "name": info.get("Name", ""), "server_version": info.get("ServerVersion", "")})
                return
            if parts.path == "/v1/containers":
                proc = run(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=20)
                rows = []
                if proc.returncode == 0:
                    for line in proc.stdout.splitlines():
                        if not line.strip():
                            continue
                        row = json.loads(line)
                        if row.get("Names") in ALLOWED_CONTAINERS:
                            rows.append({
                                "name": row.get("Names", ""),
                                "status": row.get("State", ""),
                                "health": row.get("Status", ""),
                                "image": row.get("Image", ""),
                                "started_at": "",
                                "restart_count": "",
                            })
                self._json(200 if proc.returncode == 0 else 503, {"ok": proc.returncode == 0, "containers": sorted(rows, key=lambda x: x["name"]), **({} if proc.returncode == 0 else proc_result(proc))})
                return
            if parts.path == "/v1/doctor":
                proc = run(["python3", str(PROJECT_DIR / "tools/meowhome.py"), "--project", str(PROJECT_DIR), "doctor", "--json"], timeout=30)
                if proc.returncode not in {0, 1}:
                    self._json(503, {"ok": False, **proc_result(proc)}); return
                try:
                    report = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    self._json(503, {"ok": False, "error": "doctor returned invalid JSON"}); return
                self._json(200, {"ok": True, "report": report}); return
            if parts.path == "/v1/databases":
                rows, proc = database_list()
                self._json(200 if proc.returncode == 0 else 503, {"ok": proc.returncode == 0, "databases": rows, **({} if proc.returncode == 0 else proc_result(proc))}); return
            if parts.path == "/v1/database-users":
                rows, proc = database_user_list()
                self._json(200 if proc.returncode == 0 else 503, {"ok": proc.returncode == 0, "users": rows, **({} if proc.returncode == 0 else proc_result(proc))}); return
            if parts.path == "/v1/files":
                host = (query.get("host") or [""])[0]
                rel = (query.get("path") or [""])[0]
                self._json(200, list_site_files(host, rel)); return
            if parts.path == "/v1/file-read":
                host = (query.get("host") or [""])[0]
                rel = (query.get("path") or [""])[0]
                self._json(200, read_site_file(host, rel)); return
            if parts.path == "/v1/logs":
                name = (query.get("name") or [""])[0]
                if name not in ALLOWED_CONTAINERS:
                    raise ValueError("container is not allowed")
                try:
                    lines = int((query.get("lines") or ["200"])[0])
                except ValueError:
                    lines = 200
                lines = min(max(lines, 10), 5000)
                proc = run(["docker", "logs", "--tail", str(lines), name], timeout=30)
                self._json(200 if proc.returncode == 0 else 400, {"ok": proc.returncode == 0, "text": clipped((proc.stdout or "") + (proc.stderr or ""))})
                return
            self._json(404, {"ok": False, "error": "not found"})
        except (ValueError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            self._json(400, {"ok": False, "error": str(exc)})

    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        if parts.path == "/v1/apache-reload":
            if not self._guard(allow_certbot_reload=True):
                return
        elif not self._guard(admin_only=True):
            return
        try:
            body = self._body()
            if parts.path == "/v1/container-action":
                name = str(body.get("name", ""))
                action = str(body.get("action", "")).lower()
                if name in {"meowhome_ui", "meowhome_control"} or name not in ALLOWED_CONTAINERS or action not in {"start", "stop", "restart"}:
                    raise ValueError("container action is not allowed")
                proc = run(["docker", action, name], timeout=90)
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/compose-action":
                action = str(body.get("action", "")).lower()
                commands = {
                    "up": ["up", "-d", *RUNTIME_SERVICES],
                    "pull": ["pull"],
                    "build": ["build", "--pull"],
                    "recreate": ["up", "-d", "--force-recreate", *RUNTIME_SERVICES],
                }
                if action not in commands:
                    raise ValueError("compose action is not allowed")
                proc = compose(commands[action], timeout=900)
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/apache-reload":
                result = apache_reload(); self._json(200 if result.get("ok") else 400, result); return
            if parts.path == "/v1/backup-create":
                cmd = [str(PROJECT_DIR / "tools/backup/backup.sh")]
                if bool(body.get("with_htdocs")):
                    cmd.append("--with-htdocs")
                proc = run(cmd, timeout=3600)
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/ftp":
                args, stdin = validate_ftp_args(body.get("args"), body.get("input"))
                proc = run(["python3", str(PROJECT_DIR / "tools/ftp/meowftp.py"), *args], timeout=600, input_text=stdin)
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/certbot-renew":
                proc = run(["docker", "exec", "meowhome_certbot", "certbot", "renew", "--non-interactive"], timeout=240)
                payload = proc_result(proc)
                if proc.returncode == 0:
                    payload["apache"] = apache_reload()
                    payload["ok"] = bool(payload["apache"].get("ok"))
                self._json(200 if payload.get("ok") else 400, payload); return
            if parts.path == "/v1/dns-run":
                proc = run(["docker", "restart", "meowhome_dns_updater"], timeout=60)
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/webroot-ensure":
                host = str(body.get("host", "")).strip().lower().rstrip(".")
                result = ensure_webroot(host, bool(body.get("create_index")))
                self._json(200, result); return
            if parts.path == "/v1/database-create":
                name = str(body.get("name", "")).strip()
                if not DATABASE_NAME_RE.fullmatch(name) or name in SYSTEM_DATABASES:
                    raise ValueError("invalid database name")
                proc = mariadb_sql(f"CREATE DATABASE `{name}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/database-drop":
                name = str(body.get("name", "")).strip()
                if not DATABASE_NAME_RE.fullmatch(name) or name in SYSTEM_DATABASES:
                    raise ValueError("invalid database name")
                proc = mariadb_sql(f"DROP DATABASE `{name}`")
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/database-user-create":
                database = str(body.get("database", "")).strip()
                user = validate_database_user(str(body.get("user", "")), str(body.get("password", "")))
                password = str(body.get("password", ""))
                databases, probe = database_list()
                if probe.returncode != 0 or database not in databases:
                    raise ValueError("database does not exist")
                sql = f"CREATE USER '{user}'@'%' IDENTIFIED BY '{password}'; GRANT ALL PRIVILEGES ON `{database}`.* TO '{user}'@'%';"
                proc = mariadb_sql(sql)
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/database-user-drop":
                user = validate_database_user(str(body.get("user", "")))
                proc = mariadb_sql(f"DROP USER '{user}'@'%'")
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            if parts.path == "/v1/file-write":
                self._json(200, write_site_file(str(body.get("host", "")), str(body.get("path", "")), str(body.get("content", "")))); return
            if parts.path == "/v1/file-upload":
                self._json(200, upload_site_file(str(body.get("host", "")), str(body.get("directory", "")), str(body.get("name", "")), str(body.get("data", "")), bool(body.get("overwrite")))); return
            if parts.path == "/v1/file-mkdir":
                self._json(200, mkdir_site(str(body.get("host", "")), str(body.get("directory", "")), str(body.get("name", "")))); return
            if parts.path == "/v1/file-delete":
                self._json(200, delete_site_path(str(body.get("host", "")), str(body.get("path", "")))); return
            if parts.path == "/v1/repair-control-plane":
                proc = run(["python3", str(PROJECT_DIR / "tools/meowhome.py"), "--project", str(PROJECT_DIR), "repair-control-plane", "--json"], timeout=30)
                self._json(200 if proc.returncode == 0 else 400, proc_result(proc)); return
            self._json(404, {"ok": False, "error": "not found"})
        except (ValueError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
            self._json(400, {"ok": False, "error": str(exc)})


if __name__ == "__main__":
    for required in (ADMIN_TOKEN_FILE, CERTBOT_TOKEN_FILE):
        if not required.is_file():
            raise SystemExit(f"missing control token: {required}")
    ThreadingHTTPServer(("0.0.0.0", 8765), Handler).serve_forever()
