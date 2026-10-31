import base64
import os
import time
import pathlib
import re
import subprocess
import html as html_lib
import json
import secrets
import ssl
import hashlib
import fnmatch
import hmac
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from fastapi import FastAPI, Request, Depends, HTTPException, Form, File, UploadFile
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from .domain_tls_health import certificate_details, certificate_covers_hostname, choose_covered_certificate, enrich_sites, site_tls_health
from .activity import recent_activity
from .vhost_alias_editor import UnsupportedVhost, plan_alias_edit


APP_TITLE = "MeowHome Control Panel"

PROJECT_DIR = os.getenv("MEOWHOME_PROJECT_DIR", "/meowhome")
VHOST_DIR = os.path.join(PROJECT_DIR, "apache", "vhosts")
BACKUPS_DIR = os.path.join(PROJECT_DIR, "backups")
BACKUP_TOOL = os.path.join(PROJECT_DIR, "tools", "backup", "backup.sh")
ENV_PATH = os.path.join(PROJECT_DIR, ".env")
CONTROL_URL = os.getenv("MEOWHOME_CONTROL_URL", "http://control:8765").rstrip("/")
CONTROL_TOKEN_FILE = os.getenv("MEOWHOME_CONTROL_TOKEN_FILE", "/run/secrets/meowhome-control-token")
AUDIT_LOG = os.path.join(PROJECT_DIR, "state", "control-audit.jsonl")
CSRF_COOKIE = "meowhome_csrf"
CSRF_SECRET = secrets.token_bytes(32)

UI_USER = os.getenv("MEOWHOME_UI_USER", "admin")
UI_PASS = os.getenv("MEOWHOME_UI_PASS", "admin")

SETUP_KEYS = [
    "PUID",
    "PGID",
    "HTTP_BIND",
    "HTTP_PORT",
    "HTTPS_BIND",
    "HTTPS_PORT",
    "PHPMYADMIN_BIND",
    "PHPMYADMIN_PORT",
    "FTP_BIND",
    "FTP_PORT",
    "FTP_PASV_MIN",
    "FTP_PASV_MAX",
    "FTP_CERT_DOMAIN",
    "DOMAINS",
    "LE_EMAIL",
    "CERTBOT_ENABLED",
    "DNS_UPDATER_ENABLED",
    "ACME_CHALLENGE",
    "DNS_PROVIDER",
    "CLOUDFLARE_API_TOKEN",
    "FTP_PUBLIC_HOST",
    "FTP_TLS",
    "DB_ROOT_PASSWORD",
    "DB_PASSWORD",
    "DB_USER",
    "DB_NAME",
    "PROXIED_DEFAULT",
    "MEOWHOME_UI_USER",
    "MEOWHOME_UI_PASS",
]

SECRET_KEYS = {
    "CLOUDFLARE_API_TOKEN",
    "DB_ROOT_PASSWORD",
    "DB_PASSWORD",
    "MEOWHOME_UI_PASS",
}

BOOL_KEYS = {
    "CERTBOT_ENABLED",
    "DNS_UPDATER_ENABLED",
    "FTP_TLS",
    "PROXIED_DEFAULT",
}

ALLOWED_ACME = {"dns", "http"}
FTP_USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
ALLOWED_CONTAINERS = {
    "meowhome_apache",
    "meowhome_php",
    "meowhome_db",
    "meowhome_pma",
    "meowhome_certbot",
    "meowhome_dns_updater",
    "meowhome_ftp",
    "meowhome_ui",
}
RUNTIME_SERVICES = ["web", "php", "mariadb", "phpmyadmin", "certbot", "dns_updater", "ftp"]
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
DATABASE_NAME_RE = re.compile(r"^[A-Za-z0-9_$-]{1,64}$")

security = HTTPBasic()
templates = Jinja2Templates(directory=str(pathlib.Path(__file__).parent / "templates"))

app = FastAPI(title=APP_TITLE)


def _csrf_cookie_value(request: Request) -> str:
    value = getattr(request.state, "csrf_cookie", "")
    if value:
        return value
    supplied = request.cookies.get(CSRF_COOKIE, "")
    if re.fullmatch(r"[A-Za-z0-9_-]{32,128}", supplied or ""):
        value = supplied
    else:
        value = secrets.token_urlsafe(32)
        request.state.csrf_set_cookie = True
    request.state.csrf_cookie = value
    return value


def csrf_token_for_request(request: Request) -> str:
    value = _csrf_cookie_value(request)
    return hmac.new(CSRF_SECRET, value.encode("utf-8"), hashlib.sha256).hexdigest()


templates.env.globals["csrf_token"] = csrf_token_for_request


@app.middleware("http")
async def security_headers_and_csrf_cookie(request: Request, call_next):
    _csrf_cookie_value(request)
    response = await call_next(request)
    if getattr(request.state, "csrf_set_cookie", False):
        response.set_cookie(CSRF_COOKIE, request.state.csrf_cookie, httponly=True, samesite="strict", secure=request.url.scheme == "https", path="/")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


def _same_origin_request(request: Request) -> bool:
    host = (request.headers.get("host") or "").lower()
    scheme = (request.url.scheme or "").lower()
    if not host or scheme not in {"http", "https"}:
        return False
    for header in ("origin", "referer"):
        raw = request.headers.get(header)
        if not raw:
            continue
        try:
            parsed = urllib.parse.urlsplit(raw)
        except ValueError:
            return False
        return parsed.scheme.lower() == scheme and parsed.netloc.lower() == host
    return False


def require_csrf(request: Request, csrf_token: str = Form(...)) -> None:
    if not _same_origin_request(request):
        raise HTTPException(status_code=403, detail="CSRF origin check failed")
    expected = csrf_token_for_request(request)
    if not secrets.compare_digest(csrf_token or "", expected):
        raise HTTPException(status_code=403, detail="CSRF token invalid")


def require_auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    ok_user = secrets.compare_digest(creds.username, UI_USER)
    ok_pass = secrets.compare_digest(creds.password, UI_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return creds.username


def _control_token() -> str:
    try:
        value = pathlib.Path(CONTROL_TOKEN_FILE).read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Control token unavailable: {exc}") from exc
    if len(value) < 32:
        raise HTTPException(status_code=503, detail="Control token is invalid")
    return value


def control_request(method: str, path: str, payload: Optional[Dict[str, Any]] = None, timeout: int = 120) -> Dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(CONTROL_URL + path, data=data, method=method, headers={"Authorization": "Bearer " + _control_token(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            result = json.loads(body)
        except json.JSONDecodeError:
            result = {"ok": False, "error": body or str(exc)}
    except (OSError, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=503, detail=f"MeowHome control adapter unavailable: {exc}") from exc
    if not isinstance(result, dict):
        raise HTTPException(status_code=502, detail="Invalid control adapter response")
    return result


def control_proc(path: str, payload: Optional[Dict[str, Any]] = None, timeout: int = 120) -> subprocess.CompletedProcess:
    result = control_request("POST", path, payload or {}, timeout=timeout)
    rc = int(result.get("returncode", 0 if result.get("ok") else 1))
    return subprocess.CompletedProcess(["control", path], rc, str(result.get("stdout") or ""), str(result.get("stderr") or result.get("error") or ""))


def audit_event(actor: str, action: str, target: str, success: bool, detail: str = "") -> None:
    event = {"ts": datetime.now(timezone.utc).isoformat(), "actor": (actor or "unknown")[:128], "action": (action or "unknown")[:128], "target": (target or "")[:512], "success": bool(success)}
    # Diagnostic output can contain credentials. Persist only the audit contract;
    # keep the optional argument for callers without storing its contents.
    path = pathlib.Path(AUDIT_LOG)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        set_host_file_metadata(path, 0o600)
    except OSError:
        pass

def render_text_page(title: str, text: str, back_url: str = "/", status_code: int = 200) -> HTMLResponse:
    title_html = html_lib.escape(title)
    text_html = html_lib.escape(text or "")
    back_html = html_lib.escape(back_url, quote=True)

    page = f"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title_html}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #94a3b8;
      --link: #7cc7ff;
      --link-hover: #b8e3ff;
      --pre-bg: #0b1118;
      --pre-border: #334155;
      --pre-text: #dbe5ef;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 20px;
      font-family: Arial, sans-serif;
      line-height: 1.45;
      background: var(--bg);
      color: var(--text);
    }}
    .card {{
      max-width: 960px;
      border: 1px solid var(--border);
      background: var(--surface);
      border-radius: 8px;
      padding: 14px;
    }}
    pre {{
      margin: 0;
      background: var(--pre-bg);
      color: var(--pre-text);
      border: 1px solid var(--pre-border);
      border-radius: 8px;
      padding: 12px;
      overflow: auto;
      white-space: pre-wrap;
    }}
    a {{
      color: var(--link);
      text-decoration: none;
    }}
    a:hover {{
      color: var(--link-hover);
      text-decoration: underline;
    }}
    .muted {{
      color: var(--muted);
    }}
  </style>
</head>
<body>
  <div class="card">
    <h2>{title_html}</h2>
    <pre>{text_html}</pre>
    <p class="muted"><a href="{back_html}">Back</a></p>
  </div>
</body>
</html>"""
    return HTMLResponse(page, status_code=status_code)


def html_autorefresh(
    url: str,
    seconds: int = 2,
    title: str = "OK",
    body: str = "Fertig. Aktualisiere Ansicht..."
) -> HTMLResponse:
    ts = int(time.time())
    target = f"{url}{'&' if '?' in url else '?'}ts={ts}"
    title_html = html_lib.escape(title)
    body_html = html_lib.escape(body)
    target_html = html_lib.escape(target, quote=True)
    target_js = target.replace("\\", "\\\\").replace("\"", "\\\"")

    html = f"""<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="cache-control" content="no-store" />
  <meta http-equiv="pragma" content="no-cache" />
  <meta http-equiv="expires" content="0" />
  <title>{title_html}</title>
  <style>
    :root {{
      color-scheme: dark;
      --bg: #0d1117;
      --surface: #161b22;
      --border: #30363d;
      --text: #e6edf3;
      --muted: #94a3b8;
      --link: #7cc7ff;
      --link-hover: #b8e3ff;
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 20px;
      font-family: Arial, sans-serif;
      line-height: 1.45;
      background: var(--bg);
      color: var(--text);
    }}
    .card {{
      max-width: 760px;
      border: 1px solid var(--border);
      background: var(--surface);
      border-radius: 8px;
      padding: 14px;
    }}
    a {{
      color: var(--link);
      text-decoration: none;
    }}
    a:hover {{
      color: var(--link-hover);
      text-decoration: underline;
    }}
    .muted {{
      color: var(--muted);
    }}
  </style>
</head>
<body>
  <div class="card">
    <h2>{title_html}</h2>
    <p>{body_html}</p>
    <p class="muted">Weiterleitung in {seconds} Sekunden...</p>
    <p><a href="{target_html}">Wenn nichts passiert: hier klicken</a></p>
  </div>
  <script>
    setTimeout(function() {{
      window.location.replace("{target_js}");
    }}, {seconds} * 1000);
  </script>
</body>
</html>"""

    resp = HTMLResponse(html)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


def host_uid_gid() -> Optional[Tuple[int, int]]:
    try:
        values: Dict[str, str] = {}
        for raw in pathlib.Path(ENV_PATH).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() in {"PUID", "PGID"}:
                values[key.strip()] = value.strip().strip("\"'")
        uid = int(values.get("PUID", ""))
        gid = int(values.get("PGID", ""))
        return uid, gid
    except (OSError, ValueError):
        return None


def set_host_file_metadata(path: pathlib.Path, mode: int) -> None:
    os.chmod(path, mode)
    if os.geteuid() == 0:
        ids = host_uid_gid()
        if ids is not None:
            os.chown(path, ids[0], ids[1])


def safe_write_file(path: str, content: str, mode: int = 0o664) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    set_host_file_metadata(p, mode)


def backup_file(path: str) -> Optional[str]:
    p = pathlib.Path(path)
    if not p.exists():
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = p.with_suffix(p.suffix + f".bak.{ts}")
    backup.write_bytes(p.read_bytes())
    set_host_file_metadata(backup, p.stat().st_mode & 0o777)
    return str(backup)


def ensure_vhost_control_plane_metadata() -> None:
    res = control_proc("/v1/repair-control-plane", timeout=30)
    if res.returncode != 0:
        detail = (res.stderr or res.stdout or "repair-control-plane failed").strip()
        raise HTTPException(status_code=500, detail=detail)

def validate_vhost_managed_dependencies(content: str) -> Optional[str]:
    for match in re.finditer(r"(?mi)^\s*SSLCACertificateFile\s+[\"']?([^\"'\s]+)", content or ""):
        apache_path = match.group(1)
        host_path: Optional[pathlib.Path] = None
        if apache_path.startswith("/etc/apache2/snippets/"):
            host_path = pathlib.Path(PROJECT_DIR) / "apache/snippets" / apache_path.rsplit("/", 1)[-1]
        elif apache_path.startswith("/etc/letsencrypt/"):
            host_path = pathlib.Path(PROJECT_DIR) / "letsencrypt" / apache_path[len("/etc/letsencrypt/"):]
        if host_path is not None and (not host_path.is_file() or host_path.stat().st_size == 0):
            return f"Managed Apache dependency is missing or empty: {apache_path} (host: {host_path})"
    return None


def apache_test_and_reload() -> Dict[str, Any]:
    return control_request("POST", "/v1/apache-reload", {}, timeout=90)

def list_backups() -> List[Dict[str, Any]]:
    p = pathlib.Path(BACKUPS_DIR)
    res: List[Dict[str, Any]] = []
    if not p.exists():
        return res
    for f in p.glob("meowhome-backup-*.tar.gz"):
        try:
            st = f.stat()
            res.append({
                "name": f.name,
                "size": st.st_size,
                "mtime": st.st_mtime,
            })
        except Exception:
            continue
    res.sort(key=lambda x: x["mtime"], reverse=True)
    return res


def ensure_backup_tool() -> None:
    result = control_request("GET", "/v1/ping", timeout=15)
    if not result.get("ok"):
        raise HTTPException(status_code=503, detail="MeowHome control adapter is not ready")

def parse_backup_output_for_path(text: str) -> Optional[str]:
    # Script schreibt: [backup] Fertig: /path/to/file.tar.gz
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[backup] Fertig:"):
            maybe = line.split(":", 1)[1].strip()
            if maybe:
                return maybe
    return None


def sanitize_backup_name(name: str) -> str:
    # nur Dateiname, keine Pfade
    name = name.strip()
    if "/" in name or "\\" in name:
        raise HTTPException(status_code=400, detail="Ungueltiger Dateiname")
    if not name.startswith("meowhome-backup-") or not name.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail="Ungueltiger Backup-Name")
    return name


def env_read_raw() -> List[str]:
    if not os.path.exists(ENV_PATH):
        return []
    return pathlib.Path(ENV_PATH).read_text(encoding="utf-8", errors="replace").splitlines(True)


def env_parse(lines: List[str]) -> Dict[str, str]:
    data: Dict[str, str] = {}
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        data[k.strip()] = v.strip()
    return data


def env_set_values(lines: List[str], updates: Dict[str, str]) -> List[str]:
    # Preserve comments/order while collapsing duplicate assignments for keys
    # managed by this form. One key -> one effective source of truth.
    existing_keys = set()
    out: List[str] = []

    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            k = line.split("=", 1)[0].strip()
            if k in updates:
                if k not in existing_keys:
                    out.append(f"{k}={updates[k]}\n")
                    existing_keys.add(k)
                continue
        out.append(line)

    # fehlende Keys anhaengen
    missing = [k for k in updates.keys() if k not in existing_keys]
    if missing:
        if out and not out[-1].endswith("\n"):
            out[-1] = out[-1] + "\n"
        out.append("\n# Added by MeowHome UI Setup\n")
        for k in missing:
            out.append(f"{k}={updates[k]}\n")

    return out


def env_backup_file() -> Optional[str]:
    bak = backup_file(ENV_PATH)
    if bak:
        set_host_file_metadata(pathlib.Path(bak), 0o600)
    return bak


def normalize_bool(val: str) -> str:
    v = (val or "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return "true"
    return "false"


def validate_domains(domains: str) -> str:
    # Komma-separiert, Leerwerte entfernen, basic sanity (keine spaces/slashes).
    raw = [d.strip() for d in (domains or "").split(",")]
    items = [d for d in raw if d]
    if not items:
        raise HTTPException(status_code=400, detail="DOMAINS darf nicht leer sein")
    for d in items:
        if re.search(r"[\s/]", d):
            raise HTTPException(status_code=400, detail=f"Ungueltige Domain in DOMAINS: {d}")
    return ",".join(items)


def validate_email(email: str) -> str:
    e = (email or "").strip()
    if not e or "@" not in e:
        raise HTTPException(status_code=400, detail="LE_EMAIL ungueltig")
    return e



def validate_port(value: str, field: str) -> str:
    raw = (value or "").strip()
    try:
        port = int(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field} muss eine Portnummer sein")
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail=f"{field} muss zwischen 1 und 65535 liegen")
    return str(port)

def validate_bind(value: str, field: str) -> str:
    raw = (value or "").strip()
    if not raw or any(ch.isspace() for ch in raw) or ":" in raw:
        raise HTTPException(status_code=400, detail=f"{field} enthaelt eine ungueltige Bind-Adresse")
    return raw

def resolve_vhost_file(file_name: str) -> pathlib.Path:
    file_name = (file_name or "").strip()
    if not file_name.endswith(".conf"):
        raise HTTPException(status_code=400, detail="Nur .conf erlaubt")
    if "/" in file_name or "\\" in file_name:
        raise HTTPException(status_code=403, detail="Ungueltiger Dateipfad")

    vhost_base = pathlib.Path(VHOST_DIR).resolve()
    full_path = (vhost_base / file_name).resolve()
    try:
        full_path.relative_to(vhost_base)
    except ValueError:
        raise HTTPException(status_code=403, detail="Zugriff verweigert")
    return full_path


def cert_status_for_domains(domains_csv: str) -> List[Dict[str, Any]]:
    # Checkt letsencrypt/live/<domain>/{fullchain.pem,privkey.pem}
    res: List[Dict[str, Any]] = []
    lets = pathlib.Path(PROJECT_DIR) / "letsencrypt" / "live"
    domains = [d.strip() for d in (domains_csv or "").split(",") if d.strip()]
    for d in domains:
        live = lets / d
        fullchain = live / "fullchain.pem"
        privkey = live / "privkey.pem"
        res.append({
            "domain": d,
            "exists": fullchain.exists() and privkey.exists(),
            "fullchain": str(fullchain),
            "privkey": str(privkey),
        })
    return res



def validate_hostname(value: str, field: str = "Domain") -> str:
    host = (value or "").strip().lower().rstrip(".")
    if not HOSTNAME_RE.fullmatch(host):
        raise HTTPException(status_code=400, detail=f"{field} ist ungueltig: {value}")
    return host


def validate_aliases(value: str) -> List[str]:
    aliases: List[str] = []
    for raw in re.split(r"[,\s]+", value or ""):
        if not raw.strip():
            continue
        host = validate_hostname(raw, "Alias")
        if host not in aliases:
            aliases.append(host)
    return aliases


def parse_vhost_record(path: pathlib.Path) -> Dict[str, Any]:
    content = path.read_text(encoding="utf-8", errors="replace")
    names = re.findall(r"^\s*ServerName\s+([^\s#]+)", content, re.M)
    alias_lines = re.findall(r"^\s*ServerAlias\s+(.+)$", content, re.M)
    aliases: List[str] = []
    for line in alias_lines:
        aliases.extend(x for x in line.split() if not x.startswith("#"))
    document = re.search(r"^\s*DocumentRoot\s+([^\s#]+)", content, re.M)
    proxy = re.search(r'^\s*ProxyPass\s+"?/"?\s+"?(https?://[^"\s]+)', content, re.M | re.I)
    cert = re.search(r"/etc/letsencrypt/live/([^/]+)/fullchain\.pem", content)
    host = names[0] if names else ""
    if proxy:
        kind = "proxy"
    elif document:
        kind = "website"
    else:
        kind = "custom"
    return {
        "file": path.name,
        "host": host,
        "aliases": sorted(set(aliases)),
        "kind": kind,
        "document_root": document.group(1) if document else "",
        "proxy_target": proxy.group(1) if proxy else "",
        "tls": "<VirtualHost *:443>" in content,
        "cert_domain": cert.group(1) if cert else "",
        "php": "php-fpm.conf" in content,
        "raw": content,
    }


def site_inventory() -> List[Dict[str, Any]]:
    base = pathlib.Path(VHOST_DIR)
    if not base.exists():
        return []
    sites: List[Dict[str, Any]] = []
    for path in sorted(base.glob("*.conf")):
        try:
            record = parse_vhost_record(path)
        except OSError:
            continue
        if not record.get("host"):
            continue
        sites.append(record)
    return sites


def vhost_revision(path: pathlib.Path) -> str:
    original = pathlib.Path(VHOST_DIR) / path.name
    if original.is_symlink() or path.is_symlink():
        raise HTTPException(status_code=409, detail="Symbolische Links werden nicht verändert")
    if not path.exists(): return "new"
    if not path.is_file():
        raise HTTPException(status_code=409, detail="Keine reguläre VHost-Datei")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def vhost_check_names(content: str, current_file: str = "") -> None:
    if not content or "\x00" in content or len(content.encode("utf-8")) > 131072:
        raise HTTPException(status_code=400, detail="VHost darf maximal 128 KiB enthalten")
    names = re.findall(r"(?mi)^\s*ServerName\s+([^\s#]+)", content)
    if not names or len({x.lower() for x in names}) != 1:
        raise HTTPException(status_code=400, detail="Uneindeutiger ServerName")
    host = validate_hostname(names[0])
    aliases = re.findall(r"(?mi)^\s*ServerAlias\s+([^\r\n#]+)", content)
    selected = []
    wildcards = {x.lower() for line in aliases for x in line.split() if '*' in x or '?' in x}
    if wildcards:
        prior = pathlib.Path(VHOST_DIR) / current_file if current_file else None
        if not prior or not prior.is_file() or prior.is_symlink():
            raise HTTPException(status_code=400, detail="Neue Wildcards nicht im geführten Editor")
        prior_names = re.findall(r"(?mi)^\s*ServerAlias\s+([^\r\n#]+)", prior.read_text(encoding="utf-8"))
        prior_wc = {x.lower() for line in prior_names for x in line.split() if '*' in x or '?' in x}
        if wildcards != prior_wc:
            raise HTTPException(status_code=400, detail="Wildcard-Änderungen nur manuell")
    for line in aliases:
        for name in line.split():
            if '*' in name or '?' in name: continue
            val=validate_hostname(name, "ServerAlias")
            if val!=host and val not in selected: selected.append(val)
    site_name_conflicts(host, selected, current_file=current_file)


def vhost_apply_transaction(file: str, revision: str, proposed: Optional[str], actor: str, action: str) -> None:
    if (pathlib.Path(VHOST_DIR) / file).is_symlink():
        raise HTTPException(status_code=409, detail="VHost-Symlinks sind schreibgeschützt")
    path=resolve_vhost_file(file)
    actual=vhost_revision(path)
    if actual!=revision:
        raise HTTPException(status_code=409, detail="VHost zwischenzeitlich geändert; bitte neu laden")
    if proposed is None and actual=="new":
        raise HTTPException(status_code=404, detail="VHost nicht gefunden")
    if proposed is not None:
        vhost_check_names(proposed, current_file=file if actual!="new" else "")
        dep=validate_vhost_managed_dependencies(proposed)
        if dep: raise HTTPException(status_code=400, detail=dep)
    before=path.read_bytes() if actual!="new" else None
    if before is not None and proposed is not None and before==proposed.encode("utf-8"): return
    ensure_vhost_control_plane_metadata()
    if vhost_revision(path)!=revision:
        raise HTTPException(status_code=409, detail="VHost gleichzeitig geändert")
    backup=backup_file(str(path)) if before is not None else None
    if before is not None and (not backup or not pathlib.Path(backup).is_file()):
        raise HTTPException(status_code=500, detail="VHost-Sicherung fehlgeschlagen")
    def rollback():
        try:
            if before is None: path.unlink(missing_ok=True)
            else:
                path.write_bytes(pathlib.Path(backup).read_bytes())
                set_host_file_metadata(path, 0o664)
            return bool(apache_test_and_reload().get("ok"))
        except Exception: return False
    try:
        if proposed is None: path.unlink()
        else: safe_write_file(str(path), proposed, mode=0o664)
        result=apache_test_and_reload()
    except Exception:
        restored=rollback()
        audit_event(actor,action,file,False)
        raise HTTPException(status_code=500, detail="Operation fehlgeschlagen; Rückfall: "+("OK" if restored else "FEHLGESCHLAGEN"))
    if not result.get("ok"):
        restored=rollback()
        audit_event(actor,action,file,False)
        raise HTTPException(status_code=400 if restored else 500,
                            detail="Apache hat Änderung abgelehnt; Rückfall: "+("OK" if restored else "FEHLGESCHLAGEN"))
    audit_event(actor,action,file,True)


def site_record(host: str) -> Dict[str, Any]:
    host = validate_hostname(host)
    for record in site_inventory():
        if record.get("host") == host:
            return record
    raise HTTPException(status_code=404, detail="Website nicht gefunden")


def control_get(path: str, params: Dict[str, str], timeout: int = 30) -> Dict[str, Any]:
    query = urllib.parse.urlencode(params)
    return control_request("GET", path + ("?" + query if query else ""), timeout=timeout)


def certificate_inventory() -> List[Dict[str, Any]]:
    base = pathlib.Path(PROJECT_DIR) / "letsencrypt" / "live"
    result: List[Dict[str, Any]] = []
    if not base.exists():
        return result
    for domain_dir in sorted(base.iterdir(), key=lambda p: p.name):
        if not domain_dir.is_dir():
            continue
        fullchain = domain_dir / "fullchain.pem"
        privkey = domain_dir / "privkey.pem"
        if not (fullchain.exists() and privkey.exists()):
            continue
        details = certificate_details(fullchain)
        result.append({"domain": domain_dir.name, "exists": True, **details})
    return result


def generate_site_vhost(host: str, aliases: List[str], kind: str, php: bool, proxy_target: str, cert_domain: str) -> str:
    alias_line = f"    ServerAlias {' '.join(aliases)}\n" if aliases else ""
    tls = bool(cert_domain)
    if kind == "website":
        root = f"/var/www/{host}"
        body = f"    DocumentRoot {root}\n\n    <Directory {root}>\n        AllowOverride All\n        Require all granted\n    </Directory>\n"
        if php:
            body += "\n    Include /etc/apache2/snippets/php-fpm.conf\n"
    elif kind == "proxy":
        target = (proxy_target or "").strip()
        if re.search(r'[\s"\\]', target):
            raise HTTPException(status_code=400, detail="Reverse-Proxy-Ziel enthaelt ungueltige Zeichen")
        parsed = urllib.parse.urlsplit(target)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.fragment:
            raise HTTPException(status_code=400, detail="Reverse-Proxy-Ziel muss eine HTTP/HTTPS-URL ohne Zugangsdaten oder Fragment sein")
        target = target.rstrip("/") + "/"
        body = f"    ProxyRequests Off\n    ProxyPreserveHost On\n    ProxyPass \"/\" \"{target}\" retry=0 timeout=60\n    ProxyPassReverse \"/\" \"{target}\"\n"
    else:
        raise HTTPException(status_code=400, detail="Unbekannter Website-Typ")

    if tls:
        http_body = f"    Redirect permanent / https://{host}/\n"
    else:
        http_body = body
    conf = f"<VirtualHost *:80>\n    ServerName {host}\n{alias_line}{http_body}</VirtualHost>\n"
    if tls:
        conf += f"\n<VirtualHost *:443>\n    ServerName {host}\n{alias_line}\n    Include /etc/apache2/snippets/ssl-common.conf\n    SSLCertificateFile /etc/letsencrypt/live/{cert_domain}/fullchain.pem\n    SSLCertificateKeyFile /etc/letsencrypt/live/{cert_domain}/privkey.pem\n\n{body}</VirtualHost>\n"
    return conf


def site_name_conflicts(host: str, aliases: List[str], current_file: str = "") -> None:
    """Reject duplicate Apache host identities across all known VHosts."""
    requested = {host, *aliases}
    for existing in site_inventory():
        if existing.get("file") == current_file:
            continue
        used = {str(existing.get("host", "")).lower(), *(str(a).lower() for a in existing.get("aliases", []))}
        conflicts = sorted(name for name in requested if any(
            name == assigned or (("*" in assigned or "?" in assigned) and fnmatch.fnmatchcase(name, assigned))
            for assigned in used
        ))
        if conflicts:
            raise HTTPException(status_code=409, detail="Hostname bereits in anderem VHost konfiguriert: " + ", ".join(conflicts))


def selected_site_certificate(host: str, aliases: List[str], selection: str, existing: str = "") -> str:
    """Reuse deployed certificates; never trigger issuance or mutate ACME state."""
    names = [host, *aliases]
    if selection == "keep":
        selected = existing
    elif selection == "auto":
        selected = choose_covered_certificate(names, certificate_inventory())
        if not selected:
            raise HTTPException(status_code=400, detail="Kein bestehendes gültiges Zertifikat deckt alle Hostnamen ab. Certbot verwaltet die Ausstellung für konfigurierte Zonen; prüfe die SSL/TLS-Seite. Eine DNS-Änderung erfolgt hier nicht.")
    elif selection == "none":
        selected = ""
    else:
        selected = selection
    if not selected:
        return ""
    valid = {c["domain"]: c for c in certificate_inventory() if c.get("exists")}
    cert = valid.get(selected)
    if not cert or cert.get("status") not in {"ok", "warning"}:
        raise HTTPException(status_code=400, detail="Zertifikat fehlt, ist abgelaufen oder kann nicht geprüft werden")
    uncovered = [name for name in names if not certificate_covers_hostname(name, cert.get("dns_names") or [])]
    if uncovered:
        raise HTTPException(status_code=400, detail="Zertifikat deckt folgende Hostnamen nicht ab: " + ", ".join(uncovered) + ". Wähle ein passendes bestehendes Zertifikat oder prüfe die automatische Ausstellung.")
    return selected


def site_is_generated(record: Dict[str, Any]) -> bool:
    """Edit only exact generator outputs, never handwritten Apache directives."""
    host = record.get("host", "")
    if record.get("kind") not in {"website", "proxy"} or record.get("file") != host + ".conf":
        return False
    try:
        validate_hostname(host)
        raw = record["raw"]
        lines = re.findall(r"^\s*ServerAlias\s+(.+)$", raw, flags=re.M)
        aliases = validate_aliases(lines[0]) if lines else []
        if host in aliases:
            return False
        expected = generate_site_vhost(host, aliases, record["kind"], bool(record["php"]), record["proxy_target"], record["cert_domain"])
        return expected == raw
    except (HTTPException, KeyError, ValueError):
        return False


def doctor_snapshot() -> Dict[str, Any]:
    result = control_request("GET", "/v1/doctor", timeout=30)
    if not result.get("ok"):
        return {"ok": False, "issues": [], "summary": {"errors": 1, "warnings": 0}}
    report = result.get("report")
    return report if isinstance(report, dict) else {"ok": False, "issues": [], "summary": {"errors": 1, "warnings": 0}}

def mask_value(key: str, value: str) -> str:
    if key in SECRET_KEYS and value:
        return "********"
    return value


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = Depends(require_auth)):
    ping = control_request("GET", "/v1/ping", timeout=15)
    containers_result = control_request("GET", "/v1/containers", timeout=20)
    containers = containers_result.get("containers", []) if containers_result.get("ok") else []
    certs = certificate_inventory()
    sites = enrich_sites(site_inventory(), certs)
    databases_result = control_request("GET", "/v1/databases", timeout=20)
    databases = databases_result.get("databases", []) if databases_result.get("ok") else []
    try:
        ftp_users = ftp_state().get("users", [])
    except Exception:
        ftp_users = []
    backups = list_backups()
    doctor = doctor_snapshot()
    return templates.TemplateResponse(request, "dashboard.html", {
        "request": request,
        "user": user,
        "containers": containers,
        "sites": sites,
        "certs": certs,
        "tls_issues": [s for s in sites if s["tls_status"] not in {"ok", "warning"}],
        "databases": databases,
        "ftp_users": ftp_users,
        "backups": backups,
        "doctor": doctor,
        "project_dir": PROJECT_DIR,
        "docker_ok": bool(ping.get("ok")),
        "docker_msg": ping.get("name") or ping.get("error") or "unavailable",
    })


@app.post("/container/{name}/action")
def container_action(
    name: str,
    action: str = Form(...),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    action = action.strip().lower()
    result = control_request("POST", "/v1/container-action", {"name": name, "action": action}, timeout=90)
    audit_event(user, "container_action", f"{name}:{action}", bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or result.get("stderr") or "Container action failed")
    return RedirectResponse(url="/", status_code=303)


@app.get("/container/{name}/logs", response_class=HTMLResponse)
def show_logs(request: Request, name: str, lines: int = 200, user: str = Depends(require_auth)):
    params = urllib.parse.urlencode({"name": name, "lines": min(max(lines, 10), 5000)})
    result = control_request("GET", "/v1/logs?" + params, timeout=30)
    text = str(result.get("text") or result.get("error") or "")
    return templates.TemplateResponse(request, "logs.html", {
        "request": request,
        "user": user,
        "name": name,
        "lines": lines,
        "logtext": text,
    })


@app.post("/compose/action")
def compose_action(
    action: str = Form(...),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    action = action.strip().lower()
    result = control_request("POST", "/v1/compose-action", {"action": action}, timeout=900)
    audit_event(user, "compose_action", action, bool(result.get("ok")), str(result.get("error") or ""))
    return render_text_page(
        "Compose output",
        f"{result.get('stdout', '')}\n{result.get('stderr', '')}",
        status_code=200 if result.get("ok") else 400,
    )


# ----------------------------
# Health Check
# ----------------------------

@app.get("/health", response_class=HTMLResponse)
def health_page(request: Request, user: str = Depends(require_auth)):
    ping = control_request("GET", "/v1/ping", timeout=15)
    containers_result = control_request("GET", "/v1/containers", timeout=20)
    containers = containers_result.get("containers", []) if containers_result.get("ok") else []
    return templates.TemplateResponse(request, "health.html", {
        "request": request,
        "user": user,
        "docker_ok": bool(ping.get("ok")),
        "docker_msg": ping.get("name") or ping.get("error") or "unavailable",
        "containers": containers,
        "now": time.time(),
    })


# ----------------------------
# Backup UI (Create + Download)
# Restore bleibt bewusst Shell-only
# ----------------------------

@app.get("/backup", response_class=HTMLResponse)
def backup_page(request: Request, user: str = Depends(require_auth)):
    ensure_backup_tool()
    backups = list_backups()
    return templates.TemplateResponse(request, "backup.html", {
        "request": request,
        "user": user,
        "backups": backups,
        "last_output": "",
        "last_file": "",
    })


@app.post("/backup/create", response_class=HTMLResponse)
def backup_create(
    request: Request,
    with_htdocs: Optional[str] = Form(None),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    ensure_backup_tool()
    backups_before = {b["name"] for b in list_backups()}

    include_web = bool(with_htdocs and with_htdocs.strip().lower() in ("1", "true", "yes", "on"))
    res = control_proc("/v1/backup-create", {"with_htdocs": include_web}, timeout=3600)
    audit_event(user, "backup_create", "with_htdocs" if include_web else "core", res.returncode == 0)
    out = (res.stdout + "\n" + res.stderr).strip()

    created_path = parse_backup_output_for_path(out)
    created_file = ""
    if created_path:
        created_file = os.path.basename(created_path)

    # Fallback: diff der backups
    if not created_file:
        backups_after = list_backups()
        for b in backups_after:
            if b["name"] not in backups_before:
                created_file = b["name"]
                break

    backups = list_backups()

    # bei Fehlern: Ausgabe anzeigen
    if res.returncode != 0 or not created_file:
        return templates.TemplateResponse(request, "backup.html", {
            "request": request,
            "user": user,
            "backups": backups,
            "last_output": out if out else "Backup fehlgeschlagen (keine Ausgabe).",
            "last_file": "",
        })

    return templates.TemplateResponse(request, "backup.html", {
        "request": request,
        "user": user,
        "backups": backups,
        "last_output": out,
        "last_file": created_file,
    })


@app.get("/backup/download")
def backup_download(file: str, user: str = Depends(require_auth)):
    name = sanitize_backup_name(file)
    base = pathlib.Path(BACKUPS_DIR).resolve()
    p = (base / name).resolve()
    try:
        p.relative_to(base)
    except ValueError:
        raise HTTPException(status_code=403, detail="Zugriff verweigert")
    if not p.is_file():
        raise HTTPException(status_code=404, detail="Backup nicht gefunden")
    return FileResponse(str(p), filename=name, media_type="application/gzip")


# ----------------------------
# Setup UI (.env + Zertifikate)
# ----------------------------

@app.get("/setup", response_class=HTMLResponse)
def setup_page(request: Request, user: str = Depends(require_auth)):
    lines = env_read_raw()
    env = env_parse(lines)

    # Defaults anzeigen (ohne bestehende Werte zu ueberschreiben)
    view: Dict[str, str] = {}
    for k in SETUP_KEYS:
        view[k] = env.get(k, "")

    # Secrets maskieren
    for k in list(view.keys()):
        view[k] = mask_value(k, view[k])

    domains_csv = env.get("DOMAINS", "")
    certs = cert_status_for_domains(domains_csv) if domains_csv else []

    return templates.TemplateResponse(request, "setup.html", {
        "request": request,
        "user": user,
        "env": view,
        "certs": certs,
        "env_path": ENV_PATH,
    })


@app.post("/setup/save", response_class=HTMLResponse)
def setup_save(
    request: Request,
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),

    # Network / published ports
    HTTP_BIND: str = Form("0.0.0.0"),
    HTTP_PORT: str = Form("80"),
    HTTPS_BIND: str = Form("0.0.0.0"),
    HTTPS_PORT: str = Form("443"),
    PHPMYADMIN_BIND: str = Form("127.0.0.1"),
    PHPMYADMIN_PORT: str = Form("8080"),
    FTP_BIND: str = Form("0.0.0.0"),
    FTP_PORT: str = Form("21"),
    FTP_PASV_MIN: str = Form("21000"),
    FTP_PASV_MAX: str = Form("21010"),
    FTP_CERT_DOMAIN: str = Form(""),

    # Basics
    DOMAINS: str = Form(""),
    LE_EMAIL: str = Form(""),

    CERTBOT_ENABLED: Optional[str] = Form(None),
    DNS_UPDATER_ENABLED: Optional[str] = Form(None),
    ACME_CHALLENGE: str = Form("dns"),
    DNS_PROVIDER: str = Form("cloudflare"),

    CLOUDFLARE_API_TOKEN: str = Form(""),
    FTP_PUBLIC_HOST: str = Form(""),
    FTP_TLS: Optional[str] = Form(None),

    DB_ROOT_PASSWORD: str = Form(""),
    DB_PASSWORD: str = Form(""),
    DB_USER: str = Form(""),
    DB_NAME: str = Form(""),

    PROXIED_DEFAULT: Optional[str] = Form(None),
    MEOWHOME_UI_USER: str = Form(""),
    MEOWHOME_UI_PASS: str = Form(""),
):
    global UI_USER, UI_PASS
    lines = env_read_raw()
    updates: Dict[str, str] = {}

    # Validation / normalization
    updates["HTTP_BIND"] = validate_bind(HTTP_BIND, "HTTP_BIND")
    updates["HTTP_PORT"] = validate_port(HTTP_PORT, "HTTP_PORT")
    updates["HTTPS_BIND"] = validate_bind(HTTPS_BIND, "HTTPS_BIND")
    updates["HTTPS_PORT"] = validate_port(HTTPS_PORT, "HTTPS_PORT")
    updates["PHPMYADMIN_BIND"] = validate_bind(PHPMYADMIN_BIND, "PHPMYADMIN_BIND")
    updates["PHPMYADMIN_PORT"] = validate_port(PHPMYADMIN_PORT, "PHPMYADMIN_PORT")
    updates["FTP_BIND"] = validate_bind(FTP_BIND, "FTP_BIND")
    updates["FTP_PORT"] = validate_port(FTP_PORT, "FTP_PORT")
    updates["FTP_PASV_MIN"] = validate_port(FTP_PASV_MIN, "FTP_PASV_MIN")
    updates["FTP_PASV_MAX"] = validate_port(FTP_PASV_MAX, "FTP_PASV_MAX")
    if int(updates["FTP_PASV_MIN"]) > int(updates["FTP_PASV_MAX"]):
        raise HTTPException(status_code=400, detail="FTP_PASV_MIN darf nicht groesser als FTP_PASV_MAX sein")
    updates["FTP_CERT_DOMAIN"] = (FTP_CERT_DOMAIN or "").strip().lower()

    updates["DOMAINS"] = validate_domains(DOMAINS)
    updates["LE_EMAIL"] = validate_email(LE_EMAIL)

    acme = (ACME_CHALLENGE or "").strip().lower()
    if acme not in ALLOWED_ACME:
        raise HTTPException(status_code=400, detail="ACME_CHALLENGE muss dns oder http sein")
    updates["ACME_CHALLENGE"] = acme

    updates["DNS_PROVIDER"] = (DNS_PROVIDER or "cloudflare").strip().lower() or "cloudflare"

    updates["CERTBOT_ENABLED"] = normalize_bool(CERTBOT_ENABLED or "")
    updates["DNS_UPDATER_ENABLED"] = normalize_bool(DNS_UPDATER_ENABLED or "")
    updates["FTP_TLS"] = "YES" if (FTP_TLS or "").strip().lower() in ("1", "true", "yes", "on") else "NO"
    updates["PROXIED_DEFAULT"] = normalize_bool(PROXIED_DEFAULT or "")

    # Non-secret normal fields
    updates["FTP_PUBLIC_HOST"] = (FTP_PUBLIC_HOST or "").strip()

    # Secrets: nur setzen, wenn Feld nicht leer ist
    if CLOUDFLARE_API_TOKEN.strip():
        updates["CLOUDFLARE_API_TOKEN"] = CLOUDFLARE_API_TOKEN.strip()

    if DB_ROOT_PASSWORD.strip():
        updates["DB_ROOT_PASSWORD"] = DB_ROOT_PASSWORD.strip()
    if DB_PASSWORD.strip():
        updates["DB_PASSWORD"] = DB_PASSWORD.strip()

    if DB_USER.strip():
        updates["DB_USER"] = DB_USER.strip()
    if DB_NAME.strip():
        updates["DB_NAME"] = DB_NAME.strip()
    if MEOWHOME_UI_USER.strip():
        updates["MEOWHOME_UI_USER"] = MEOWHOME_UI_USER.strip()
    if MEOWHOME_UI_PASS.strip():
        updates["MEOWHOME_UI_PASS"] = MEOWHOME_UI_PASS.strip()

    # Backup + write
    bak = env_backup_file()
    new_lines = env_set_values(lines, updates)
    pathlib.Path(ENV_PATH).write_text("".join(new_lines), encoding="utf-8")
    set_host_file_metadata(pathlib.Path(ENV_PATH), 0o600)

    # UI Basic Auth values are process globals. Apply changed credentials now;
    # self-recreating this container from inside itself is inherently racy.
    env_after = env_parse(new_lines)
    UI_USER = env_after.get("MEOWHOME_UI_USER", UI_USER) or UI_USER
    UI_PASS = env_after.get("MEOWHOME_UI_PASS", UI_PASS) or UI_PASS

    # Page neu rendern (maskiert)
    view: Dict[str, str] = {}
    for k in SETUP_KEYS:
        view[k] = mask_value(k, env_after.get(k, ""))

    certs = cert_status_for_domains(env_after.get("DOMAINS", ""))
    audit_event(user, "setup_save", "configuration", True)

    return templates.TemplateResponse(request, "setup.html", {
        "request": request,
        "user": user,
        "env": view,
        "certs": certs,
        "env_path": ENV_PATH,
        "saved": True,
        "backup_file": bak or "",
        "note": "Gespeichert. Neue UI Login-Daten gelten sofort fuer neue Requests; andere Service-Einstellungen werden beim naechsten Compose-Reconcile wirksam.",
    })


# ----------------------------
# FTP User Management (core owner: tools/ftp/meowftp.py + ftp/users.sqlite)
# ----------------------------

def ftp_run(args: List[str], *, timeout: int = 60, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    return control_proc("/v1/ftp", {"args": args, "input": input_text}, timeout=timeout)

def ftp_state() -> Dict[str, Any]:
    res = ftp_run(["list", "--json"], timeout=60)
    if res.returncode != 0:
        raise HTTPException(status_code=500, detail=(res.stderr or res.stdout or "FTP state unavailable").strip())
    try:
        data = json.loads(res.stdout)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail=f"FTP state JSON ungueltig: {exc}") from exc
    if not isinstance(data, dict):
        raise HTTPException(status_code=500, detail="FTP state JSON hat ein unerwartetes Format")
    return data


def ftp_apply_or_error(prefix: str, result: subprocess.CompletedProcess) -> Optional[HTMLResponse]:
    if result.returncode != 0:
        text = "\n".join([prefix, result.stdout, result.stderr]).strip()
        return render_text_page("FTP command failed", text, back_url="/ftp", status_code=400)
    apply_result = ftp_run(["apply"], timeout=600)
    if apply_result.returncode != 0:
        text = "\n".join([prefix, result.stdout, result.stderr, "=== apply ===", apply_result.stdout, apply_result.stderr]).strip()
        return render_text_page("FTP apply failed", text, back_url="/ftp", status_code=400)
    return None


@app.get("/ftp", response_class=HTMLResponse)
def ftp_page(request: Request, user: str = Depends(require_auth)):
    state = ftp_state()
    resp = templates.TemplateResponse(request, "ftp.html", {
        "request": request,
        "user": user,
        "users": state.get("users", []),
        "domains": state.get("available_domains", []),
    })
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.post("/ftp/add")
def ftp_add(
    username: str = Form(...),
    password: str = Form(...),
    domains: Optional[List[str]] = Form(None),
    allow_all: Optional[str] = Form(None),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    username = username.strip()
    selected = [d.strip() for d in (domains or []) if d.strip()]
    allow_all_enabled = (allow_all or "").strip().lower() in ("1", "true", "yes", "on")

    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="username muss 1-32 Zeichen lang sein und darf nur A-Z, a-z, 0-9, _, - enthalten")
    if not password:
        raise HTTPException(status_code=400, detail="Passwort darf nicht leer sein")
    if allow_all_enabled and selected:
        raise HTTPException(status_code=400, detail="Entweder Vollzugriff oder konkrete Domains auswaehlen, nicht beides")
    if not allow_all_enabled and not selected:
        raise HTTPException(status_code=400, detail="Mindestens eine Domain auswaehlen oder Vollzugriff aktivieren")

    initial_home = "" if allow_all_enabled else selected[0]
    add_args = ["add", username, initial_home, "--password-stdin"]
    if allow_all_enabled:
        add_args.append("--allow-all")
    res_add = ftp_run(add_args, input_text=password + "\n")
    if res_add.returncode != 0:
        return render_text_page("FTP add failed", (res_add.stdout + "\n" + res_add.stderr).strip(), back_url="/ftp", status_code=400)

    if allow_all_enabled:
        access_result = ftp_run(["all", username])
    else:
        access_result = ftp_run(["assign", username] + selected)
    if access_result.returncode != 0:
        return render_text_page(
            "FTP access assignment failed",
            "\n".join([res_add.stdout, res_add.stderr, access_result.stdout, access_result.stderr]).strip(),
            back_url="/ftp",
            status_code=400,
        )

    error = ftp_apply_or_error("=== access ===", access_result)
    if error:
        audit_event(user, "ftp_add", username, False)
        return error
    audit_event(user, "ftp_add", username, True)
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/access")
def ftp_access(
    username: str = Form(...),
    domains: Optional[List[str]] = Form(None),
    allow_all: Optional[str] = Form(None),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    username = username.strip()
    selected = [d.strip() for d in (domains or []) if d.strip()]
    allow_all_enabled = (allow_all or "").strip().lower() in ("1", "true", "yes", "on")
    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="ungueltiger FTP username")
    if allow_all_enabled and selected:
        raise HTTPException(status_code=400, detail="Entweder Vollzugriff oder konkrete Domains auswaehlen")
    if allow_all_enabled:
        res = ftp_run(["all", username])
    elif selected:
        res = ftp_run(["assign", username] + selected)
    else:
        raise HTTPException(status_code=400, detail="Mindestens eine Domain auswaehlen")
    error = ftp_apply_or_error("=== access ===", res)
    if error:
        audit_event(user, "ftp_access", username, False)
        return error
    audit_event(user, "ftp_access", username, True)
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/passwd")
def ftp_passwd(
    username: str = Form(...),
    password: str = Form(...),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    username = username.strip()
    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="ungueltiger FTP username")
    if not password:
        raise HTTPException(status_code=400, detail="Passwort darf nicht leer sein")
    res = ftp_run(["passwd", username, "--password-stdin"], input_text=password + "\n")
    error = ftp_apply_or_error("=== passwd ===", res)
    if error:
        audit_event(user, "ftp_passwd", username, False)
        return error
    audit_event(user, "ftp_passwd", username, True)
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/del")
def ftp_del(username: str = Form(...), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    username = username.strip()
    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="ungueltiger FTP username")
    res = ftp_run(["del", username])
    error = ftp_apply_or_error("=== delete ===", res)
    if error:
        audit_event(user, "ftp_del", username, False)
        return error
    audit_event(user, "ftp_del", username, True)
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/enable")
def ftp_enable(
    username: str = Form(...),
    enabled: str = Form(...),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    username = username.strip()
    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="ungueltiger FTP username")
    cmd = "enable" if enabled.strip().lower() in ("1", "true", "yes", "on") else "disable"
    res = ftp_run([cmd, username])
    error = ftp_apply_or_error(f"=== {cmd} ===", res)
    if error:
        audit_event(user, "ftp_enable", username, False)
        return error
    audit_event(user, "ftp_enable", username, True)
    return RedirectResponse(url="/ftp", status_code=303)



# ----------------------------
# Websites & Domains
# ----------------------------

@app.get("/sites", response_class=HTMLResponse)
def sites_page(request: Request, user: str = Depends(require_auth)):
    certs = certificate_inventory()
    return templates.TemplateResponse(request, "sites.html", {
        "request": request,
        "user": user,
        "sites": enrich_sites(site_inventory(), certs),
        "certs": certs,
    })


@app.get("/sites/new", response_class=HTMLResponse)
def site_new_page(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse(request, "site_new.html", {
        "request": request,
        "user": user,
        "certs": [c for c in certificate_inventory() if c.get("status") in {"ok", "warning"}],
    })


@app.post("/sites/create")
def site_create(
    host: str = Form(...),
    aliases: str = Form(""),
    kind: str = Form("website"),
    proxy_target: str = Form(""),
    cert_domain: str = Form("auto"),
    php: Optional[str] = Form(None),
    create_index: Optional[str] = Form(None),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    host = validate_hostname(host)
    alias_list = [a for a in validate_aliases(aliases) if a != host]
    kind = (kind or "website").strip().lower()
    cert_domain = (cert_domain or "").strip()
    site_name_conflicts(host, alias_list)
    cert_domain = selected_site_certificate(host, alias_list, "none" if cert_domain == "" else cert_domain)
    file_name = host + ".conf"
    path = resolve_vhost_file(file_name)
    if path.exists():
        raise HTTPException(status_code=409, detail="Fuer diese Domain existiert bereits ein VHost")
    content = generate_site_vhost(host, alias_list, kind, bool(php), proxy_target, cert_domain)
    if kind == "website":
        result = control_request("POST", "/v1/webroot-ensure", {"host": host, "create_index": bool(create_index)}, timeout=30)
        if not result.get("ok"):
            raise HTTPException(status_code=400, detail=result.get("error") or "Webroot konnte nicht erstellt werden")
    vhost_apply_transaction(file_name, "new", content, user, "site_create")
    return RedirectResponse(url=f"/sites/{host}", status_code=303)


def _alias_site_state(host: str) -> Tuple[Dict[str, Any], pathlib.Path, bytes]:
    site = site_record(host)
    if len([s for s in site_inventory() if s.get("host", "").lower() == host.lower()]) != 1:
        raise HTTPException(status_code=409, detail="Hauptdomain ist mehrfach konfiguriert")
    path = resolve_vhost_file(site["file"])
    if (pathlib.Path(VHOST_DIR) / site["file"]).is_symlink() or not path.is_file():
        raise HTTPException(status_code=409, detail="Keine reguläre VHost-Datei")
    return site, path, path.read_bytes()


def _alias_site_plan(host: str, aliases: str, revision: str) -> Tuple[Dict[str, Any], pathlib.Path, Any]:
    site, path, before = _alias_site_state(host)
    if not re.fullmatch(r"[a-f0-9]{64}", revision) or hashlib.sha256(before).hexdigest() != revision:
        raise HTTPException(status_code=409, detail="VHost zwischenzeitlich geändert; Seite neu laden")
    try:
        raw = before.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status_code=409, detail="VHost ist nicht UTF-8-kodiert")
    wanted = [a for a in validate_aliases(aliases) if a != site["host"].lower()]
    try:
        plan = plan_alias_edit(raw, site["host"], wanted)
    except UnsupportedVhost as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    site_name_conflicts(site["host"].lower(), wanted, current_file=site["file"])
    if site["tls"]:
        if not site["cert_domain"]:
            raise HTTPException(status_code=409, detail="TLS-Zertifikat nicht eindeutig erkannt; Advanced VHost verwenden")
        selected_site_certificate(site["host"].lower(), wanted, "keep", site["cert_domain"])
    return site, path, plan


@app.get("/sites/{host}/aliases", response_class=HTMLResponse)
def site_aliases_page(request: Request, host: str, user: str = Depends(require_auth)):
    site, path, before = _alias_site_state(host)
    try:
        proposal = plan_alias_edit(before.decode("utf-8"), site["host"], [str(a).lower() for a in site["aliases"]])
        editable, reason = True, ""
        shown = ", ".join(proposal.aliases)
    except (UnicodeDecodeError, UnsupportedVhost) as exc:
        editable, reason = False, str(exc)
        shown = ", ".join(site["aliases"])
    return templates.TemplateResponse(request, "site_aliases.html", {
        "request": request, "user": user, "site": site, "editable": editable,
        "reason": reason, "aliases": shown,
        "revision": hashlib.sha256(before).hexdigest(),
    })


@app.post("/sites/{host}/aliases/preview", response_class=HTMLResponse)
def site_aliases_preview(request: Request, host: str, revision: str = Form(...), aliases: str = Form(""),
                         user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    site, path, plan = _alias_site_plan(host, aliases, revision)
    return templates.TemplateResponse(request, "site_aliases_preview.html", {
        "request": request, "user": user, "site": site,
        "revision": revision, "aliases": ", ".join(plan.aliases), "diff": plan.diff,
        "changed": plan.before != plan.after,
    })


@app.post("/sites/{host}/aliases/apply")
def site_aliases_apply(host: str, revision: str = Form(...), aliases: str = Form(""),
                       user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    site, path, plan = _alias_site_plan(host, aliases, revision)
    if plan.before == plan.after:
        return RedirectResponse(url=f"/sites/{host}", status_code=303)
    ensure_vhost_control_plane_metadata()
    if hashlib.sha256(path.read_bytes()).hexdigest() != revision:
        raise HTTPException(status_code=409, detail="VHost während der Freigabe geändert")
    dependency_error = validate_vhost_managed_dependencies(plan.after)
    if dependency_error:
        raise HTTPException(status_code=400, detail=dependency_error)
    bak = backup_file(str(path))
    if not bak:
        raise HTTPException(status_code=500, detail="Sicherung der VHost-Konfiguration fehlgeschlagen")
    try:
        safe_write_file(str(path), plan.after, mode=0o664)
        result = apache_test_and_reload()
    except Exception:
        safe_write_file(str(path), pathlib.Path(bak).read_text(encoding="utf-8"), mode=0o664)
        apache_test_and_reload()
        audit_event(user, "site_aliases_apply", host, False)
        raise
    if not result.get("ok"):
        safe_write_file(str(path), pathlib.Path(bak).read_text(encoding="utf-8"), mode=0o664)
        rollback = apache_test_and_reload()
        audit_event(user, "site_aliases_apply", host, False)
        message = "Apache hat die Änderung abgelehnt; vorherige Datei wiederhergestellt."
        if not rollback.get("ok"):
            message += " WARNUNG: Apache-Rollback fehlgeschlagen; bitte sofort prüfen."
        return render_text_page("Aliases nicht gespeichert", message,
                                back_url=f"/sites/{host}/aliases", status_code=400)
    audit_event(user, "site_aliases_apply", host, True)
    return RedirectResponse(url=f"/sites/{host}", status_code=303)


@app.get("/sites/{host}/settings", response_class=HTMLResponse)
def site_settings(request: Request, host: str, user: str = Depends(require_auth)):
    site = site_record(host)
    if not site_is_generated(site):
        raise HTTPException(status_code=409, detail="Benutzerdefinierten VHost nur über den Advanced-Editor bearbeiten")
    path = resolve_vhost_file(site["file"])
    return templates.TemplateResponse(request, "site_settings.html", {
        "request": request, "user": user, "site": site,
        "revision": hashlib.sha256(path.read_bytes()).hexdigest(),
        "certs": [c for c in certificate_inventory() if c.get("status") in {"ok", "warning"}],
    })


@app.post("/sites/{host}/settings")
def site_settings_save(
    host: str,
    revision: str = Form(...),
    aliases: str = Form(""),
    php: Optional[str] = Form(None),
    proxy_target: str = Form(""),
    cert_domain: str = Form("keep"),
    user: str = Depends(require_auth),
    _csrf: None = Depends(require_csrf),
):
    site = site_record(host)
    if not site_is_generated(site):
        raise HTTPException(status_code=409, detail="VHost wurde individuell angepasst; bitte Advanced VHost verwenden")
    path = resolve_vhost_file(site["file"])
    if not re.fullmatch(r"[a-f0-9]{64}", revision) or hashlib.sha256(path.read_bytes()).hexdigest() != revision:
        raise HTTPException(status_code=409, detail="VHost wurde zwischenzeitlich geändert. Seite neu laden.")
    host = site["host"]
    alias_list = [a for a in validate_aliases(aliases) if a != host]
    site_name_conflicts(host, alias_list, current_file=site["file"])
    kind = site["kind"]
    cert = selected_site_certificate(host, alias_list, (cert_domain or "keep").strip(), site["cert_domain"])
    content = generate_site_vhost(host, alias_list, kind, bool(php) if kind == "website" else False,
                                  proxy_target if kind == "proxy" else "", cert)
    if content == site["raw"]:
        return RedirectResponse(url=f"/sites/{host}", status_code=303)
    ensure_vhost_control_plane_metadata()
    if hashlib.sha256(path.read_bytes()).hexdigest() != revision:
        raise HTTPException(status_code=409, detail="VHost wurde während der Änderung aktualisiert. Seite neu laden.")
    dependency_error = validate_vhost_managed_dependencies(content)
    if dependency_error:
        raise HTTPException(status_code=400, detail=dependency_error)
    bak = backup_file(str(path))
    try:
        safe_write_file(str(path), content, mode=0o664)
        result = apache_test_and_reload()
    except Exception:
        if bak:
            safe_write_file(str(path), pathlib.Path(bak).read_text(encoding="utf-8"), mode=0o664)
            apache_test_and_reload()
        raise
    if not result.get("ok"):
        if bak:
            safe_write_file(str(path), pathlib.Path(bak).read_text(encoding="utf-8"), mode=0o664)
            rollback = apache_test_and_reload()
        else:
            rollback = {"ok": False}
        audit_event(user, "site_settings_save", host, False)
        detail = "Apache hat die neue Konfiguration abgelehnt. Vorherige Datei wiederhergestellt."
        if not rollback.get("ok"):
            detail += " ACHTUNG: Apache-Rollback-Reload fehlgeschlagen; bitte sofort prüfen."
        return render_text_page("Website-Einstellungen nicht gespeichert", detail, back_url=f"/sites/{host}/settings", status_code=400)
    audit_event(user, "site_settings_save", host, True)
    return RedirectResponse(url=f"/sites/{host}", status_code=303)


@app.get("/sites/{host}", response_class=HTMLResponse)
def site_detail(request: Request, host: str, user: str = Depends(require_auth)):
    site = site_record(host)
    certs = certificate_inventory()
    site = site_tls_health(site, certs)
    cert = site.get("tls_cert")
    file_manager = site.get("kind") == "website"
    return templates.TemplateResponse(request, "site_detail.html", {
        "request": request, "user": user, "site": site, "cert": cert, "file_manager": file_manager,
        "settings_editable": site_is_generated(site),
    })


@app.get("/sites/{host}/files", response_class=HTMLResponse)
def site_files(request: Request, host: str, path: str = "", user: str = Depends(require_auth)):
    site = site_record(host)
    if site.get("kind") != "website":
        raise HTTPException(status_code=400, detail="File Manager ist nur fuer Websites mit Webroot verfuegbar")
    result = control_get("/v1/files", {"host": host, "path": path}, timeout=30)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Dateien konnten nicht geladen werden")
    return templates.TemplateResponse(request, "file_manager.html", {
        "request": request, "user": user, "site": site, "listing": result,
    })


@app.get("/sites/{host}/files/edit", response_class=HTMLResponse)
def site_file_edit(request: Request, host: str, path: str, user: str = Depends(require_auth)):
    site = site_record(host)
    if site.get("kind") != "website":
        raise HTTPException(status_code=400, detail="File Manager ist nur fuer Websites verfuegbar")
    result = control_get("/v1/file-read", {"host": host, "path": path}, timeout=30)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Datei konnte nicht gelesen werden")
    return templates.TemplateResponse(request, "file_edit.html", {"user": user, "site": site, "file": result})


@app.post("/sites/{host}/files/save")
def site_file_save(host: str, path: str = Form(...), content: str = Form(""), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    site_record(host)
    result = control_request("POST", "/v1/file-write", {"host": host, "path": path, "content": content}, timeout=30)
    audit_event(user, "file_write", f"{host}/{path}", bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Datei konnte nicht gespeichert werden")
    parent = str(pathlib.PurePosixPath(path).parent)
    parent = "" if parent == "." else parent
    return RedirectResponse(url=f"/sites/{host}/files?path={urllib.parse.quote(parent)}", status_code=303)


@app.post("/sites/{host}/files/mkdir")
def site_file_mkdir(host: str, directory: str = Form(""), name: str = Form(...), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    site_record(host)
    result = control_request("POST", "/v1/file-mkdir", {"host": host, "directory": directory, "name": name}, timeout=30)
    audit_event(user, "file_mkdir", f"{host}/{directory}/{name}", bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Ordner konnte nicht erstellt werden")
    return RedirectResponse(url=f"/sites/{host}/files?path={urllib.parse.quote(directory)}", status_code=303)


@app.post("/sites/{host}/files/upload")
def site_file_upload(host: str, directory: str = Form(""), overwrite: Optional[str] = Form(None), upload: UploadFile = File(...), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    site_record(host)
    data = upload.file.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Upload ist auf 8 MiB pro Datei begrenzt")
    result = control_request("POST", "/v1/file-upload", {"host": host, "directory": directory, "name": upload.filename or "", "data": base64.b64encode(data).decode("ascii"), "overwrite": bool(overwrite)}, timeout=60)
    audit_event(user, "file_upload", f"{host}/{directory}/{upload.filename or ''}", bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Upload fehlgeschlagen")
    return RedirectResponse(url=f"/sites/{host}/files?path={urllib.parse.quote(directory)}", status_code=303)


@app.post("/sites/{host}/files/delete")
def site_file_delete(host: str, path: str = Form(...), directory: str = Form(""), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    site_record(host)
    result = control_request("POST", "/v1/file-delete", {"host": host, "path": path}, timeout=30)
    audit_event(user, "file_delete", f"{host}/{path}", bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or "Datei/Ordner konnte nicht geloescht werden")
    return RedirectResponse(url=f"/sites/{host}/files?path={urllib.parse.quote(directory)}", status_code=303)


# ----------------------------
# SSL/TLS
# ----------------------------

@app.get("/certificates", response_class=HTMLResponse)
def certificates_page(request: Request, user: str = Depends(require_auth)):
    env = env_parse(env_read_raw())
    certs = certificate_inventory()
    sites = enrich_sites(site_inventory(), certs)
    containers = control_request("GET", "/v1/containers", timeout=20)
    certbot_running = any(
        c.get("name") == "meowhome_certbot" and c.get("status") == "running"
        for c in containers.get("containers", [])
    )
    return templates.TemplateResponse(request, "certificates.html", {
        "request": request,
        "user": user,
        "certs": certs,
        "sites": sites,
        "problem_count": sum(s["tls_status"] not in {"ok", "warning"} for s in sites),
        "challenge": env.get("ACME_CHALLENGE", ""),
        "provider": env.get("DNS_PROVIDER", ""),
        "email": env.get("LE_EMAIL", ""),
        "certbot_enabled": env.get("CERTBOT_ENABLED", "true").lower() == "true",
        "certbot_running": certbot_running,
    })


@app.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request, user: str = Depends(require_auth)):
    return templates.TemplateResponse(request, "activity.html", {
        "request": request, "user": user,
        "events": recent_activity(pathlib.Path(AUDIT_LOG)),
    })


@app.get("/dns", response_class=HTMLResponse)
def dns_page(request: Request, user: str = Depends(require_auth)):
    env = env_parse(env_read_raw())
    zones = [d.strip() for d in env.get("DOMAINS", "").split(",") if d.strip()]
    containers = control_request("GET", "/v1/containers", timeout=20)
    updater_running = any(
        c.get("name") == "meowhome_dns_updater" and c.get("status") == "running"
        for c in containers.get("containers", [])
    )
    return templates.TemplateResponse(request, "dns.html", {
        "request": request,
        "user": user,
        "zones": zones,
        "provider": env.get("DNS_PROVIDER", ""),
        "challenge": env.get("ACME_CHALLENGE", ""),
        "updater_enabled": env.get("DNS_UPDATER_ENABLED", "true").lower() == "true",
        "updater_running": updater_running,
    })


# ----------------------------
# Databases
# ----------------------------

@app.get("/databases", response_class=HTMLResponse)
def databases_page(request: Request, user: str = Depends(require_auth)):
    result = control_request("GET", "/v1/databases", timeout=20)
    users_result = control_request("GET", "/v1/database-users", timeout=20)
    users_by_db: Dict[str, List[Dict[str, Any]]] = {}
    if users_result.get("ok"):
        for row in users_result.get("users", []):
            users_by_db.setdefault(str(row.get("database", "")), []).append(row)
    env = env_parse(env_read_raw())
    return templates.TemplateResponse(request, "databases.html", {
        "request": request,
        "user": user,
        "databases": result.get("databases", []) if result.get("ok") else [],
        "users_by_db": users_by_db,
        "db_error": "" if result.get("ok") else (result.get("error") or result.get("stderr") or ""),
        "users_error": "" if users_result.get("ok") else (users_result.get("error") or users_result.get("stderr") or ""),
        "pma_bind": env.get("PHPMYADMIN_BIND", "127.0.0.1"),
        "pma_port": env.get("PHPMYADMIN_PORT", "8080"),
    })


@app.post("/databases/create")
def database_create(name: str = Form(...), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    name = (name or "").strip()
    if not DATABASE_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Datenbankname darf nur A-Z, a-z, 0-9, _, $, - enthalten")
    result = control_request("POST", "/v1/database-create", {"name": name}, timeout=30)
    audit_event(user, "database_create", name, bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or result.get("stderr") or "Datenbank konnte nicht erstellt werden")
    return RedirectResponse(url="/databases", status_code=303)


@app.post("/databases/drop")
def database_drop(name: str = Form(...), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    name = (name or "").strip()
    if not DATABASE_NAME_RE.fullmatch(name):
        raise HTTPException(status_code=400, detail="Ungueltiger Datenbankname")
    result = control_request("POST", "/v1/database-drop", {"name": name}, timeout=30)
    audit_event(user, "database_drop", name, bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or result.get("stderr") or "Datenbank konnte nicht geloescht werden")
    return RedirectResponse(url="/databases", status_code=303)


@app.post("/databases/user-create")
def database_user_create(database: str = Form(...), username: str = Form(...), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    database = (database or "").strip()
    username = (username or "").strip()
    if not DATABASE_NAME_RE.fullmatch(database) or not re.fullmatch(r"[A-Za-z0-9_$-]{1,32}", username):
        raise HTTPException(status_code=400, detail="Ungueltiger Datenbank- oder Benutzername")
    password = secrets.token_urlsafe(24)
    result = control_request("POST", "/v1/database-user-create", {"database": database, "user": username, "password": password}, timeout=30)
    audit_event(user, "database_user_create", f"{username}@{database}", bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or result.get("stderr") or "Datenbankbenutzer konnte nicht erstellt werden")
    return render_text_page("Datenbankbenutzer erstellt", f"Benutzer: {username}\nDatenbank: {database}\nPasswort: {password}\n\nDas Passwort wird nur jetzt angezeigt. Bitte sicher speichern.", back_url="/databases")


@app.post("/databases/user-drop")
def database_user_drop(username: str = Form(...), user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    username = (username or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9_$-]{1,32}", username):
        raise HTTPException(status_code=400, detail="Ungueltiger Datenbankbenutzer")
    result = control_request("POST", "/v1/database-user-drop", {"user": username}, timeout=30)
    audit_event(user, "database_user_drop", username, bool(result.get("ok")), str(result.get("error") or ""))
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error") or result.get("stderr") or "Datenbankbenutzer konnte nicht geloescht werden")
    return RedirectResponse(url="/databases", status_code=303)


# ----------------------------
# VHost Management
# ----------------------------

@app.get("/vhosts", response_class=HTMLResponse)
def vhosts(request: Request, user: str = Depends(require_auth)):
    ensure_vhost_control_plane_metadata()
    files=[]
    for path in sorted(pathlib.Path(VHOST_DIR).glob("*.conf")):
        if path.is_file() and not path.is_symlink():
            content=path.read_text(encoding="utf-8",errors="replace")
            files.append({"name":path.name,"managed":bool(re.search(r"(?mi)^\s*ServerName\s+",content))})
    return templates.TemplateResponse(request,"vhosts.html",{"user":user,"files":files})


@app.get("/vhosts/new",response_class=HTMLResponse)
def vhosts_new(request:Request,user:str=Depends(require_auth)):
    return templates.TemplateResponse(request,"vhosts_new.html",{"user":user})


@app.get("/vhosts/edit",response_class=HTMLResponse)
def vhosts_edit(request:Request,file:str,user:str=Depends(require_auth)):
    file=file.strip()
    if (pathlib.Path(VHOST_DIR)/file).is_symlink():
        raise HTTPException(status_code=409,detail="VHost-Link nicht bearbeitbar")
    path=resolve_vhost_file(file)
    revision=vhost_revision(path)
    content=path.read_text(encoding="utf-8") if revision!="new" else ""
    return templates.TemplateResponse(request,"vhosts_edit.html",{"user":user,
        "file":file,"revision":revision,"content":content})


def vhost_preview_context(file:str,content:str,revision:str)->Dict[str,Any]:
    import difflib
    file=file.strip()
    if (pathlib.Path(VHOST_DIR)/file).is_symlink():
        raise HTTPException(status_code=409,detail="VHost-Link nicht bearbeitbar")
    path=resolve_vhost_file(file)
    if vhost_revision(path)!=revision:
        raise HTTPException(status_code=409,detail="VHost zwischenzeitlich geändert")
    vhost_check_names(content,current_file=file if revision!="new" else "")
    dep=validate_vhost_managed_dependencies(content)
    if dep:raise HTTPException(status_code=400,detail=dep)
    before=path.read_text(encoding="utf-8") if revision!="new" else ""
    diff="".join(difflib.unified_diff(before.splitlines(keepends=True),content.splitlines(keepends=True),
                                     fromfile="Aktuell",tofile="Vorschlag",n=3))
    return {"file":file,"revision":revision,"content":content,"changed":before!=content,"diff":diff}


@app.post("/vhosts/preview",response_class=HTMLResponse)
def vhosts_preview(request:Request,file:str=Form(...),content:str=Form(...),revision:str=Form(...),
                   user:str=Depends(require_auth),_csrf:None=Depends(require_csrf)):
    details=vhost_preview_context(file,content,revision)
    return templates.TemplateResponse(request,"vhosts_preview.html",{"user":user,**details})


@app.post("/vhosts/save")
def vhosts_save(file:str=Form(...),content:str=Form(...),revision:str=Form(...),
                user:str=Depends(require_auth),_csrf:None=Depends(require_csrf)):
    vhost_apply_transaction(file.strip(),revision,content,user,"vhost_save")
    return RedirectResponse(url="/vhosts",status_code=303)


@app.get("/vhosts/delete",response_class=HTMLResponse)
def vhosts_delete_page(request:Request,file:str,user:str=Depends(require_auth)):
    file=file.strip()
    if (pathlib.Path(VHOST_DIR)/file).is_symlink():
        raise HTTPException(status_code=409,detail="VHost-Link nicht bearbeitbar")
    path=resolve_vhost_file(file)
    rev=vhost_revision(path)
    if rev=="new":raise HTTPException(status_code=404,detail="VHost nicht gefunden")
    raw=path.read_text(encoding="utf-8")
    names=re.findall(r"(?mi)^\s*ServerName\s+([^\s#]+)",raw)
    if not names:raise HTTPException(status_code=409,detail="System-Hilfskonfiguration bleibt geschützt")
    return templates.TemplateResponse(request,"vhosts_delete.html",{"user":user,
             "file":file,"revision":rev,"servers":sorted(set(names))})


@app.post("/vhosts/delete")
def vhosts_delete(file:str=Form(...),revision:str=Form(...),confirm:str=Form(...),
                  user:str=Depends(require_auth),_csrf:None=Depends(require_csrf)):
    file=file.strip()
    if confirm.strip()!=file:raise HTTPException(status_code=400,detail="Dateiname stimmt nicht überein")
    if (pathlib.Path(VHOST_DIR)/file).is_symlink():
        raise HTTPException(status_code=409,detail="VHost-Link nicht löschbar")
    path=resolve_vhost_file(file)
    if vhost_revision(path)=="new":raise HTTPException(status_code=404,detail="VHost nicht gefunden")
    if not re.search(r"(?mi)^\s*ServerName\s+",path.read_text(encoding="utf-8")):
        raise HTTPException(status_code=409,detail="Hilfskonfiguration geschützt")
    vhost_apply_transaction(file,revision,None,user,"vhost_delete")
    return RedirectResponse(url="/vhosts",status_code=303)


# ----------------------------
# Certbot / DNS Updater
# ----------------------------

@app.post("/certbot/renew")
def certbot_renew(user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    result = control_request("POST", "/v1/certbot-renew", {}, timeout=300)
    text = (str(result.get("stdout") or "") + "\n" + str(result.get("stderr") or "")).strip()
    audit_event(user, "certbot_renew", "certificates", bool(result.get("ok")), str(result.get("error") or ""))
    return render_text_page(
        "Certbot renew output",
        text or ("Renew completed; Apache reloaded." if result.get("ok") else "Renew failed."),
        status_code=200 if result.get("ok") else 400,
    )


@app.post("/dns/run")
def dns_run(user: str = Depends(require_auth), _csrf: None = Depends(require_csrf)):
    result = control_request("POST", "/v1/dns-run", {}, timeout=90)
    text = (str(result.get("stdout") or "") + "\n" + str(result.get("stderr") or "")).strip()
    audit_event(user, "dns_run", "dns_updater", bool(result.get("ok")), str(result.get("error") or ""))
    return render_text_page("DNS updater output", text, status_code=200 if result.get("ok") else 400)
