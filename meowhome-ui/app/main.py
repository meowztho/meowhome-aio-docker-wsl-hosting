import os
import time
import pathlib
import re
import subprocess
import html as html_lib
import json
from typing import Optional, Dict, Any, List, Tuple
import secrets

import docker
from docker.errors import DockerException, NotFound

from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.templating import Jinja2Templates
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse


APP_TITLE = "MeowHome UI"

PROJECT_DIR = os.getenv("MEOWHOME_PROJECT_DIR", "/meowhome")
VHOST_DIR = os.path.join(PROJECT_DIR, "apache", "vhosts")
BACKUPS_DIR = os.path.join(PROJECT_DIR, "backups")
BACKUP_TOOL = os.path.join(PROJECT_DIR, "tools", "backup", "backup.sh")
CORE_TOOL = os.path.join(PROJECT_DIR, "tools", "meowhome.py")
ENV_PATH = os.path.join(PROJECT_DIR, ".env")

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

security = HTTPBasic()
templates = Jinja2Templates(directory=str(pathlib.Path(__file__).parent / "templates"))

app = FastAPI(title=APP_TITLE)


def require_auth(creds: HTTPBasicCredentials = Depends(security)) -> str:
    ok_user = secrets.compare_digest(creds.username, UI_USER)
    ok_pass = secrets.compare_digest(creds.password, UI_PASS)
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Unauthorized", headers={"WWW-Authenticate": "Basic"})
    return creds.username


def get_docker_client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except DockerException as e:
        raise HTTPException(status_code=500, detail=f"Docker nicht erreichbar: {e}")


def sh(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = 120,
    input_text: Optional[str] = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=timeout,
        check=False,
    )


def compose(cmd_args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    probe = sh(["docker", "compose", "version"], cwd=PROJECT_DIR, timeout=15)
    if probe.returncode == 0:
        return sh(["docker", "compose"] + cmd_args, cwd=PROJECT_DIR, timeout=timeout)
    return sh(["docker-compose"] + cmd_args, cwd=PROJECT_DIR, timeout=timeout)


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


def container_by_name(dc: docker.DockerClient, name: str):
    if name not in ALLOWED_CONTAINERS:
        raise HTTPException(status_code=403, detail="Container ist nicht Teil des MeowHome-Vertrags")
    try:
        return dc.containers.get(name)
    except NotFound:
        raise HTTPException(status_code=404, detail=f"Container nicht gefunden: {name}")


def tail_logs(dc: docker.DockerClient, name: str, lines: int = 200) -> str:
    c = container_by_name(dc, name)
    try:
        data = c.logs(tail=lines)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[log error] {e}"


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
    if not os.path.isfile(CORE_TOOL):
        raise HTTPException(status_code=500, detail=f"MeowHome Core-Tool fehlt: {CORE_TOOL}")
    res = sh(["python3", CORE_TOOL, "--project", PROJECT_DIR, "repair-control-plane", "--json"], cwd=PROJECT_DIR, timeout=30)
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
    test = sh(["docker", "exec", "meowhome_apache", "apachectl", "-t"], timeout=30)
    if test.returncode != 0:
        return {"ok": False, "step": "apachectl -t", "stdout": test.stdout, "stderr": test.stderr}

    reloadp = sh(["docker", "exec", "meowhome_apache", "apachectl", "-k", "graceful"], timeout=30)
    if reloadp.returncode != 0:
        restart = sh(["docker", "restart", "meowhome_apache"], timeout=60)
        return {
            "ok": restart.returncode == 0,
            "step": "docker restart fallback",
            "stdout": "\n".join(x for x in (reloadp.stdout, restart.stdout) if x),
            "stderr": "\n".join(x for x in (reloadp.stderr, restart.stderr) if x),
        }

    return {"ok": True, "step": "apachectl -k graceful", "stdout": reloadp.stdout, "stderr": reloadp.stderr}


def list_meowhome_containers(dc: docker.DockerClient) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in dc.containers.list(all=True):
        if c.name not in ALLOWED_CONTAINERS:
            continue
        attrs = getattr(c, "attrs", {}) or {}
        state = (attrs.get("State") or {})
        health = ""
        try:
            health = (state.get("Health") or {}).get("Status", "") or ""
        except Exception:
            health = ""
        image = ""
        try:
            image = (getattr(c.image, "tags", None) or [""])[0]
        except Exception:
            image = ""
        started_at = state.get("StartedAt", "") or ""
        restart_count = attrs.get("RestartCount", "")
        out.append({
            "name": c.name,
            "status": c.status,
            "health": health,
            "image": image,
            "started_at": started_at,
            "restart_count": restart_count,
        })
    out.sort(key=lambda x: x["name"])
    return out


def docker_ok(dc: docker.DockerClient) -> Tuple[bool, str]:
    try:
        dc.ping()
        return True, "ok"
    except Exception as e:
        return False, str(e)


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
    if not os.path.exists(BACKUP_TOOL):
        raise HTTPException(status_code=500, detail=f"Backup-Tool fehlt: {BACKUP_TOOL}")
    if not os.access(BACKUP_TOOL, os.X_OK):
        raise HTTPException(status_code=500, detail=f"Backup-Tool ist nicht ausfuehrbar: chmod +x {BACKUP_TOOL}")


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


def mask_value(key: str, value: str) -> str:
    if key in SECRET_KEYS and value:
        return "********"
    return value


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, user: str = Depends(require_auth)):
    dc = get_docker_client()
    ok, msg = docker_ok(dc)
    containers = list_meowhome_containers(dc)

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "containers": containers,
        "project_dir": PROJECT_DIR,
        "docker_ok": ok,
        "docker_msg": msg,
    })


@app.post("/container/{name}/action")
def container_action(
    name: str,
    action: str = Form(...),
    user: str = Depends(require_auth)
):
    if name == "meowhome_ui":
        raise HTTPException(status_code=400, detail="Die UI verwaltet ihren eigenen Container nicht; nutze docker compose vom Host.")
    dc = get_docker_client()
    c = container_by_name(dc, name)

    action = action.strip().lower()
    if action == "start":
        c.start()
    elif action == "stop":
        c.stop(timeout=20)
    elif action == "restart":
        c.restart(timeout=20)
    else:
        raise HTTPException(status_code=400, detail="Unknown action")

    return RedirectResponse(url="/", status_code=303)


@app.get("/container/{name}/logs", response_class=HTMLResponse)
def show_logs(request: Request, name: str, lines: int = 200, user: str = Depends(require_auth)):
    dc = get_docker_client()
    text = tail_logs(dc, name, lines=lines)
    return templates.TemplateResponse("logs.html", {
        "request": request,
        "user": user,
        "name": name,
        "lines": lines,
        "logtext": text,
    })


@app.post("/compose/action")
def compose_action(
    action: str = Form(...),
    user: str = Depends(require_auth)
):
    action = action.strip().lower()
    if action == "up":
        res = compose(["up", "-d"] + RUNTIME_SERVICES, timeout=600)
    elif action == "pull":
        res = compose(["pull"], timeout=600)
    elif action == "build":
        res = compose(["build", "--pull"], timeout=900)
    elif action == "recreate":
        res = compose(["up", "-d", "--force-recreate"] + RUNTIME_SERVICES, timeout=900)
    else:
        raise HTTPException(status_code=400, detail="Unknown compose action")

    return render_text_page(
        "Compose output",
        f"{res.stdout}\n{res.stderr}",
        status_code=200 if res.returncode == 0 else 400,
    )


# ----------------------------
# Health Check
# ----------------------------

@app.get("/health", response_class=HTMLResponse)
def health_page(request: Request, user: str = Depends(require_auth)):
    dc = get_docker_client()
    ok, msg = docker_ok(dc)
    containers = list_meowhome_containers(dc)

    return templates.TemplateResponse("health.html", {
        "request": request,
        "user": user,
        "docker_ok": ok,
        "docker_msg": msg,
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
    return templates.TemplateResponse("backup.html", {
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
    user: str = Depends(require_auth)
):
    ensure_backup_tool()
    backups_before = {b["name"] for b in list_backups()}

    args = [BACKUP_TOOL]
    if with_htdocs and with_htdocs.strip().lower() in ("1", "true", "yes", "on"):
        args.append("--with-htdocs")

    res = sh(args, cwd=PROJECT_DIR, timeout=3600)
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
        return templates.TemplateResponse("backup.html", {
            "request": request,
            "user": user,
            "backups": backups,
            "last_output": out if out else "Backup fehlgeschlagen (keine Ausgabe).",
            "last_file": "",
        })

    return templates.TemplateResponse("backup.html", {
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

    return templates.TemplateResponse("setup.html", {
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

    return templates.TemplateResponse("setup.html", {
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

def meowftp_py() -> str:
    p = os.path.join(PROJECT_DIR, "tools", "ftp", "meowftp.py")
    if not os.path.exists(p):
        raise HTTPException(status_code=500, detail=f"meowftp.py nicht gefunden: {p}")
    return p


def ftp_run(args: List[str], *, timeout: int = 60, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    return sh(["python3", meowftp_py()] + args, cwd=PROJECT_DIR, timeout=timeout, input_text=input_text)


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
    resp = templates.TemplateResponse("ftp.html", {
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
        return error
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/access")
def ftp_access(
    username: str = Form(...),
    domains: Optional[List[str]] = Form(None),
    allow_all: Optional[str] = Form(None),
    user: str = Depends(require_auth),
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
        return error
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/passwd")
def ftp_passwd(
    username: str = Form(...),
    password: str = Form(...),
    user: str = Depends(require_auth),
):
    username = username.strip()
    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="ungueltiger FTP username")
    if not password:
        raise HTTPException(status_code=400, detail="Passwort darf nicht leer sein")
    res = ftp_run(["passwd", username, "--password-stdin"], input_text=password + "\n")
    error = ftp_apply_or_error("=== passwd ===", res)
    if error:
        return error
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/del")
def ftp_del(username: str = Form(...), user: str = Depends(require_auth)):
    username = username.strip()
    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="ungueltiger FTP username")
    res = ftp_run(["del", username])
    error = ftp_apply_or_error("=== delete ===", res)
    if error:
        return error
    return RedirectResponse(url="/ftp", status_code=303)


@app.post("/ftp/enable")
def ftp_enable(
    username: str = Form(...),
    enabled: str = Form(...),
    user: str = Depends(require_auth),
):
    username = username.strip()
    if not FTP_USERNAME_RE.fullmatch(username):
        raise HTTPException(status_code=400, detail="ungueltiger FTP username")
    cmd = "enable" if enabled.strip().lower() in ("1", "true", "yes", "on") else "disable"
    res = ftp_run([cmd, username])
    error = ftp_apply_or_error(f"=== {cmd} ===", res)
    if error:
        return error
    return RedirectResponse(url="/ftp", status_code=303)


# ----------------------------
# VHost Management
# ----------------------------

@app.get("/vhosts", response_class=HTMLResponse)
def vhosts(request: Request, user: str = Depends(require_auth)):
    ensure_vhost_control_plane_metadata()
    p = pathlib.Path(VHOST_DIR)
    files = []
    if p.exists():
        for f in p.glob("*.conf"):
            files.append(f.name)
    files.sort()
    return templates.TemplateResponse("vhosts.html", {
        "request": request,
        "user": user,
        "files": files,
    })


@app.get("/vhosts/edit", response_class=HTMLResponse)
def vhosts_edit(request: Request, file: str, user: str = Depends(require_auth)):
    ensure_vhost_control_plane_metadata()
    file = file.strip()
    full_path = resolve_vhost_file(file)

    content = ""
    if full_path.exists():
        content = full_path.read_text(encoding="utf-8", errors="replace")
    return templates.TemplateResponse("vhosts_edit.html", {
        "request": request,
        "user": user,
        "file": file,
        "content": content,
    })


@app.post("/vhosts/save")
def vhosts_save(
    file: str = Form(...),
    content: str = Form(...),
    user: str = Depends(require_auth)
):
    ensure_vhost_control_plane_metadata()
    file = file.strip()
    full_path = resolve_vhost_file(file)

    dependency_error = validate_vhost_managed_dependencies(content)
    if dependency_error:
        return render_text_page(
            "VHost dependency missing",
            dependency_error + "\n\nRun the current MeowHome installer/upgrade before enabling that directive.",
            back_url=f"/vhosts/edit?file={file}",
            status_code=400,
        )

    full = str(full_path)
    bak = backup_file(full)
    safe_write_file(full, content, mode=0o664)

    result = apache_test_and_reload()
    if not result.get("ok"):
        if bak and os.path.exists(bak):
            pathlib.Path(full).write_bytes(pathlib.Path(bak).read_bytes())
            set_host_file_metadata(pathlib.Path(full), 0o664)
        details = "\n".join([
            "Apache config test failed. Changes were rolled back.",
            "",
            result.get("stdout", ""),
            result.get("stderr", ""),
        ]).strip()
        return render_text_page("VHost save failed", details, back_url="/vhosts", status_code=400)

    return RedirectResponse(url="/vhosts", status_code=303)


@app.post("/vhosts/delete")
def vhosts_delete(
    file: str = Form(...),
    user: str = Depends(require_auth)
):
    ensure_vhost_control_plane_metadata()
    file = file.strip()
    full_path = resolve_vhost_file(file)

    if not full_path.exists():
        return render_text_page(
            "VHost delete failed",
            f"Datei nicht gefunden: {file}",
            back_url="/vhosts",
            status_code=404
        )

    full = str(full_path)
    bak = backup_file(full)

    try:
        full_path.unlink()
    except OSError as e:
        return render_text_page(
            "VHost delete failed",
            f"Datei konnte nicht geloescht werden: {e}",
            back_url="/vhosts",
            status_code=400
        )

    result = apache_test_and_reload()
    if not result.get("ok"):
        if bak and os.path.exists(bak):
            pathlib.Path(full).write_bytes(pathlib.Path(bak).read_bytes())
            set_host_file_metadata(pathlib.Path(full), 0o664)
        details = "\n".join([
            "Apache config test failed. Deletion was rolled back.",
            "",
            result.get("stdout", ""),
            result.get("stderr", ""),
        ]).strip()
        return render_text_page("VHost delete failed", details, back_url="/vhosts", status_code=400)

    return RedirectResponse(url="/vhosts", status_code=303)


# ----------------------------
# Certbot / DNS Updater
# ----------------------------

@app.post("/certbot/renew")
def certbot_renew(user: str = Depends(require_auth)):
    res = sh(["docker", "exec", "meowhome_certbot", "certbot", "renew", "--non-interactive"], timeout=180)
    text = (res.stdout + "\n" + res.stderr).strip()
    if res.returncode != 0:
        return render_text_page("Certbot renew failed", text, status_code=400)

    reload_result = apache_test_and_reload()
    if not reload_result.get("ok"):
        details = "\n".join([
            text,
            "",
            "Certificate renewal completed, but Apache reload failed.",
            reload_result.get("stdout", ""),
            reload_result.get("stderr", ""),
        ]).strip()
        return render_text_page("Certbot renew warning", details, status_code=500)
    return render_text_page("Certbot renew output", text or "Renew completed; Apache reloaded.")


@app.post("/dns/run")
def dns_run(user: str = Depends(require_auth)):
    res = sh(["docker", "restart", "meowhome_dns_updater"], timeout=60)
    text = (res.stdout + "\n" + res.stderr).strip()
    return render_text_page("DNS updater output", text)
