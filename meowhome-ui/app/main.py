import os
import time
import pathlib
import re
import subprocess
import html as html_lib
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
ENV_PATH = os.path.join(PROJECT_DIR, ".env")

UI_USER = os.getenv("MEOWHOME_UI_USER", "admin")
UI_PASS = os.getenv("MEOWHOME_UI_PASS", "admin")

SETUP_KEYS = [
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


def sh(cmd: List[str], cwd: Optional[str] = None, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def compose(cmd_args: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
    # stabil: wir nutzen docker-compose (standalone)
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


def safe_write_file(path: str, content: str) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def backup_file(path: str) -> Optional[str]:
    p = pathlib.Path(path)
    if not p.exists():
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = p.with_suffix(p.suffix + f".bak.{ts}")
    backup.write_bytes(p.read_bytes())
    return str(backup)


def apache_test_and_reload() -> Dict[str, Any]:
    test = sh(["docker", "exec", "meowhome_apache", "apachectl", "-t"], timeout=30)
    if test.returncode != 0:
        return {"ok": False, "step": "apachectl -t", "stdout": test.stdout, "stderr": test.stderr}

    reloadp = sh(["docker", "exec", "meowhome_apache", "apachectl", "-k", "graceful"], timeout=30)
    if reloadp.returncode != 0:
        sh(["docker", "restart", "meowhome_apache"], timeout=60)
        return {"ok": True, "step": "docker restart fallback", "stdout": reloadp.stdout, "stderr": reloadp.stderr}

    return {"ok": True, "step": "apachectl -k graceful", "stdout": reloadp.stdout, "stderr": reloadp.stderr}


def list_meowhome_containers(dc: docker.DockerClient) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in dc.containers.list(all=True):
        if not c.name.startswith("meowhome_"):
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
    # Erhaelt Kommentare/Reihenfolge bestmoeglich, ersetzt nur KEY= Zeilen oder haengt an.
    existing_keys = set()
    out: List[str] = []

    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            k = line.split("=", 1)[0].strip()
            if k in updates:
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
    if not os.path.exists(ENV_PATH):
        return None
    ts = time.strftime("%Y%m%d-%H%M%S")
    bak = ENV_PATH + f".bak.{ts}"
    pathlib.Path(bak).write_bytes(pathlib.Path(ENV_PATH).read_bytes())
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
        res = compose(["up", "-d"], timeout=600)
    elif action == "pull":
        res = compose(["pull"], timeout=600)
    elif action == "build":
        res = compose(["build", "--pull"], timeout=900)
    elif action == "recreate":
        res = compose(["up", "-d", "--force-recreate"], timeout=900)
    else:
        raise HTTPException(status_code=400, detail="Unknown compose action")

    return render_text_page("Compose output", f"{res.stdout}\n{res.stderr}")


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
    p = pathlib.Path(BACKUPS_DIR) / name
    if not p.exists():
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
    lines = env_read_raw()
    updates: Dict[str, str] = {}

    # Validation / normalization
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

    # Page neu rendern (maskiert)
    env_after = env_parse(new_lines)
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
        "note": "Gespeichert. Aenderungen werden beim naechsten docker compose recreate wirksam (auch fuer UI Login-Daten).",
    })


@app.post("/setup/recreate-ui")
def setup_recreate_ui(user: str = Depends(require_auth)):
    res = compose(["up", "-d", "--force-recreate", "ui"], timeout=900)
    text = (res.stdout + "\n" + res.stderr).strip()
    if res.returncode != 0:
        return render_text_page(
            "UI recreate failed",
            text or "docker compose up -d --force-recreate ui fehlgeschlagen.",
            back_url="/setup",
            status_code=500,
        )
    return render_text_page("UI recreate output", text or "UI wurde neu erstellt.", back_url="/setup")


# ----------------------------
# FTP User Management (nutzt tools/ftp/meowftp.py)
# ----------------------------

def meowftp_py() -> str:
    p = os.path.join(PROJECT_DIR, "tools", "ftp", "meowftp.py")
    if not os.path.exists(p):
        raise HTTPException(status_code=500, detail=f"meowftp.py nicht gefunden: {p}")
    return p


@app.get("/ftp", response_class=HTMLResponse)
def ftp_page(request: Request, user: str = Depends(require_auth)):
    res = sh(["python", meowftp_py(), "list"], cwd=PROJECT_DIR, timeout=60)
    resp = templates.TemplateResponse("ftp.html", {
        "request": request,
        "user": user,
        "list_out": (res.stdout + "\n" + res.stderr).strip(),
    })
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.post("/ftp/add")
def ftp_add(
    username: str = Form(...),
    password: str = Form(...),
    home_rel: str = Form(""),
    allow_all: Optional[str] = Form(None),
    user: str = Depends(require_auth)
):
    username = username.strip()
    home_rel = home_rel.strip()

    if not username:
        raise HTTPException(status_code=400, detail="username leer")
    
    # Input validation: username = alphanumeric, underscore, hyphen
    if not all(c.isalnum() or c in "_-" for c in username):
        raise HTTPException(status_code=400, detail="username nur alphanumeric, _, - erlaubt")
    if len(username) > 32:
        raise HTTPException(status_code=400, detail="username zu lang (max 32 chars)")
    
    # home_rel validation (if provided): only relative paths allowed
    if home_rel:
        if ".." in home_rel:
            raise HTTPException(status_code=400, detail="home_rel: parent directory (..) nicht erlaubt")
        if home_rel.startswith("/"):
            raise HTTPException(status_code=400, detail="home_rel: absolute Pfade (/) nicht erlaubt, nur relative")
        if any(c.isspace() for c in home_rel):
            raise HTTPException(status_code=400, detail="home_rel: keine Leerzeichen erlaubt")
    else:
        allow_all_enabled = (allow_all or "").strip().lower() in ("1", "true", "yes", "on")
        if not allow_all_enabled:
            raise HTTPException(
                status_code=400,
                detail="Leeres home_rel bedeutet Zugriff auf alles unter htdocs. Bitte Checkbox 'Vollzugriff' aktivieren.",
            )

    add_cmd = ["python", meowftp_py(), "add", username, home_rel, password]
    if not home_rel:
        add_cmd.append("--allow-all")
    res_add = sh(add_cmd, cwd=PROJECT_DIR, timeout=60)
    res_apply = sh(["python", meowftp_py(), "apply"], cwd=PROJECT_DIR, timeout=600)

    text = "\n".join([
        "=== add ===", res_add.stdout, res_add.stderr,
        "=== apply ===", res_apply.stdout, res_apply.stderr,
    ]).strip()

    if res_add.returncode != 0 or res_apply.returncode != 0:
        return render_text_page("FTP command failed", text, back_url="/ftp", status_code=400)

    return html_autorefresh("/ftp", seconds=2, title="FTP User hinzugefuegt", body="User wurde gespeichert und apply wurde ausgefuehrt.")


@app.post("/ftp/del")
def ftp_del(
    username: str = Form(...),
    user: str = Depends(require_auth)
):
    username = username.strip()
    
    # Input validation
    if not username:
        raise HTTPException(status_code=400, detail="username leer")
    if not all(c.isalnum() or c in "_-" for c in username):
        raise HTTPException(status_code=400, detail="username nur alphanumeric, _, - erlaubt")
    if len(username) > 32:
        raise HTTPException(status_code=400, detail="username zu lang (max 32 chars)")
    res_del = sh(["python", meowftp_py(), "del", username], cwd=PROJECT_DIR, timeout=60)
    res_apply = sh(["python", meowftp_py(), "apply"], cwd=PROJECT_DIR, timeout=600)

    text = "\n".join([
        "=== del ===", res_del.stdout, res_del.stderr,
        "=== apply ===", res_apply.stdout, res_apply.stderr,
    ]).strip()

    if res_del.returncode != 0 or res_apply.returncode != 0:
        return render_text_page("FTP command failed", text, back_url="/ftp", status_code=400)

    return html_autorefresh("/ftp", seconds=2, title="FTP User geloescht", body="User wurde geloescht und apply wurde ausgefuehrt.")


@app.post("/ftp/enable")
def ftp_enable(
    username: str = Form(...),
    enabled: str = Form(...),
    user: str = Depends(require_auth)
):
    username = username.strip()
    enabled = enabled.strip().lower()
    
    # Input validation
    if not username:
        raise HTTPException(status_code=400, detail="username leer")
    if not all(c.isalnum() or c in "_-" for c in username):
        raise HTTPException(status_code=400, detail="username nur alphanumeric, _, - erlaubt")
    if len(username) > 32:
        raise HTTPException(status_code=400, detail="username zu lang (max 32 chars)")

    cmd = "enable" if enabled in ("1", "true", "yes", "on") else "disable"
    res = sh(["python", meowftp_py(), cmd, username], cwd=PROJECT_DIR, timeout=60)
    res_apply = sh(["python", meowftp_py(), "apply"], cwd=PROJECT_DIR, timeout=600)

    text = "\n".join([
        f"=== {cmd} ===", res.stdout, res.stderr,
        "=== apply ===", res_apply.stdout, res_apply.stderr,
    ]).strip()

    if res.returncode != 0 or res_apply.returncode != 0:
        return render_text_page("FTP command failed", text, back_url="/ftp", status_code=400)

    return html_autorefresh("/ftp", seconds=2, title="FTP User aktualisiert", body="Status wurde geaendert und apply wurde ausgefuehrt.")


# ----------------------------
# VHost Management
# ----------------------------

@app.get("/vhosts", response_class=HTMLResponse)
def vhosts(request: Request, user: str = Depends(require_auth)):
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
    file = file.strip()
    full_path = resolve_vhost_file(file)

    full = str(full_path)
    bak = backup_file(full)
    safe_write_file(full, content)

    result = apache_test_and_reload()
    if not result.get("ok"):
        if bak and os.path.exists(bak):
            pathlib.Path(full).write_bytes(pathlib.Path(bak).read_bytes())
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
    res = sh(["docker", "exec", "meowhome_certbot", "sh", "-lc", "certbot renew --non-interactive || true"], timeout=180)
    text = (res.stdout + "\n" + res.stderr).strip()
    return render_text_page("Certbot renew output", text)


@app.post("/dns/run")
def dns_run(user: str = Depends(require_auth)):
    res = sh(["docker", "restart", "meowhome_dns_updater"], timeout=60)
    text = (res.stdout + "\n" + res.stderr).strip()
    return render_text_page("DNS updater output", text)
