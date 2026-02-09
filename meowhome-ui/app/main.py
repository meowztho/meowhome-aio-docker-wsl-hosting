import os
import time
import pathlib
import subprocess
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

UI_USER = os.getenv("MEOWHOME_UI_USER", "admin")
UI_PASS = os.getenv("MEOWHOME_UI_PASS", "admin")

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


def html_autorefresh(
    url: str,
    seconds: int = 2,
    title: str = "OK",
    body: str = "Fertig. Aktualisiere Ansicht..."
) -> HTMLResponse:
    ts = int(time.time())
    target = f"{url}{'&' if '?' in url else '?'}ts={ts}"

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="cache-control" content="no-store" />
  <meta http-equiv="pragma" content="no-cache" />
  <meta http-equiv="expires" content="0" />
  <title>{title}</title>
</head>
<body>
  <p>{body}</p>
  <p>Weiterleitung in {seconds} Sekunden...</p>
  <p><a href="{target}">Wenn nichts passiert: hier klicken</a></p>
  <script>
    setTimeout(function() {{
      window.location.replace("{target}");
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
        raise HTTPException(status_code=500, detail=f"Backup-Tool ist nicht ausführbar: chmod +x {BACKUP_TOOL}")


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
        raise HTTPException(status_code=400, detail="Ungültiger Dateiname")
    if not name.startswith("meowhome-backup-") or not name.endswith(".tar.gz"):
        raise HTTPException(status_code=400, detail="Ungültiger Backup-Name")
    return name


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

    return HTMLResponse(f"<pre>{res.stdout}\n{res.stderr}</pre><p><a href='/'>Back</a></p>")


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

    res_add = sh(["python", meowftp_py(), "add", username, home_rel, password], cwd=PROJECT_DIR, timeout=60)
    res_home = sh(["python", meowftp_py(), "home", username, home_rel], cwd=PROJECT_DIR, timeout=60)
    res_apply = sh(["python", meowftp_py(), "apply"], cwd=PROJECT_DIR, timeout=600)

    text = "\n".join([
        "=== add ===", res_add.stdout, res_add.stderr,
        "=== home ===", res_home.stdout, res_home.stderr,
        "=== apply ===", res_apply.stdout, res_apply.stderr,
    ]).strip()

    if res_add.returncode != 0 or res_home.returncode != 0 or res_apply.returncode != 0:
        return HTMLResponse(f"<pre>{text}</pre><p><a href='/ftp'>Back</a></p>", status_code=400)

    return html_autorefresh("/ftp", seconds=2, title="FTP User hinzugefügt", body="User wurde gespeichert und apply wurde ausgeführt.")


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
        return HTMLResponse(f"<pre>{text}</pre><p><a href='/ftp'>Back</a></p>", status_code=400)

    return html_autorefresh("/ftp", seconds=2, title="FTP User gelöscht", body="User wurde gelöscht und apply wurde ausgeführt.")


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
        return HTMLResponse(f"<pre>{text}</pre><p><a href='/ftp'>Back</a></p>", status_code=400)

    return html_autorefresh("/ftp", seconds=2, title="FTP User aktualisiert", body="Status wurde geändert und apply wurde ausgeführt.")


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
    if not file.endswith(".conf"):
        raise HTTPException(status_code=400, detail="Nur .conf erlaubt")
    
    # Path traversal prevention: resolve() ensures path is within VHOST_DIR
    try:
        vhost_base = pathlib.Path(VHOST_DIR).resolve()
        full_path = (vhost_base / file).resolve()
        if not str(full_path).startswith(str(vhost_base)):
            raise HTTPException(status_code=403, detail="Zugriff verweigert")
    except Exception as e:
        raise HTTPException(status_code=403, detail="Ungültiger Dateipfad")
    
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
    if not file.endswith(".conf"):
        raise HTTPException(status_code=400, detail="Nur .conf erlaubt")

    # Path traversal prevention
    try:
        vhost_base = pathlib.Path(VHOST_DIR).resolve()
        full_path = (vhost_base / file).resolve()
        if not str(full_path).startswith(str(vhost_base)):
            raise HTTPException(status_code=403, detail="Zugriff verweigert")
    except Exception as e:
        raise HTTPException(status_code=403, detail="Ungültiger Dateipfad")
    
    full = str(full_path)
    bak = backup_file(full)
    safe_write_file(full, content)

    result = apache_test_and_reload()
    if not result.get("ok"):
        if bak and os.path.exists(bak):
            pathlib.Path(full).write_bytes(pathlib.Path(bak).read_bytes())
        return HTMLResponse(
            "<h3>Fehler: Apache Config Test fehlgeschlagen, Änderung zurückgerollt</h3>"
            f"<pre>{result.get('stdout','')}\n{result.get('stderr','')}</pre>"
            "<p><a href='/vhosts'>Back</a></p>",
            status_code=400
        )

    return RedirectResponse(url="/vhosts", status_code=303)


# ----------------------------
# Certbot / DNS Updater
# ----------------------------

@app.post("/certbot/renew")
def certbot_renew(user: str = Depends(require_auth)):
    res = sh(["docker", "exec", "meowhome_certbot", "sh", "-lc", "certbot renew --non-interactive || true"], timeout=180)
    text = (res.stdout + "\n" + res.stderr).strip()
    return HTMLResponse(f"<pre>{text}</pre><p><a href='/'>Back</a></p>")


@app.post("/dns/run")
def dns_run(user: str = Depends(require_auth)):
    res = sh(["docker", "restart", "meowhome_dns_updater"], timeout=60)
    text = (res.stdout + "\n" + res.stderr).strip()
    return HTMLResponse(f"<pre>{text}</pre><p><a href='/'>Back</a></p>")
