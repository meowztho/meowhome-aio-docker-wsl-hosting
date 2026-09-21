#!/usr/bin/env python3
from __future__ import annotations

import getpass
import json
import os
import pathlib
import re
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from typing import Any, Tuple

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(BASE, "ftp", "users.sqlite")
HTDOCS = os.path.join(BASE, "htdocs")
ENV_PATH = os.path.join(BASE, ".env")
COMPOSE_OVERRIDE_PATH = os.path.join(BASE, "docker-compose.override.yml")
GENERATED_OVERRIDE_MARKER = "# MEOWHOME-GENERATED: ftp-domain-views-v1"
FTP_VIEW_ROOT = "/srv/meowftp/views"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")


def sh(cmd: list[str], *, cwd: str | None = None) -> None:
    subprocess.check_call(cmd, cwd=cwd)


def sh_out(cmd: list[str], *, input_text: str | None = None) -> str:
    return subprocess.check_output(cmd, input=input_text, text=True).strip()


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def read_env_value(key: str, default: str = "") -> str:
    if not os.path.exists(ENV_PATH):
        return default
    value = default
    with open(ENV_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == key:
                value = _strip_quotes(v)
    return value


def host_uid_gid() -> Tuple[int, int]:
    uid = int(read_env_value("PUID", read_env_value("FTP_HOST_UID", "1000")) or "1000")
    gid = int(read_env_value("PGID", read_env_value("FTP_HOST_GID", "1000")) or "1000")
    return uid, gid


def _ensure_db_owner() -> None:
    try:
        os.chmod(DB_PATH, 0o600)
        if os.geteuid() == 0:
            uid, gid = host_uid_gid()
            os.chown(DB_PATH, uid, gid)
    except OSError:
        pass


def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA foreign_keys=ON")
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          pass_hash TEXT NOT NULL,
          home_rel TEXT NOT NULL DEFAULT '',
          enabled INTEGER NOT NULL DEFAULT 1
        )
        """
    )
    columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
    if "access_mode" not in columns:
        con.execute("ALTER TABLE users ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'legacy'")
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS user_domains (
          username TEXT NOT NULL,
          domain TEXT NOT NULL,
          PRIMARY KEY (username, domain),
          FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        )
        """
    )
    con.execute(
        """
        UPDATE users
           SET access_mode = CASE WHEN home_rel = '' THEN 'all' ELSE 'path' END
         WHERE access_mode IS NULL OR access_mode = '' OR access_mode = 'legacy'
        """
    )
    con.commit()
    _ensure_db_owner()
    return con


def validate_username(username: str) -> str:
    value = username.strip()
    if not USERNAME_RE.fullmatch(value):
        raise SystemExit("Username muss 1-32 Zeichen lang sein und darf nur A-Z, a-z, 0-9, _ und - enthalten.")
    return value


def hash_pw_sha512_crypt(password: str) -> str:
    if not password:
        raise SystemExit("Passwort darf nicht leer sein.")
    out = sh_out(["openssl", "passwd", "-6", "-stdin"], input_text=password + "\n")
    if not out.startswith("$6$"):
        raise RuntimeError("Password hash generation failed.")
    return out


def prompt_password() -> str:
    p1 = getpass.getpass("Passwort: ")
    p2 = getpass.getpass("Passwort (wiederholen): ")
    if not p1 or p1 != p2:
        raise SystemExit("Passwoerter stimmen nicht ueberein oder sind leer.")
    return p1


def confirm(msg: str) -> None:
    ans = input(f"{msg} (yes/no): ").strip().lower()
    if ans != "yes":
        raise SystemExit("Abgebrochen.")


def require_all_access_confirmation(home_rel: str, allow_all: bool = False) -> None:
    if home_rel or allow_all:
        return
    confirm("home_rel ist leer -> User sieht ALLE Domain-Ordner unter htdocs. Fortfahren?")


def normalize_home_rel(home_rel: str) -> str:
    raw = (home_rel or "").strip().replace("\\", "/")
    if raw in ("", ".", "./"):
        return ""
    if raw.startswith("/"):
        raise SystemExit("Ungueltiger Pfad (absolute Pfade nicht erlaubt).")
    parts = [part for part in raw.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise SystemExit("Ungueltiger Pfad (.. nicht erlaubt).")
    normalized = "/".join(parts)
    target = (pathlib.Path(HTDOCS).resolve() / normalized).resolve()
    try:
        target.relative_to(pathlib.Path(HTDOCS).resolve())
    except ValueError:
        raise SystemExit("Ungueltiger Pfad ausserhalb von htdocs.")
    return normalized


def available_domains() -> list[str]:
    root = pathlib.Path(HTDOCS)
    if not root.is_dir():
        return []
    domains: list[str] = []
    for child in root.iterdir():
        try:
            if child.is_dir() and not child.name.startswith("."):
                domains.append(child.name)
        except OSError:
            continue
    return sorted(domains, key=str.casefold)


def normalize_domain(domain: str, *, require_exists: bool = True) -> str:
    value = (domain or "").strip()
    if not value or value in {".", ".."} or "/" in value or "\\" in value or "\x00" in value:
        raise SystemExit(f"Ungueltige Domain/Top-Level-Ordnerzuweisung: {domain!r}")
    target = pathlib.Path(HTDOCS) / value
    if require_exists and not target.is_dir():
        raise SystemExit(f"Domain-Ordner existiert nicht unter htdocs/: {value}")
    try:
        target.resolve().relative_to(pathlib.Path(HTDOCS).resolve())
    except ValueError:
        raise SystemExit(f"Ungueltige Domain ausserhalb von htdocs/: {value}")
    return value


def normalize_domains(domains: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in domains:
        value = normalize_domain(raw)
        if value not in seen:
            seen.add(value)
            out.append(value)
    if not out:
        raise SystemExit("Mindestens eine Domain muss zugewiesen werden.")
    return out


def ensure_home_dir(home_rel: str) -> None:
    if home_rel == "":
        return
    path = os.path.join(HTDOCS, home_rel)
    os.makedirs(path, exist_ok=True)
    uid, gid = host_uid_gid()
    try:
        os.chown(path, uid, gid)
        os.chmod(path, 0o775)
    except PermissionError:
        pass


def _domains_for(con: sqlite3.Connection, username: str) -> list[str]:
    return [row[0] for row in con.execute(
        "SELECT domain FROM user_domains WHERE username=? ORDER BY domain COLLATE NOCASE",
        (username,),
    )]


def _user_records(enabled_only: bool = False) -> list[dict[str, Any]]:
    where = " WHERE enabled=1" if enabled_only else ""
    with closing(db()) as con:
        rows = list(con.execute(
            f"SELECT username, pass_hash, home_rel, enabled, access_mode FROM users{where} ORDER BY username"
        ))
        result = []
        for username, pass_hash, home_rel, enabled, access_mode in rows:
            result.append({
                "username": username,
                "pass_hash": pass_hash,
                "home_rel": home_rel,
                "enabled": bool(enabled),
                "access_mode": access_mode,
                "domains": _domains_for(con, username),
            })
        return result


def _access_label(user: dict[str, Any]) -> str:
    mode = user["access_mode"]
    if mode == "all":
        return "all domains"
    if mode == "domains":
        domains = user["domains"]
        return ", ".join(domains) if domains else "INVALID: no domains"
    return user["home_rel"] or "all domains"


def cmd_list(as_json: bool = False) -> None:
    users = _user_records()
    if as_json:
        print(json.dumps({"users": [{k: v for k, v in u.items() if k != "pass_hash"} for u in users], "available_domains": available_domains()}, ensure_ascii=False, indent=2))
        return
    if not users:
        print("Keine User vorhanden.")
        return
    print(f"{'Username':<20} {'Enabled':<8} {'Mode':<10} {'Access':<50}")
    print("-" * 92)
    for user in users:
        print(f"{user['username']:<20} {'yes' if user['enabled'] else 'no':<8} {user['access_mode']:<10} {_access_label(user):<50}")


def _clear_domains(con: sqlite3.Connection, username: str) -> None:
    con.execute("DELETE FROM user_domains WHERE username=?", (username,))


def cmd_add(username: str, home_rel: str, password: str | None = None, allow_all: bool = False) -> None:
    username = validate_username(username)
    home_rel = normalize_home_rel(home_rel)
    require_all_access_confirmation(home_rel, allow_all=allow_all)
    pw = prompt_password() if password is None or str(password) == "" else str(password)
    ph = hash_pw_sha512_crypt(pw)
    ensure_home_dir(home_rel)
    mode = "all" if home_rel == "" else "path"
    with closing(db()) as con:
        con.execute(
            """
            INSERT INTO users(username, pass_hash, home_rel, enabled, access_mode)
            VALUES(?,?,?,?,?)
            ON CONFLICT(username) DO UPDATE SET
              pass_hash=excluded.pass_hash,
              home_rel=excluded.home_rel,
              enabled=1,
              access_mode=excluded.access_mode
            """,
            (username, ph, home_rel, 1, mode),
        )
        _clear_domains(con, username)
        con.commit()
    print(f"[OK] User '{username}' gespeichert ({_access_label({'access_mode': mode, 'home_rel': home_rel, 'domains': []})})")
    print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def cmd_del(username: str) -> None:
    username = validate_username(username)
    with closing(db()) as con:
        _clear_domains(con, username)
        cur = con.execute("DELETE FROM users WHERE username=?", (username,))
        con.commit()
        changed = cur.rowcount
    if changed == 0:
        print("[ERR] User nicht gefunden.")
    else:
        print(f"[OK] User '{username}' geloescht")
        print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def cmd_enable(username: str, enabled: int) -> None:
    username = validate_username(username)
    with closing(db()) as con:
        cur = con.execute("UPDATE users SET enabled=? WHERE username=?", (enabled, username))
        con.commit()
        changed = cur.rowcount
    if changed == 0:
        print("[ERR] User nicht gefunden.")
    else:
        status = "aktiviert" if enabled else "deaktiviert"
        print(f"[OK] User '{username}' {status}")
        print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def cmd_passwd(username: str, password: str | None = None) -> None:
    username = validate_username(username)
    with closing(db()) as con:
        row = con.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
        if not row:
            raise SystemExit("[ERR] User nicht gefunden.")
        pw = prompt_password() if password is None or str(password) == "" else str(password)
        ph = hash_pw_sha512_crypt(pw)
        con.execute("UPDATE users SET pass_hash=? WHERE username=?", (ph, username))
        con.commit()
    print(f"[OK] User '{username}' password updated")
    print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def cmd_home(username: str, home_rel: str, allow_all: bool = False) -> None:
    username = validate_username(username)
    home_rel = normalize_home_rel(home_rel)
    require_all_access_confirmation(home_rel, allow_all=allow_all)
    ensure_home_dir(home_rel)
    mode = "all" if home_rel == "" else "path"
    with closing(db()) as con:
        cur = con.execute(
            "UPDATE users SET home_rel=?, access_mode=? WHERE username=?",
            (home_rel, mode, username),
        )
        if cur.rowcount:
            _clear_domains(con, username)
        con.commit()
        changed = cur.rowcount
    if changed == 0:
        print("[ERR] User nicht gefunden.")
    else:
        print(f"[OK] User '{username}' access='{_access_label({'access_mode': mode, 'home_rel': home_rel, 'domains': []})}'")
        print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def cmd_assign(username: str, domains: list[str]) -> None:
    username = validate_username(username)
    normalized = normalize_domains(domains)
    with closing(db()) as con:
        if not con.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise SystemExit("[ERR] User nicht gefunden.")
        con.execute("UPDATE users SET home_rel='', access_mode='domains' WHERE username=?", (username,))
        _clear_domains(con, username)
        con.executemany(
            "INSERT INTO user_domains(username, domain) VALUES(?,?)",
            [(username, domain) for domain in normalized],
        )
        con.commit()
    print(f"[OK] User '{username}' Domains: {', '.join(normalized)}")
    print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def cmd_all(username: str) -> None:
    username = validate_username(username)
    with closing(db()) as con:
        cur = con.execute("UPDATE users SET home_rel='', access_mode='all' WHERE username=?", (username,))
        if cur.rowcount:
            _clear_domains(con, username)
        con.commit()
        changed = cur.rowcount
    if changed == 0:
        raise SystemExit("[ERR] User nicht gefunden.")
    print(f"[OK] User '{username}' hat Vollzugriff auf alle Domains.")
    print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def _compose_override_content(users: list[dict[str, Any]]) -> str | None:
    mounts: list[tuple[str, str]] = []
    for user in users:
        if user["access_mode"] != "domains":
            continue
        domains = user["domains"]
        if not domains:
            raise SystemExit(f"[ERR] FTP User '{user['username']}' hat access_mode=domains aber keine Domainzuweisung.")
        if len(domains) == 1:
            continue
        for domain in domains:
            normalize_domain(domain)
            source = f"${{MEOWHOME_HOST_PROJECT_DIR:-.}}/htdocs/{domain}"
            target = f"{FTP_VIEW_ROOT}/{user['username']}/{domain}"
            mounts.append((source, target))
    if not mounts:
        return None
    lines = [GENERATED_OVERRIDE_MARKER, "services:", "  ftp:", "    volumes:"]
    for source, target in mounts:
        lines.extend([
            "      - type: bind",
            f"        source: {json.dumps(source)}",
            f"        target: {json.dumps(target)}",
        ])
    lines.append("")
    return "\n".join(lines)


def write_compose_override(users: list[dict[str, Any]]) -> bool:
    content = _compose_override_content(users)
    path = pathlib.Path(COMPOSE_OVERRIDE_PATH)
    if path.exists():
        existing = path.read_text(encoding="utf-8", errors="replace")
        if not existing.startswith(GENERATED_OVERRIDE_MARKER):
            if content is not None:
                raise SystemExit(
                    "[ERR] docker-compose.override.yml existiert bereits und gehoert nicht MeowHome. "
                    "Multi-Domain-FTP kann diesen Benutzer-Override nicht sicher ueberschreiben."
                )
            return False
    if content is None:
        if path.exists() and path.read_text(encoding="utf-8", errors="replace").startswith(GENERATED_OVERRIDE_MARKER):
            path.unlink()
            return True
        return False
    path.write_text(content, encoding="utf-8")
    try:
        os.chmod(path, 0o644)
        if os.geteuid() == 0:
            uid, gid = host_uid_gid()
            os.chown(path, uid, gid)
    except OSError:
        pass
    return True


def docker_compose_cmd() -> list[str]:
    try:
        subprocess.check_call(
            ["docker", "compose", "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return ["docker", "compose"]
    except Exception:
        return ["docker-compose"]


def compose(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[Any]:
    return subprocess.run(docker_compose_cmd() + args, cwd=BASE, check=check)


def wait_for_container(max_wait: int = 90) -> None:
    print("[WAIT] Warte auf FTP Container...")
    last_err = ""
    for _ in range(max_wait):
        try:
            subprocess.run(
                ["docker", "exec", "meowhome_ftp", "test", "-d", "/etc/vsftpd"],
                capture_output=True,
                check=True,
                timeout=5,
            )
            print("[OK] Container ist bereit")
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as exc:
            last_err = str(exc)
            time.sleep(1)
    try:
        logs = subprocess.run(
            ["docker", "logs", "--tail", "80", "meowhome_ftp"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        print("----- meowhome_ftp logs (tail 80) -----")
        print(logs.stdout)
        print(logs.stderr)
    except Exception:
        pass
    raise SystemExit(f"[ERR] Container startet nicht korrekt (nach {max_wait}s). Last error: {last_err}")


def _local_root_for(user: dict[str, Any]) -> str:
    mode = user["access_mode"]
    if mode == "all":
        return "/var/www"
    if mode == "domains":
        domains = user["domains"]
        if not domains:
            raise SystemExit(f"[ERR] FTP User '{user['username']}' hat keine zugewiesenen Domains.")
        if len(domains) == 1:
            return f"/var/www/{domains[0]}"
        return f"{FTP_VIEW_ROOT}/{user['username']}"
    home_rel = user["home_rel"]
    return "/var/www" if not home_rel else f"/var/www/{home_rel}"


def apply() -> None:
    if os.geteuid() != 0:
        print("[WARN] apply benoetigt sudo/root")
        try:
            sudo_path = sh_out(["which", "sudo"])
        except Exception:
            sudo_path = ""
        if sudo_path:
            print("Starte erneut mit sudo...")
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        raise SystemExit("[ERR] sudo nicht verfuegbar. Bitte 'apply' als root ausfuehren.")

    print("=" * 60)
    print("MeowFTP Apply - Aktiviere User-Aenderungen")
    print("=" * 60)

    users = _user_records(enabled_only=True)
    print(f"1/8 Gefunden: {len(users)} aktive User")

    for user in users:
        if user["access_mode"] == "path":
            ensure_home_dir(user["home_rel"])
        elif user["access_mode"] == "domains":
            for domain in user["domains"]:
                normalize_domain(domain)

    print("2/8 Erzeuge FTP-Domain-View (Compose Override)...")
    changed_override = write_compose_override(users)
    if changed_override:
        print("   docker-compose.override.yml aktualisiert")

    print("3/8 Reconcile FTP Container...")
    compose(["up", "-d", "--force-recreate", "ftp"])
    wait_for_container()

    users_txt_content = "".join(f"{user['username']}\n{user['pass_hash']}\n" for user in users)
    print("4/8 Schreibe users.txt und users.db...")
    subprocess.run(
        ["docker", "exec", "-i", "meowhome_ftp", "sh", "-c", "cat > /etc/vsftpd/users.txt"],
        input=users_txt_content.encode(),
        check=True,
    )
    try:
        subprocess.run(["docker", "exec", "meowhome_ftp", "which", "db5.3_load"], capture_output=True, check=True)
        db_cmd = "db5.3_load"
    except subprocess.CalledProcessError:
        db_cmd = "db_load"
    subprocess.run(
        ["docker", "exec", "meowhome_ftp", "sh", "-c", f"cd /etc/vsftpd && rm -f users.db && {db_cmd} -T -t hash -f users.txt users.db"],
        check=True,
    )

    print("5/8 Erstelle User-Configs...")
    subprocess.run(["docker", "exec", "meowhome_ftp", "sh", "-c", "rm -f /etc/vsftpd/users.d/*"], check=True)
    for user in users:
        local_root = _local_root_for(user)
        subprocess.run(
            ["docker", "exec", "-i", "meowhome_ftp", "sh", "-c", f"cat > /etc/vsftpd/users.d/{user['username']}"],
            input=f"local_root={local_root}\n".encode(),
            check=True,
        )

    print("6/8 Setze Permissions...")
    subprocess.run(
        [
            "docker", "exec", "meowhome_ftp", "sh", "-c",
            "chown root:root /etc/vsftpd/vsftpd.conf /etc/vsftpd/users.txt /etc/vsftpd/users.db; "
            "chmod 600 /etc/vsftpd/vsftpd.conf /etc/vsftpd/users.txt /etc/vsftpd/users.db; "
            "chown root:root /etc/vsftpd/users.d; chmod 755 /etc/vsftpd/users.d; "
            "find /etc/vsftpd/users.d -type f -exec chmod 600 {} \\;",
        ],
        check=True,
    )

    print("7/8 Restart FTP Service...")
    compose(["restart", "ftp"])
    time.sleep(2)

    print("8/8 Pruefe generierten User-State...")
    expected = sorted(user["username"] for user in users)
    proc = subprocess.run(
        ["docker", "exec", "meowhome_ftp", "sh", "-c", "find /etc/vsftpd/users.d -maxdepth 1 -type f -printf '%f\\n' | sort"],
        capture_output=True,
        text=True,
        check=True,
    )
    actual = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if actual != expected:
        raise SystemExit(f"[ERR] FTP User-State stimmt nicht: expected={expected}, actual={actual}")
    print(f"[OK] Apply erfolgreich. Aktive User: {len(users)}")


def usage() -> None:
    print("\n".join([
        "",
        "MeowFTP - FTP User Management",
        "=" * 50,
        "",
        "Usage:",
        "  meowftp.py list [--json]",
        "  meowftp.py add <user> <htdocs_subfolder_or_empty> [password_optional|--password-stdin] [--allow-all]",
        "  meowftp.py del <user>",
        "  meowftp.py enable <user>",
        "  meowftp.py disable <user>",
        "  meowftp.py passwd <user> [password_optional|--password-stdin]",
        "  meowftp.py home <user> <htdocs_subfolder_or_empty> [--allow-all]",
        "  meowftp.py assign <user> <domain> [domain ...]",
        "  meowftp.py all <user>",
        "  meowftp.py apply",
        "",
        "Domain semantics:",
        "  1 assigned domain  -> FTP root is that domain's contents",
        "  2+ assigned domains -> FTP root lists only the assigned domain folders",
        "  all                  -> FTP root lists all htdocs folders",
        "",
    ]))


def main() -> int:
    if len(sys.argv) < 2:
        usage()
        return 2
    cmd = sys.argv[1].lower()
    try:
        if cmd == "list":
            extra = sys.argv[2:]
            if any(x != "--json" for x in extra):
                raise SystemExit("list: unbekanntes Argument")
            cmd_list(as_json="--json" in extra)
        elif cmd == "add":
            if len(sys.argv) < 4:
                raise SystemExit("add benoetigt: <user> <htdocs_subfolder_or_empty> [password_optional] [--allow-all]")
            extra = sys.argv[4:]
            allow_all = "--allow-all" in extra
            password_stdin = "--password-stdin" in extra
            free_args = [x for x in extra if x not in {"--allow-all", "--password-stdin"}]
            if len(free_args) > 1 or (password_stdin and free_args):
                raise SystemExit("add: Passwort entweder als Argument oder via --password-stdin uebergeben.")
            password = sys.stdin.readline().rstrip("\n") if password_stdin else (free_args[0] if free_args else None)
            cmd_add(sys.argv[2], sys.argv[3], password, allow_all=allow_all)
        elif cmd == "del":
            if len(sys.argv) < 3:
                raise SystemExit("del benoetigt: <user>")
            cmd_del(sys.argv[2])
        elif cmd == "enable":
            if len(sys.argv) < 3:
                raise SystemExit("enable benoetigt: <user>")
            cmd_enable(sys.argv[2], 1)
        elif cmd == "disable":
            if len(sys.argv) < 3:
                raise SystemExit("disable benoetigt: <user>")
            cmd_enable(sys.argv[2], 0)
        elif cmd == "passwd":
            if len(sys.argv) < 3:
                raise SystemExit("passwd benoetigt: <user> [password_optional|--password-stdin]")
            if len(sys.argv) >= 4 and sys.argv[3] == "--password-stdin":
                password = sys.stdin.readline().rstrip("\n")
            else:
                password = sys.argv[3] if len(sys.argv) >= 4 else None
            cmd_passwd(sys.argv[2], password)
        elif cmd == "home":
            if len(sys.argv) < 4:
                raise SystemExit("home benoetigt: <user> <htdocs_subfolder_or_empty> [--allow-all]")
            extra = sys.argv[4:]
            if any(x != "--allow-all" for x in extra):
                raise SystemExit("home: unbekanntes Argument")
            cmd_home(sys.argv[2], sys.argv[3], allow_all="--allow-all" in extra)
        elif cmd == "assign":
            if len(sys.argv) < 4:
                raise SystemExit("assign benoetigt: <user> <domain> [domain ...]")
            cmd_assign(sys.argv[2], sys.argv[3:])
        elif cmd == "all":
            if len(sys.argv) < 3:
                raise SystemExit("all benoetigt: <user>")
            cmd_all(sys.argv[2])
        elif cmd == "apply":
            apply()
        else:
            usage()
            return 2
        return 0
    except subprocess.CalledProcessError as exc:
        print(f"[ERR] Command failed: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
