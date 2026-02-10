#!/usr/bin/env python3
import os
import sys
import sqlite3
import getpass
import subprocess
import time
from typing import Tuple

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DB_PATH = os.path.join(BASE, "ftp", "users.sqlite")
HTDOCS = os.path.join(BASE, "htdocs")
ENV_PATH = os.path.join(BASE, ".env")

def sh(cmd: list[str]) -> None:
    subprocess.check_call(cmd)

def sh_out(cmd: list[str]) -> str:
    return subprocess.check_output(cmd, text=True).strip()

def read_env_value(key: str, default: str = "") -> str:
    if not os.path.exists(ENV_PATH):
        return default
    with open(ENV_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() == key:
                return v.strip()
    return default

def host_uid_gid() -> Tuple[int, int]:
    uid = int(read_env_value("FTP_HOST_UID", "1000") or "1000")
    gid = int(read_env_value("FTP_HOST_GID", "1000") or "1000")
    return uid, gid

def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        pass_hash TEXT NOT NULL,
        home_rel TEXT NOT NULL DEFAULT '',
        enabled INTEGER NOT NULL DEFAULT 1
      )
    """)
    con.commit()
    return con

def hash_pw_sha512_crypt(password: str) -> str:
    out = sh_out(["openssl", "passwd", "-6", password])
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
    if home_rel != "":
        return
    if allow_all:
        return
    confirm("home_rel ist leer -> User sieht ALLE Domain-Ordner unter htdocs. Fortfahren?")

def normalize_home_rel(home_rel: str) -> str:
    home_rel = home_rel.strip().lstrip("/").replace("\\", "/")
    if home_rel in (".", "./"):
        home_rel = ""
    if ".." in home_rel.split("/"):
        raise SystemExit("Ungueltiger Pfad (.. nicht erlaubt).")
    return home_rel

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

def cmd_list() -> None:
    con = db()
    rows = list(con.execute("SELECT username, home_rel, enabled FROM users ORDER BY username"))
    if not rows:
        print("Keine User vorhanden.")
        return
    print(f"{'Username':<20} {'Enabled':<8} {'Path':<40}")
    print("-" * 70)
    for u, home_rel, enabled in rows:
        target = "htdocs/" + (home_rel if home_rel else "(all domains)")
        status = "yes" if enabled else "no"
        print(f"{u:<20} {status:<8} {target:<40}")

def cmd_add(
    username: str,
    home_rel: str,
    password: str | None = None,
    allow_all: bool = False,
) -> None:
    username = username.strip()
    if not username:
        raise SystemExit("Username fehlt.")
    home_rel = normalize_home_rel(home_rel)

    require_all_access_confirmation(home_rel, allow_all=allow_all)

    # If a password is provided, run non-interactive.
    # Otherwise keep the interactive shell workflow.
    if password is None or str(password).strip() == "":
        pw = prompt_password()
    else:
        pw = str(password)

    ph = hash_pw_sha512_crypt(pw)

    ensure_home_dir(home_rel)

    con = db()
    con.execute(
        "INSERT OR REPLACE INTO users(username, pass_hash, home_rel, enabled) VALUES(?,?,?,1)",
        (username, ph, home_rel),
    )
    con.commit()
    print(f"[OK] User '{username}' gespeichert (home_rel='{home_rel or '(root)'}')")
    print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")

def cmd_del(username: str) -> None:
    con = db()
    cur = con.execute("DELETE FROM users WHERE username=?", (username,))
    con.commit()
    if cur.rowcount == 0:
        print("[ERR] User nicht gefunden.")
    else:
        print(f"[OK] User '{username}' geloescht")
        print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")

def cmd_enable(username: str, enabled: int) -> None:
    con = db()
    cur = con.execute("UPDATE users SET enabled=? WHERE username=?", (enabled, username))
    con.commit()
    if cur.rowcount == 0:
        print("[ERR] User nicht gefunden.")
    else:
        status = "aktiviert" if enabled else "deaktiviert"
        print(f"[OK] User '{username}' {status}")
        print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")

def cmd_passwd(username: str, password: str | None = None) -> None:
    con = db()
    row = con.execute("SELECT username FROM users WHERE username=?", (username,)).fetchone()
    if not row:
        raise SystemExit("[ERR] User nicht gefunden.")

    if password is None or str(password).strip() == "":
        pw = prompt_password()
    else:
        pw = str(password)

    ph = hash_pw_sha512_crypt(pw)
    con.execute("UPDATE users SET pass_hash=? WHERE username=?", (ph, username))
    con.commit()
    print(f"[OK] User '{username}' password updated")
    print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")


def cmd_home(username: str, home_rel: str, allow_all: bool = False) -> None:
    home_rel = normalize_home_rel(home_rel)
    require_all_access_confirmation(home_rel, allow_all=allow_all)
    ensure_home_dir(home_rel)
    con = db()
    cur = con.execute("UPDATE users SET home_rel=? WHERE username=?", (home_rel, username))
    con.commit()
    if cur.rowcount == 0:
        print("[ERR] User nicht gefunden.")
    else:
        print(f"[OK] User '{username}' home_rel='{home_rel or '(root)'}'")
        print("[WARN] Fuehre 'meowftp.py apply' aus um Aenderungen zu aktivieren!")

def docker_compose_cmd() -> list[str]:
    """
    Returns the compose command as argv list.
    Prefers: docker compose
    Fallback: docker-compose
    """
    try:
        subprocess.check_call(
            ["docker", "compose", "version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return ["docker", "compose"]
    except Exception:
        return ["docker-compose"]


def docker_compose_up_ftp() -> None:
    compose_file = os.path.join(BASE, "docker-compose.yml")
    cmd = docker_compose_cmd()
    sh(cmd + ["-f", compose_file, "up", "-d", "ftp"])


def wait_for_container(max_wait: int = 90) -> None:
    print("[WAIT] Warte auf FTP Container...")
    last_err = ""
    for i in range(max_wait):
        try:
            subprocess.run(
                ["docker", "exec", "meowhome_ftp", "test", "-d", "/etc/vsftpd"],
                capture_output=True, check=True, timeout=5
            )
            print("[OK] Container ist bereit")
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            last_err = str(e)
            time.sleep(1)

    # Debug am Ende
    try:
        logs = subprocess.run(["docker", "logs", "--tail", "80", "meowhome_ftp"], capture_output=True, text=True, timeout=10)
        print("----- meowhome_ftp logs (tail 80) -----")
        print(logs.stdout)
        print(logs.stderr)
    except Exception:
        pass

    raise SystemExit(f"[ERR] Container startet nicht korrekt (nach {max_wait}s). Last error: {last_err}")

def apply() -> None:
    if os.geteuid() != 0:
        print("[WARN] apply benoetigt sudo/root")

        # Re-exec with sudo if available (keeps shell workflow).
        try:
            sudo_path = sh_out(["which", "sudo"])
        except Exception:
            sudo_path = ""

        if sudo_path:
            print("Starte erneut mit sudo...")
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

        # Kein sudo vorhanden (typisch im Container) -> sauber abbrechen
        raise SystemExit("[ERR] sudo nicht verfuegbar. Bitte 'apply' als root ausfuehren (z.B. via sudo in der Shell).")

    print("=" * 60)
    print("MeowFTP Apply - Aktiviere User-Aenderungen")
    print("=" * 60)
    print()

    print("1/7 Starte FTP Container...")
    # Do not touch running containers to avoid restart races.
    ps = subprocess.run(["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True)
    if "meowhome_ftp" not in ps.stdout.split():
        print("   FTP Container laeuft nicht -> starte...")
        docker_compose_up_ftp()
    else:
        print("   FTP Container laeuft bereits -> ueberspringe start")

    wait_for_container()

    con = db()
    rows = list(con.execute(
        "SELECT username, pass_hash, home_rel FROM users WHERE enabled=1 ORDER BY username"
    ))

    if not rows:
        print("[WARN] Keine aktiven User in Datenbank")
        return

    print(f"2/7 Gefunden: {len(rows)} aktive User")

    users_txt_content = ""
    for username, pass_hash, _ in rows:
        users_txt_content += f"{username}\n{pass_hash}\n"

    print("3/7 Schreibe users.txt in Container...")
    subprocess.run(
        ["docker", "exec", "-i", "meowhome_ftp", "sh", "-c", "cat > /etc/vsftpd/users.txt"],
        input=users_txt_content.encode(),
        check=True
    )

    print("4/7 Erstelle users.db...")

    try:
        subprocess.run(
            ["docker", "exec", "meowhome_ftp", "which", "db5.3_load"],
            capture_output=True, check=True
        )
        db_cmd = "db5.3_load"
    except subprocess.CalledProcessError:
        db_cmd = "db_load"

    subprocess.run([
        "docker", "exec", "meowhome_ftp", "sh", "-c",
        f"cd /etc/vsftpd && {db_cmd} -T -t hash -f users.txt users.db"
    ], check=True)

    print("5/7 Erstelle User-Configs...")
    for username, _, home_rel in rows:
        local_root = "/var/www" if not home_rel else f"/var/www/{home_rel}"
        config_content = f"local_root={local_root}\n"

        subprocess.run([
            "docker", "exec", "-i", "meowhome_ftp", "sh", "-c",
            f"cat > /etc/vsftpd/users.d/{username}"
        ], input=config_content.encode(), check=True)

        ensure_home_dir(home_rel)

    print("6/7 Setze Permissions...")
    subprocess.run([
        "docker", "exec", "meowhome_ftp", "sh", "-c",
        """
        chown root:root /etc/vsftpd/vsftpd.conf /etc/vsftpd/users.txt /etc/vsftpd/users.db
        chmod 600 /etc/vsftpd/vsftpd.conf /etc/vsftpd/users.txt /etc/vsftpd/users.db
        chown root:root /etc/vsftpd/users.d
        chmod 755 /etc/vsftpd/users.d
        find /etc/vsftpd/users.d -type f -exec chmod 600 {} \\;
        """
    ], check=True)

    print("7/7 Restart FTP Service...")
    cmd = docker_compose_cmd()
    subprocess.run(
        cmd + ["-f", os.path.join(BASE, "docker-compose.yml"), "restart", "ftp"],
        check=True
    )

    time.sleep(2)

    print()
    print("=" * 60)
    print("[OK] Apply erfolgreich!")
    print("=" * 60)
    print()
    print(f"Aktive User: {len(rows)}")
    for username, _, home_rel in rows:
        path = f"htdocs/{home_rel}" if home_rel else "htdocs/ (all)"
        print(f"  - {username:<20} -> {path}")
    print()
    print("Debug mit: docker logs meowhome_ftp")
    print()

def usage() -> None:
    print("\n".join([
        "",
        "MeowFTP - FTP User Management",
        "=" * 50,
        "",
        "Usage:",
        "  meowftp.py list",
        "  meowftp.py add <user> <htdocs_subfolder_or_empty> [password_optional] [--allow-all]",
        "  meowftp.py del <user>",
        "  meowftp.py enable <user>",
        "  meowftp.py disable <user>",
        "  meowftp.py passwd <user>",
        "  meowftp.py home <user> <htdocs_subfolder_or_empty> [--allow-all]",
        "  meowftp.py apply",
        "",
    ]))

def main() -> int:
    if len(sys.argv) < 2:
        usage()
        return 2

    cmd = sys.argv[1].lower()

    try:
        if cmd == "list":
            cmd_list()
        elif cmd == "add":
            if len(sys.argv) < 4:
                raise SystemExit("add benoetigt: <user> <htdocs_subfolder_or_empty> [password_optional] [--allow-all]")
            username = sys.argv[2]
            home_rel = sys.argv[3]
            extra = sys.argv[4:]
            allow_all = False
            free_args: list[str] = []
            for arg in extra:
                if arg == "--allow-all":
                    allow_all = True
                else:
                    free_args.append(arg)
            if len(free_args) > 1:
                raise SystemExit("add: zu viele Argumente. Erlaubt: [password_optional] [--allow-all]")
            password = free_args[0] if free_args else None
            cmd_add(username, home_rel, password, allow_all=allow_all)
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
                raise SystemExit("passwd benoetigt: <user> [password_optional]")
            password = sys.argv[3] if len(sys.argv) >= 4 else None
            cmd_passwd(sys.argv[2], password)
        elif cmd == "home":
            if len(sys.argv) < 4:
                raise SystemExit("home benoetigt: <user> <htdocs_subfolder_or_empty> [--allow-all]")
            username = sys.argv[2]
            home_rel = sys.argv[3]
            extra = sys.argv[4:]
            allow_all = False
            for arg in extra:
                if arg == "--allow-all":
                    allow_all = True
                else:
                    raise SystemExit("home: unbekanntes Argument: " + arg)
            cmd_home(username, home_rel, allow_all=allow_all)
        elif cmd == "apply":
            apply()
        else:
            usage()
            return 2
        return 0
    except subprocess.CalledProcessError as e:
        print(f"[ERR] Command failed: {e}")
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
