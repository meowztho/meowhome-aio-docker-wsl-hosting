import io
import os
import pathlib
import sqlite3
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from contextlib import closing

ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKUP = ROOT / "assets/tools/backup/backup.sh"
RESTORE = ROOT / "assets/tools/backup/restore.sh"
FTPS_BUILDER = ROOT / "assets/ftp/build-ftps-pem.sh"


class BackupRestoreTests(unittest.TestCase):
    def make_project(self, base: pathlib.Path, *, ftp_tls: str = "NO", include_ftps_key: bool = True, mismatch_ftps_key: bool = False) -> pathlib.Path:
        project = base / "project"
        for rel in ["apache/vhosts", "htdocs/example.org", "ftp/data/users.d", "ftp/ssl", "tools/ftp", "db", "backups", "control", "letsencrypt/archive/example.org", "letsencrypt/live/example.org"]:
            (project / rel).mkdir(parents=True, exist_ok=True)
        (project / ".env").write_text(f"DB_ROOT_PASSWORD=secret\nFTP_TLS={ftp_tls}\nFTP_CERT_DOMAIN=example.org\nMEOWHOME_HOST_PROJECT_DIR={project}\n", encoding="utf-8")
        (project / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
        for name, char in (("control.token", "a"), ("certbot.token", "b")):
            token = project / "control" / name
            token.write_text(char * 64 + "\n", encoding="utf-8")
            token.chmod(0o644)
        (project / "apache/vhosts/example.conf").write_text("vhost\n", encoding="utf-8")
        (project / "htdocs/example.org/index.html").write_text("web\n", encoding="utf-8")
        (project / "db/raw.dat").write_text("raw-db\n", encoding="utf-8")
        (project / "ftp/data/users.db").write_text("generated\n", encoding="utf-8")
        cert = project / "letsencrypt/archive/example.org/fullchain1.pem"
        key = project / "letsencrypt/archive/example.org/privkey1.pem"
        if ftp_tls.upper() in {"YES", "TRUE", "1", "ON"}:
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-subj", "/CN=example.org", "-days", "1",
            ], check=True, capture_output=True, text=True)
            if mismatch_ftps_key:
                alternate_key = project / "letsencrypt/archive/example.org/alternate-key.pem"
                subprocess.run([
                    "openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(alternate_key),
                ], check=True, capture_output=True, text=True)
                key.write_bytes(alternate_key.read_bytes())
                alternate_key.unlink()
        else:
            cert.write_text("certificate\n", encoding="utf-8")
            if include_ftps_key:
                key.write_text("private-key\n", encoding="utf-8")
        (project / "letsencrypt/live/example.org/fullchain.pem").symlink_to("../../archive/example.org/fullchain1.pem")
        if include_ftps_key:
            (project / "letsencrypt/live/example.org/privkey.pem").symlink_to("../../archive/example.org/privkey1.pem")
        builder = project / "ftp/build-ftps-pem.sh"
        builder.write_bytes(FTPS_BUILDER.read_bytes())
        builder.chmod(0o755)
        with closing(sqlite3.connect(project / "ftp/users.sqlite")) as con, con:
            con.execute("create table users(username text)")
            con.execute("insert into users values ('alice')")
        (project / "ftp/users.sqlite").chmod(0o664)
        (project / "control").chmod(0o755)
        tool = project / "tools/ftp/meowftp.py"
        tool.write_text(textwrap.dedent("""\
            #!/usr/bin/env python3
            import pathlib, sys
            if len(sys.argv) > 1 and sys.argv[1] == 'apply':
                p = pathlib.Path(__file__).resolve().parents[2] / 'ftp/data/rebuilt.txt'
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text('rebuilt')
        """), encoding="utf-8")
        tool.chmod(0o755)
        return project

    def make_fake_path(self, base: pathlib.Path) -> dict[str, str]:
        bindir = base / "bin"
        bindir.mkdir(exist_ok=True)
        docker = bindir / "docker"
        docker.write_text(textwrap.dedent("""\
            #!/usr/bin/env bash
            set -e
            if [[ -n "${FAKE_DOCKER_LOG:-}" ]]; then printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"; fi
            if [[ "$1" == "inspect" ]]; then exit 0; fi
            if [[ "$1" == "compose" && "$2" == "version" ]]; then exit 0; fi
            if [[ "$1" == "compose" ]]; then exit 0; fi
            if [[ "$1" == "logs" ]]; then exit 0; fi
            if [[ "$1" == "exec" ]]; then
              shift
              while [[ "${1:-}" == "-e" || "${1:-}" == "-i" ]]; do
                if [[ "$1" == "-e" ]]; then shift 2; else shift; fi
              done
              container="$1"; shift
              if [[ "$1" == "sh" && "${2:-}" == "-lc" && "${3:-}" == *"command -v mariadb-dump"* ]]; then
                echo /usr/bin/mariadb-dump; exit 0
              fi
              if [[ "$1" == "mariadb-dump" || "$1" == "mysqldump" ]]; then
                echo 'CREATE DATABASE test;'; exit 0
              fi
              if [[ "$1" == "mariadb-admin" ]]; then exit 0; fi
              if [[ "$1" == "mariadb" ]]; then cat >/dev/null; exit 0; fi
            fi
            echo "unsupported fake docker args: $*" >&2
            exit 1
        """), encoding="utf-8")
        docker.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = str(bindir) + os.pathsep + env["PATH"]
        return env

    def make_internal_env_link_backup(self, base: pathlib.Path) -> pathlib.Path:
        project_payload = io.BytesIO()
        with tarfile.open(fileobj=project_payload, mode="w:gz") as tf:
            env_link = tarfile.TarInfo(".env")
            env_link.type = tarfile.SYMTYPE
            env_link.linkname = "control/control.token"
            tf.addfile(env_link)
            for name, data in (("docker-compose.yml", b"services: {}\n"), ("control/control.token", b"original-token\n")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))

        import gzip
        db_payload = io.BytesIO()
        with gzip.GzipFile(fileobj=db_payload, mode="wb") as gz:
            gz.write(b"SELECT 1;\n")
        backup = base / "internal-link-backup.tar.gz"
        with tarfile.open(backup, "w:gz") as tf:
            for name, payload in (("project.tar.gz", project_payload.getvalue()), ("db/all-databases.sql.gz", db_payload.getvalue())):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                tf.addfile(info, io.BytesIO(payload))
        return backup

    def make_valid_backup(self, base: pathlib.Path) -> tuple[pathlib.Path, dict[str, str]]:
        source = self.make_project(base)
        env = self.make_fake_path(base)
        env["MEOWHOME_PROJECT_DIR"] = str(source)
        subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
        return next((source / "backups").glob("meowhome-backup-*.tar.gz")), env

    def test_installed_backup_uses_its_project_root_without_env_override(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-backup-installed-") as td:
            base = pathlib.Path(td)
            project = self.make_project(base)
            installed = project / "tools/backup/backup.sh"
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes(BACKUP.read_bytes())
            installed.chmod(0o755)

            env = self.make_fake_path(base)
            env.pop("MEOWHOME_PROJECT_DIR", None)
            env["HOME"] = str(base / "wrong-home")
            subprocess.run(
                ["bash", str(installed)],
                cwd=base,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            backups = list((project / "backups").glob("meowhome-backup-*.tar.gz"))
            self.assertEqual(len(backups), 1)
            self.assertFalse((base / "wrong-home/meowhome/backups").exists())

    def test_installed_restore_uses_its_project_root_without_env_override(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-installed-") as td:
            base = pathlib.Path(td)
            source = self.make_project(base)
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(source)
            subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
            backup = next((source / "backups").glob("meowhome-backup-*.tar.gz"))

            destination = base / "destination"
            destination.mkdir()
            (destination / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            installed = destination / "tools/backup/restore.sh"
            installed.parent.mkdir(parents=True, exist_ok=True)
            installed.write_bytes(RESTORE.read_bytes())
            installed.chmod(0o755)

            env = self.make_fake_path(base)
            env.pop("MEOWHOME_PROJECT_DIR", None)
            env["HOME"] = str(base / "wrong-home")
            subprocess.run(
                ["bash", str(installed), str(backup)],
                cwd=base,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertTrue((destination / ".env").is_file())
            restored_env = (destination / ".env").read_text(encoding="utf-8")
            self.assertIn(f"MEOWHOME_HOST_PROJECT_DIR={destination.resolve()}", restored_env)
            self.assertFalse((base / "wrong-home/meowhome").exists())

    def test_backup_contains_ftp_source_and_excludes_raw_runtime_data(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-backup-") as td:
            base = pathlib.Path(td)
            project = self.make_project(base)
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(project)
            subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
            backups = list((project / "backups").glob("meowhome-backup-*.tar.gz"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
            with tarfile.open(backups[0], "r:gz") as outer:
                project_bytes = outer.extractfile("project.tar.gz").read()
            with tarfile.open(fileobj=io.BytesIO(project_bytes), mode="r:gz") as inner:
                names = {n.lstrip("./") for n in inner.getnames()}
            self.assertIn("ftp/users.sqlite", names)
            self.assertIn("control/control.token", names)
            self.assertIn("control/certbot.token", names)
            self.assertNotIn("ftp/data/users.db", names)
            self.assertNotIn("db/raw.dat", names)
            self.assertNotIn("htdocs/example.org/index.html", names)

    def test_restore_without_htdocs_preserves_existing_webroot(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-") as td:
            base = pathlib.Path(td)
            source = self.make_project(base)
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(source)
            subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
            backup = next((source / "backups").glob("meowhome-backup-*.tar.gz"))
            destination = base / "restore"
            destination.mkdir()
            (destination / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            (destination / "htdocs").mkdir()
            (destination / "htdocs/keep.txt").write_text("keep\n", encoding="utf-8")
            (destination / "extra.txt").write_text("keep-extra\n", encoding="utf-8")
            env["MEOWHOME_PROJECT_DIR"] = str(destination)
            subprocess.run(["bash", str(RESTORE), str(backup)], env=env, check=True, capture_output=True, text=True)
            self.assertEqual((destination / "htdocs/keep.txt").read_text(encoding="utf-8"), "keep\n")
            self.assertEqual((destination / "extra.txt").read_text(encoding="utf-8"), "keep-extra\n")
            self.assertEqual((destination / "ftp/data/rebuilt.txt").read_text(encoding="utf-8"), "rebuilt")
            self.assertEqual((destination / ".env").stat().st_mode & 0o777, 0o600)
            self.assertEqual((destination / "ftp/users.sqlite").stat().st_mode & 0o777, 0o600)
            self.assertEqual((destination / "control").stat().st_mode & 0o777, 0o700)
            self.assertEqual((destination / "control/control.token").stat().st_mode & 0o777, 0o600)
            self.assertEqual((destination / "control/certbot.token").stat().st_mode & 0o777, 0o600)
            restored_env = (destination / ".env").read_text(encoding="utf-8")
            self.assertIn(f"MEOWHOME_HOST_PROJECT_DIR={destination.resolve()}", restored_env)
            self.assertNotIn(f"MEOWHOME_HOST_PROJECT_DIR={source.resolve()}", restored_env)
            link = destination / "letsencrypt/live/example.org/fullchain.pem"
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve().read_text(encoding="utf-8"), "certificate\n")

    def test_restore_rebuilds_ftps_pem_before_starting_services(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-ftps-") as td:
            base = pathlib.Path(td)
            source = self.make_project(base, ftp_tls="YES")
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(source)
            subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
            backup = next((source / "backups").glob("meowhome-backup-*.tar.gz"))
            with tarfile.open(backup, "r:gz") as outer:
                project_bytes = outer.extractfile("project.tar.gz").read()
            with tarfile.open(fileobj=io.BytesIO(project_bytes), mode="r:gz") as inner:
                self.assertNotIn("ftp/ssl/vsftpd.pem", {n.lstrip("./") for n in inner.getnames()})

            destination = base / "ftps-restore"
            destination.mkdir()
            (destination / "docker-compose.yml").write_text("services: {}\n", encoding="utf-8")
            log = base / "docker.log"
            log.write_text("", encoding="utf-8")
            env["MEOWHOME_PROJECT_DIR"] = str(destination)
            env["FAKE_DOCKER_LOG"] = str(log)
            result = subprocess.run(["bash", str(RESTORE), str(backup)], env=env, check=True, capture_output=True, text=True)

            pem = destination / "ftp/ssl/vsftpd.pem"
            self.assertTrue(pem.read_bytes().startswith((destination / "letsencrypt/archive/example.org/fullchain1.pem").read_bytes()))
            self.assertIn(b"PRIVATE KEY", pem.read_bytes())
            self.assertEqual(pem.stat().st_mode & 0o777, 0o600)
            self.assertLess(result.stdout.index("FTPS-Zertifikat"), result.stdout.index("Bestehenden Stack stoppen"))
            self.assertIn("compose down", log.read_text(encoding="utf-8"))

    def test_restore_ftps_missing_key_fails_before_target_mutation(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-ftps-missing-") as td:
            base = pathlib.Path(td)
            source = self.make_project(base, ftp_tls="YES", include_ftps_key=False)
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(source)
            subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
            backup = next((source / "backups").glob("meowhome-backup-*.tar.gz"))

            destination = base / "ftps-restore-failure"
            destination.mkdir()
            (destination / "docker-compose.yml").write_text("original compose\n", encoding="utf-8")
            (destination / ".env").write_text("original config\n", encoding="utf-8")
            log = base / "docker.log"
            log.write_text("", encoding="utf-8")
            env["MEOWHOME_PROJECT_DIR"] = str(destination)
            env["FAKE_DOCKER_LOG"] = str(log)
            result = subprocess.run(["bash", str(RESTORE), str(backup)], env=env, capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("FTPS-PEM konnte", result.stderr)
            self.assertEqual((destination / "docker-compose.yml").read_text(encoding="utf-8"), "original compose\n")
            self.assertEqual((destination / ".env").read_text(encoding="utf-8"), "original config\n")
            self.assertEqual(log.read_text(encoding="utf-8"), "")

    def test_restore_ftps_mismatched_key_fails_before_target_mutation(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-ftps-mismatch-") as td:
            base = pathlib.Path(td)
            source = self.make_project(base, ftp_tls="YES", mismatch_ftps_key=True)
            # Historical backups contain a builder that concatenates any key.
            # Recovery must use today's validator rather than that old helper.
            (source / "ftp/build-ftps-pem.sh").write_text(
                "#!/bin/sh\nmkdir -p ftp/ssl\n"
                "cat letsencrypt/live/example.org/fullchain.pem "
                "letsencrypt/live/example.org/privkey.pem > ftp/ssl/vsftpd.pem\n"
            )
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(source)
            subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
            backup = next((source / "backups").glob("meowhome-backup-*.tar.gz"))

            destination = base / "ftps-mismatch-restore"
            destination.mkdir()
            compose = destination / "docker-compose.yml"
            compose.write_text("original compose\n", encoding="utf-8")
            env_file = destination / ".env"
            env_file.write_text("original config\n", encoding="utf-8")
            log = base / "docker.log"
            log.write_text("", encoding="utf-8")
            env["MEOWHOME_PROJECT_DIR"] = str(destination)
            env["FAKE_DOCKER_LOG"] = str(log)

            result = subprocess.run(["bash", str(RESTORE), str(backup)], env=env, capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("certificate and private key do not match", result.stderr)
            self.assertEqual(compose.read_text(encoding="utf-8"), "original compose\n")
            self.assertEqual(env_file.read_text(encoding="utf-8"), "original config\n")
            self.assertFalse((destination / "ftp/ssl/vsftpd.pem").exists())
            self.assertEqual(log.read_text(encoding="utf-8"), "")

    def test_ftps_builder_rejects_linked_output_directory(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-ftps-output-link-") as td:
            base = pathlib.Path(td)
            project = self.make_project(base, ftp_tls="YES")
            outside = base / "outside"
            outside.mkdir()
            (project / "ftp/ssl").rmdir()
            (project / "ftp/ssl").symlink_to(outside, target_is_directory=True)
            result = subprocess.run(["bash", str(project / "ftp/build-ftps-pem.sh")], cwd=project, capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(outside.iterdir()), [])

    def test_ftps_builder_failure_preserves_existing_pem(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-ftps-builder-atomic-") as td:
            base = pathlib.Path(td)
            project = self.make_project(base, ftp_tls="YES", mismatch_ftps_key=True)
            output = project / "ftp/ssl/vsftpd.pem"
            output.write_bytes(b"previous valid PEM\n")

            result = subprocess.run(["bash", str(project / "ftp/build-ftps-pem.sh")], cwd=project, capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("certificate and private key do not match", result.stderr)
            self.assertEqual(output.read_bytes(), b"previous valid PEM\n")

    def test_restore_rejects_webroot_target_links_before_stopping_services(self):
        for link_kind in ("root", "nested", "hardlink"):
            with self.subTest(link_kind=link_kind), tempfile.TemporaryDirectory(prefix="meowhome-restore-webroot-link-") as td:
                base = pathlib.Path(td)
                source = self.make_project(base)
                env = self.make_fake_path(base)
                env["MEOWHOME_PROJECT_DIR"] = str(source)
                subprocess.run(["bash", str(BACKUP), "--with-htdocs"], env=env, check=True, capture_output=True)
                backup = next((source / "backups").glob("meowhome-backup-*.tar.gz"))
                destination = base / "destination"
                destination.mkdir()
                compose = destination / "docker-compose.yml"
                compose.write_text("original compose\n")
                outside = base / "outside"
                outside.mkdir()
                marker = outside / "index.html"
                marker.write_text("preserve me")
                if link_kind == "root":
                    (outside / "example.org").mkdir()
                    marker = outside / "example.org/index.html"
                    marker.write_text("preserve me")
                    (destination / "htdocs").symlink_to(outside, target_is_directory=True)
                elif link_kind == "nested":
                    (destination / "htdocs").mkdir()
                    (destination / "htdocs/example.org").symlink_to(outside, target_is_directory=True)
                else:
                    (destination / "htdocs/example.org").mkdir(parents=True)
                    os.link(marker, destination / "htdocs/example.org/index.html")
                log = base / "docker.log"
                log.write_text("")
                env["MEOWHOME_PROJECT_DIR"] = str(destination)
                env["FAKE_DOCKER_LOG"] = str(log)
                result = subprocess.run(["bash", str(RESTORE), str(backup)], env=env, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("unsafe webroot restore", result.stderr)
                self.assertEqual(marker.read_text(), "preserve me")
                self.assertEqual(compose.read_text(), "original compose\n")
                self.assertEqual(log.read_text(), "")

    def test_restore_into_empty_destination(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-empty-") as td:
            base = pathlib.Path(td)
            source = self.make_project(base)
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(source)
            subprocess.run(["bash", str(BACKUP)], env=env, check=True, capture_output=True, text=True)
            backup = next((source / "backups").glob("meowhome-backup-*.tar.gz"))
            destination = base / "empty-restore"
            env["MEOWHOME_PROJECT_DIR"] = str(destination)
            result = subprocess.run(["bash", str(RESTORE), str(backup)], env=env, check=True, capture_output=True, text=True)
            self.assertIn("compose down wird uebersprungen", result.stdout)
            self.assertTrue((destination / "docker-compose.yml").is_file())
            self.assertTrue((destination / ".env").is_file())
            with closing(sqlite3.connect(destination / "ftp/users.sqlite")) as con:
                self.assertEqual(con.execute("SELECT username FROM users").fetchone()[0], "alice")
            self.assertEqual((destination / "ftp/data/rebuilt.txt").read_text(encoding="utf-8"), "rebuilt")
            restored_env = (destination / ".env").read_text(encoding="utf-8")
            self.assertIn(f"MEOWHOME_HOST_PROJECT_DIR={destination.resolve()}", restored_env)
            self.assertNotIn(f"MEOWHOME_HOST_PROJECT_DIR={source.resolve()}", restored_env)
            link = destination / "letsencrypt/live/example.org/fullchain.pem"
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve().read_text(encoding="utf-8"), "certificate\n")

    def test_restore_rejects_symlink_that_escapes_archive(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-unsafe-") as td:
            base = pathlib.Path(td)
            malicious_project = base / "project.tar.gz"
            with tarfile.open(malicious_project, "w:gz") as tf:
                info = tarfile.TarInfo("escape")
                info.type = tarfile.SYMTYPE
                info.linkname = "../../outside"
                tf.addfile(info)

            outer = base / "malicious-backup.tar.gz"
            db_payload = io.BytesIO()
            import gzip
            with gzip.GzipFile(fileobj=db_payload, mode="wb") as gz:
                gz.write(b"SELECT 1;\n")
            with tarfile.open(outer, "w:gz") as tf:
                project_data = malicious_project.read_bytes()
                project_info = tarfile.TarInfo("project.tar.gz")
                project_info.size = len(project_data)
                tf.addfile(project_info, io.BytesIO(project_data))
                db_data = db_payload.getvalue()
                db_info = tarfile.TarInfo("db/all-databases.sql.gz")
                db_info.size = len(db_data)
                tf.addfile(db_info, io.BytesIO(db_data))

            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(base / "destination")
            result = subprocess.run(["bash", str(RESTORE), str(outer)], env=env, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe escaping tar symlink", result.stderr)

    def test_restore_rejects_internal_env_symlink_before_target_mutation(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-internal-link-") as td:
            base = pathlib.Path(td)
            backup = self.make_internal_env_link_backup(base)
            destination = base / "destination"
            destination.mkdir()
            compose = destination / "docker-compose.yml"
            compose.write_text("original compose\n", encoding="utf-8")
            env_file = destination / ".env"
            env_file.write_text("original config\n", encoding="utf-8")
            token = destination / "control/control.token"
            token.parent.mkdir()
            token.write_text("original target token\n", encoding="utf-8")
            log = base / "docker.log"
            log.write_text("", encoding="utf-8")
            env = self.make_fake_path(base)
            env["MEOWHOME_PROJECT_DIR"] = str(destination)
            env["FAKE_DOCKER_LOG"] = str(log)

            result = subprocess.run(["bash", str(RESTORE), str(backup)], env=env, capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe backup path .env", result.stderr)
            self.assertEqual(compose.read_text(encoding="utf-8"), "original compose\n")
            self.assertEqual(env_file.read_text(encoding="utf-8"), "original config\n")
            self.assertEqual(token.read_text(encoding="utf-8"), "original target token\n")
            self.assertEqual(log.read_text(encoding="utf-8"), "")

    def test_restore_rejects_existing_target_env_symlink_before_docker(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-restore-target-link-") as td:
            base = pathlib.Path(td)
            backup, env = self.make_valid_backup(base)
            destination = base / "destination"
            destination.mkdir()
            compose = destination / "docker-compose.yml"
            compose.write_text("original compose\n", encoding="utf-8")
            outside = base / "outside.env"
            outside.write_text("preserve target\n", encoding="utf-8")
            (destination / ".env").symlink_to(outside)
            log = base / "docker.log"
            log.write_text("", encoding="utf-8")
            env["MEOWHOME_PROJECT_DIR"] = str(destination)
            env["FAKE_DOCKER_LOG"] = str(log)

            result = subprocess.run(["bash", str(RESTORE), str(backup)], env=env, capture_output=True, text=True)

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe target path .env", result.stderr)
            self.assertEqual(compose.read_text(encoding="utf-8"), "original compose\n")
            self.assertEqual(outside.read_text(encoding="utf-8"), "preserve target\n")
            self.assertTrue((destination / ".env").is_symlink())
            self.assertEqual(log.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main()
