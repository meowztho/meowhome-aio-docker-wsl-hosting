"""Opt-in real MariaDB recovery; no published ports or installed-stack changes.

MEOWHOME_DOCKER_TESTS=1 python3 -m unittest tests.test_restore_integration -v
The fixture translates the legacy fixed database container name only. Compose,
dump, SQL import, filesystem restore and FTPS PEM creation execute for real.
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid

from tests import test_backup_restore as backup_support


class RestoreIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("MEOWHOME_DOCKER_TESTS") != "1" or os.name != "posix":
            raise unittest.SkipTest("set MEOWHOME_DOCKER_TESTS=1 in WSL/Linux for real recovery")
        cls.docker = shutil.which("docker")
        if not cls.docker:
            raise unittest.SkipTest("Docker CLI unavailable")
        result = subprocess.run([cls.docker, "image", "inspect", "mariadb:10.11"], capture_output=True)
        if result.returncode:
            raise unittest.SkipTest("local mariadb:10.11 image required")

    def test_backup_restores_rows_into_fresh_database_and_rebuilds_ftps(self):
        name = "meowhome-recovery-it-" + uuid.uuid4().hex[:12]
        with tempfile.TemporaryDirectory(prefix="meowhome-recovery-it-") as td:
            base = pathlib.Path(td)
            source = backup_support.BackupRestoreTests().make_project(base, ftp_tls="YES")
            env_file = source / ".env"
            env_file.write_text(env_file.read_text() + f"COMPOSE_PROJECT_NAME={name}\n")
            (source / "docker-compose.yml").write_text(
                "services:\n  mariadb:\n    image: mariadb:10.11\n"
                f"    container_name: {name}\n    network_mode: none\n"
                "    environment:\n      MYSQL_ROOT_PASSWORD: ${DB_ROOT_PASSWORD}\n"
                "    tmpfs:\n      - /var/lib/mysql\n"
            )
            bindir = base / "bin"
            bindir.mkdir()
            wrapper = bindir / "docker"
            wrapper.write_text(
                "#!/usr/bin/env python3\nimport os,sys\n"
                f"args=[{self.docker!r}]+[{name!r} if x=='meowhome_db' else x for x in sys.argv[1:]]\n"
                "os.execv(args[0],args)\n"
            )
            wrapper.chmod(0o700)
            env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ["PATH"],
                       MEOWHOME_PROJECT_DIR=str(source), MEOWHOME_SKIP_FTP_REBUILD="true")

            def run(args, **kwargs):
                result = subprocess.run(args, env=env, capture_output=True, text=True, **kwargs)
                self.assertEqual(result.returncode, 0, "recovery fixture command failed: " + result.stderr[-1500:])
                return result.stdout

            query = ["docker", "exec", "-e", "MYSQL_PWD=secret", name,
                     "mariadb", "--protocol=tcp", "-h127.0.0.1", "-uroot", "-Nse"]
            try:
                run(["docker", "compose", "up", "-d"], cwd=source)
                for _ in range(60):
                    result = subprocess.run(query + ["SELECT 1"], env=env, capture_output=True)
                    if result.returncode == 0:
                        break
                    time.sleep(1)
                else:
                    self.fail("initial fixture database did not become ready")
                run(query + ["CREATE DATABASE recovery_probe; "
                             "CREATE TABLE recovery_probe.items(id INT PRIMARY KEY, value VARCHAR(64)); "
                             "INSERT INTO recovery_probe.items VALUES (1,'roundtrip sentinel');"])
                run(["bash", str(backup_support.BACKUP), "--with-htdocs"], cwd=source)
                backup = next((source / "backups").glob("meowhome-backup-*"))
                # tmpfs disappears with the first database container; restore
                # must therefore initialize a genuinely empty data directory.
                run(["docker", "compose", "down"], cwd=source)
                destination = base / "restored"
                env["MEOWHOME_PROJECT_DIR"] = str(destination)
                run(["bash", str(backup_support.RESTORE), str(backup)], cwd=source, timeout=180)
                self.assertEqual(run(query + ["SELECT value FROM recovery_probe.items WHERE id=1"]).strip(),
                                 "roundtrip sentinel")
                self.assertEqual((destination / "htdocs/example.org/index.html").read_text(), "web\n")
                self.assertEqual((destination / "ftp/ssl/vsftpd.pem").stat().st_mode & 0o777, 0o600)
                self.assertEqual((destination / ".env").stat().st_mode & 0o777, 0o600)
                self.assertIn(str(destination), (destination / ".env").read_text())
            finally:
                subprocess.run([self.docker, "rm", "-f", name], capture_output=True)


if __name__ == "__main__":
    unittest.main()
