"""Disposable vsftpd integration coverage; opt in with MEOWHOME_DOCKER_TESTS=1.

Run from the WSL project checkout with:
    MEOWHOME_DOCKER_TESTS=1 python3 -m unittest tests.test_ftp_integration -v

The test uses the already-built meowhome-ftp image, a source-mounted read-only
entrypoint, fresh temporary roots/auth/certificate, and a private Docker network
namespace (network=none by default; optionally a test-created --internal network
with MEOWHOME_FTP_TEST_NETWORK=internal). It never joins or changes Compose.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("MEOWHOME_FTP_TEST_IMAGE", "meowhome-ftp:latest")
PASSWORD = "synthetic-ftps-test-password"


def _run(args: list[str], *, input_text: str | None = None, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)


class FtpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if os.environ.get("MEOWHOME_DOCKER_TESTS") != "1":
            raise unittest.SkipTest("set MEOWHOME_DOCKER_TESTS=1 to run disposable Docker FTP integration")
        if os.name != "posix":
            raise unittest.SkipTest("run this test in WSL/Linux so temporary bind mounts have real Unix permissions")
        docker = shutil.which("docker")
        if not docker:
            raise unittest.SkipTest("Docker CLI is unavailable")
        cls.docker = docker
        info = _run([docker, "info", "--format", "{{.ServerVersion}}"], timeout=10)
        if info.returncode:
            raise unittest.SkipTest("Docker daemon is unavailable")
        image = _run([docker, "image", "inspect", IMAGE], timeout=10)
        if image.returncode:
            raise unittest.SkipTest(f"required local image {IMAGE!r} is absent; build it before opting in")

    def test_real_vsftpd_scope_ftps_writes_and_uid_collision(self) -> None:
        with tempfile.TemporaryDirectory(prefix="meowhome-ftp-it-") as tmp:
            base = pathlib.Path(tmp)
            self.container = f"meowhome-ftp-it-{uuid.uuid4().hex[:12]}"
            network_mode = os.environ.get("MEOWHOME_FTP_TEST_NETWORK", "none")
            if network_mode not in {"none", "internal"}:
                self.fail("MEOWHOME_FTP_TEST_NETWORK must be 'none' or 'internal'")
            self.network = None
            if network_mode == "internal":
                self.network = self.container + "-net"
            htdocs = base / "htdocs"
            for domain in ("alpha.example", "beta.example", "gamma.example"):
                (htdocs / domain).mkdir(parents=True)
                (htdocs / domain / "visible.txt").write_text(domain, encoding="ascii")
            config = base / "vsftpd"
            coordination = base / "coordination"
            coordination.mkdir()
            self.server_log = base / "vsftpd.log"
            self.server_log.touch()
            (config / "users.d").mkdir(parents=True)
            (config / "users.d" / "single").write_text("local_root=/var/www/alpha.example\n", encoding="ascii")
            (config / "users.d" / "multi").write_text(
                "local_root=/srv/meowftp/views/multi\n", encoding="ascii"
            )
            (config / "users.txt").write_text(
                f"single\n{self._password_hash()}\nmulti\n{self._password_hash()}\n", encoding="ascii"
            )
            # The image's Berkeley DB utility produces the exact authentication
            # format consumed by the shipped PAM/vsftpd configuration.
            db = _run([
                self.docker, "run", "--rm", "--network", "none",
                "-v", f"{config}:/etc/vsftpd", "--entrypoint", "/bin/sh", IMAGE,
                "-c", "db5.3_load -T -t hash -f /etc/vsftpd/users.txt /etc/vsftpd/users.db",
            ])
            self.assertEqual(db.returncode, 0, "could not prepare disposable virtual-user database")

            pem = config / "vsftpd.pem"
            cert = _run([
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                "-subj", "/CN=localhost", "-keyout", str(base / "test.key"),
                "-out", str(base / "test.crt"),
            ], timeout=30)
            self.assertEqual(cert.returncode, 0, "could not generate disposable FTPS certificate")
            pem.write_bytes((base / "test.crt").read_bytes() + (base / "test.key").read_bytes())
            pem.chmod(0o600)

            # Exercise canonical validation with this disposable filesystem,
            # including symlinked domain roots that must not become FTP homes.
            alias = htdocs / "alias.example"
            alias.symlink_to(htdocs / "alpha.example", target_is_directory=True)
            meowftp = self._canonical_tool()
            self.assert_validation_rejects(meowftp.validate_username, "../escape")
            old_htdocs = meowftp.HTDOCS
            try:
                meowftp.HTDOCS = str(htdocs)
                self.assert_validation_rejects(meowftp.normalize_domain, "alias.example")
            finally:
                meowftp.HTDOCS = old_htdocs

            uid, gid = (1001, 1001) if os.getuid() == 0 else (os.getuid(), os.getgid())
            if os.getuid() == 0:
                for domain in ("alpha.example", "beta.example", "gamma.example"):
                    os.chown(htdocs / domain, uid, gid)
            if self.network:
                made = _run([self.docker, "network", "create", "--internal", self.network], timeout=10)
                self.assertEqual(made.returncode, 0, "could not create isolated disposable Docker network")
            command = [
                self.docker, "run", "--init", "--detach", "--name", self.container,
                "--network", self.network or "none", "--env", f"PUID={uid}", "--env", f"PGID={gid}",
                "--env", "FTP_TLS=YES", "--env", "FTP_PASV_MIN=21000", "--env", "FTP_PASV_MAX=21010",
                "--env", "FTP_PUBLIC_HOST=127.0.0.1",
                "-v", f"{ROOT / 'assets/ftp/entrypoint.sh'}:/entrypoint.sh:ro",
                "-v", f"{htdocs}:/var/www",
                "-v", f"{coordination}:/test-coord",
                "-v", f"{self.server_log}:/var/log/vsftpd.log",
                # Match canonical meowftp.py's generated multi-domain view:
                # only assigned domains are mounted under this user's view.
                "-v", f"{htdocs / 'alpha.example'}:/srv/meowftp/views/multi/alpha.example",
                "-v", f"{htdocs / 'beta.example'}:/srv/meowftp/views/multi/beta.example",
                "-v", f"{config}:/etc/vsftpd",
                "-v", f"{pem}:/etc/ssl/private/vsftpd.pem:ro",
                IMAGE,
            ]
            started = _run(command, timeout=20)
            self.assertEqual(started.returncode, 0, "could not start disposable FTP container")
            try:
                self._wait_ready()
                client = subprocess.Popen(
                    [
                        self.docker, "run", "--rm", "-i", "--network", f"container:{self.container}",
                        "-v", f"{coordination}:/test-coord", "--entrypoint", "python3", IMAGE, "-",
                    ],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                )
                assert client.stdin is not None
                client.stdin.write(self._client_script())
                client.stdin.close()
                client.stdin = None
                ready = coordination / "upload-ready"
                self._wait_for_marker(ready, client, "single-domain FTPS upload")

                uploaded = htdocs / "alpha.example" / "integration-upload.txt"
                self.assertEqual(uploaded.read_text(encoding="ascii"), "uploaded by FTP")
                self.assertEqual(uploaded.stat().st_uid, uid)
                self.assertEqual(uploaded.stat().st_gid, gid)
                self.assertEqual(uploaded.stat().st_mode & 0o777, 0o664)
                self.assertFalse((htdocs / "beta.example" / "integration-upload.txt").exists())
                (coordination / "delete-now").touch()

                multi_ready = coordination / "multi-upload-ready"
                self._wait_for_marker(multi_ready, client, "multi-domain FTPS upload after sequential sessions")
                multi_uploaded = htdocs / "alpha.example" / "multi-integration-upload.txt"
                self.assertEqual(multi_uploaded.read_text(encoding="ascii"), "uploaded by FTP")
                self.assertEqual(multi_uploaded.stat().st_uid, uid)
                self.assertEqual(multi_uploaded.stat().st_gid, gid)
                self.assertEqual(multi_uploaded.stat().st_mode & 0o777, 0o664)
                self.assertFalse((htdocs / "gamma.example" / "multi-integration-upload.txt").exists())
                (coordination / "multi-delete-now").touch()
                try:
                    out, err = client.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    client.kill()
                    out, err = client.communicate()
                    self.fail("FTPS delete operation timed out: " + self._safe_logs(out + err))
                self.assertEqual(client.returncode, 0, "FTPS upload/delete failed: " + self._safe_logs(out + err))
                self.assertFalse(uploaded.exists(), "FTP DELE left the uploaded file behind")
                self.assertFalse(multi_uploaded.exists(), "FTP DELE left the multi-domain upload behind")
                state = self._container_state()
                self.assertEqual(state["Status"], "running", "vsftpd exited after sequential FTPS sessions")
            finally:
                _run([self.docker, "rm", "-f", self.container], timeout=20)
                # The entrypoint deliberately makes generated auth state
                # root-owned. Restore disposable temp ownership for cleanup.
                _run([
                    self.docker, "run", "--rm", "--network", "none",
                    "-v", f"{config}:/etc/vsftpd", "--entrypoint", "/bin/sh", IMAGE,
                    "-c", f"chmod -R u+rwX /etc/vsftpd && chown -R {uid}:{gid} /etc/vsftpd",
                ], timeout=10)
                if self.network:
                    _run([self.docker, "network", "rm", self.network], timeout=10)

            # UID 0 is already owned by root in this base image. Startup must
            # reject the collision before mapping/changing the ftp account.
            collision = _run([
                self.docker, "run", "--rm", "--network", "none", "--env", "PUID=0", "--env", f"PGID={gid}",
                "-v", f"{ROOT / 'assets/ftp/entrypoint.sh'}:/entrypoint.sh:ro",
                "-v", f"{config}:/etc/vsftpd", IMAGE,
            ], timeout=20)
            self.assertNotEqual(collision.returncode, 0, "FTP entrypoint unexpectedly accepted root UID collision")
            self.assertIn("already belongs to account 'root'", collision.stdout + collision.stderr)

    @staticmethod
    def _password_hash() -> str:
        hashed = _run(["openssl", "passwd", "-6", PASSWORD], timeout=10)
        if hashed.returncode:
            raise AssertionError("could not generate synthetic disposable password hash")
        return hashed.stdout.strip()

    @staticmethod
    def _canonical_tool():
        path = ROOT / "assets/tools/ftp/meowftp.py"
        spec = importlib.util.spec_from_file_location("meowftp_integration", path)
        if spec is None or spec.loader is None:
            raise AssertionError("could not load canonical FTP tool")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module

    def assert_validation_rejects(self, validator, value: str) -> None:
        with self.assertRaises(SystemExit):
            validator(value)

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            state = self._container_state()
            if not state or state["Status"] != "running":
                logs = _run([self.docker, "logs", self.container], timeout=5)
                self.fail("disposable FTP container exited before ready: " + self._safe_logs(logs.stdout + logs.stderr))
            probe = _run([self.docker, "exec", self.container, "python3", "-c",
                          "import socket; s=socket.create_connection(('127.0.0.1',21),1); s.close()"], timeout=5)
            if probe.returncode == 0:
                return
            time.sleep(0.25)
        logs = _run([self.docker, "logs", self.container], timeout=5)
        self.fail("disposable FTP listener did not become ready: " + self._safe_logs(logs.stdout + logs.stderr))

    def _container_state(self) -> dict[str, object]:
        result = _run([
            self.docker, "inspect", "--format", "{{json .State}}", self.container,
        ], timeout=5)
        if result.returncode:
            return {}
        import json
        return json.loads(result.stdout)

    def _wait_for_marker(self, marker: pathlib.Path, client: subprocess.Popen[str], description: str) -> None:
        deadline = time.monotonic() + 20
        while not marker.exists() and client.poll() is None and time.monotonic() < deadline:
            time.sleep(0.1)
        if marker.exists():
            return
        try:
            out, err = client.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            client.kill()
            out, err = client.communicate()
        logs = _run([self.docker, "logs", self.container], timeout=5)
        state = self._container_state()
        protocol_log = self.server_log.read_text(encoding="utf-8", errors="replace")[-4000:]
        self.fail(
            f"{description} did not complete; client_exit={client.returncode}, "
            f"container_state={state}, client={self._safe_logs(out + err)}, "
            f"server_logs={self._safe_logs(logs.stdout + logs.stderr)}, "
            f"vsftpd_protocol_log={self._safe_logs(protocol_log)}"
        )

    @staticmethod
    def _safe_logs(logs: str) -> str:
        # The password is synthetic, but keep test diagnostics credential-free.
        return logs.replace(PASSWORD, "[redacted]")[-3000:]

    @staticmethod
    def _client_script() -> str:
        # Credential arrives on docker exec stdin, never in argv or test output.
        return f'''import ftplib, io, ssl
password = {PASSWORD!r}
context = ssl._create_unverified_context()

def connect(user):
    ftp = ftplib.FTP_TLS(context=context, timeout=8)
    ftp.connect("127.0.0.1", 21)
    print("connected", user, flush=True)
    ftp.auth()
    print("tls-authenticated", user, flush=True)
    ftp.login(user, password)
    print("logged-in", user, flush=True)
    ftp.prot_p()
    return ftp

single = connect("single")
single_names = single.nlst()
assert "visible.txt" in single_names, single_names
assert "beta.example" not in single_names, single_names
single.storbinary("STOR integration-upload.txt", io.BytesIO(b"uploaded by FTP"))
open("/test-coord/upload-ready", "w").close()
import os, time
while not os.path.exists("/test-coord/delete-now"):
    time.sleep(0.05)
single.delete("integration-upload.txt")
single.quit()
print("single-session-1-complete", flush=True)

# A completed client session must not stop the standalone FTP service. Open a
# second authenticated FTPS session to the same listener, then verify the
# generated two-domain view is limited to alpha/beta and excludes gamma.
again = connect("single")
print("single-session-2-authenticated", flush=True)
assert "visible.txt" in again.nlst()
print("single-session-2-listed", flush=True)
again.quit()
print("single-session-2-complete", flush=True)

multi = connect("multi")
print("multi-session-authenticated", flush=True)
assert set(multi.nlst()) == {{"alpha.example", "beta.example"}}
print("multi-session-listed", flush=True)
try:
    multi.cwd("gamma.example")
except ftplib.error_perm as exc:
    assert str(exc).startswith("550"), exc
else:
    raise AssertionError("unassigned gamma.example unexpectedly accessible")
multi.cwd("alpha.example")
multi.storbinary("STOR multi-integration-upload.txt", io.BytesIO(b"uploaded by FTP"))
open("/test-coord/multi-upload-ready", "w").close()
while not os.path.exists("/test-coord/multi-delete-now"):
    time.sleep(0.05)
multi.delete("multi-integration-upload.txt")
multi.quit()
'''


if __name__ == "__main__":
    unittest.main()
