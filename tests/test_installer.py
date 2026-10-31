import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "init-meowhome.sh"


class InstallerTests(unittest.TestCase):
    def installer_env(self) -> dict[str, str]:
        env = os.environ.copy()
        # Root-run test environments need an explicit non-root target identity,
        # just like the real sudo invocation required by init-meowhome.sh.
        if os.name == "posix" and os.getuid() == 0:
            env.setdefault("SUDO_UID", "65534")
            env.setdefault("SUDO_GID", "65534")
        return env

    def installer_owner_ids(self, env: dict[str, str] | None = None) -> tuple[int, int]:
        env = env or self.installer_env()
        if os.name == "posix" and os.getuid() == 0:
            return int(env["SUDO_UID"]), int(env["SUDO_GID"])
        return os.getuid(), os.getgid()

    def run_installer(self, project: pathlib.Path) -> subprocess.CompletedProcess[str]:
        env = self.installer_env()
        return subprocess.run(
            ["bash", str(INSTALLER), str(project)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            env=env,
        )

    def test_fresh_install_uses_invoking_uid_gid(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-install-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            self.run_installer(project)
            env = (project / ".env").read_text(encoding="utf-8")
            uid, gid = self.installer_owner_ids()
            self.assertIn(f"PUID={uid}", env)
            self.assertIn(f"PGID={gid}", env)
            self.assertIn(f"MEOWHOME_HOST_PROJECT_DIR={project.resolve()}", env)
            self.assertEqual((project / ".env").stat().st_mode & 0o777, 0o600)
            env_values = dict(line.split("=", 1) for line in env.splitlines() if "=" in line and not line.startswith("#"))
            generated_secrets = [
                env_values.get("DB_ROOT_PASSWORD", ""),
                env_values.get("DB_PASSWORD", ""),
                env_values.get("MEOWHOME_UI_PASS", ""),
            ]
            self.assertTrue(all(len(secret) >= 24 for secret in generated_secrets), "fresh install secrets must be sufficiently long")
            self.assertEqual(len(set(generated_secrets)), 3, "fresh install database and UI secrets must be distinct")
            self.assertTrue(
                all(secret not in {"admin", "GENERATED_ON_INSTALL", "PASTE_TOKEN_HERE"} for secret in generated_secrets),
                "fresh install must replace all secret placeholders",
            )
            self.assertEqual(env_values.get("FTP_BIND"), "127.0.0.1")
            self.assertEqual(env_values.get("CERTBOT_ENABLED"), "false")
            self.assertEqual(env_values.get("DNS_UPDATER_ENABLED"), "false")
            preserved_secrets = tuple(generated_secrets)
            self.run_installer(project)
            rerun_env = (project / ".env").read_text(encoding="utf-8")
            rerun_values = dict(line.split("=", 1) for line in rerun_env.splitlines() if "=" in line and not line.startswith("#"))
            self.assertTrue(
                preserved_secrets == (
                    rerun_values.get("DB_ROOT_PASSWORD"),
                    rerun_values.get("DB_PASSWORD"),
                    rerun_values.get("MEOWHOME_UI_PASS"),
                ),
                "installer rerun must preserve generated database and UI secrets",
            )
            control_token = project / "control/control.token"
            self.assertTrue(control_token.is_file())
            self.assertEqual(control_token.stat().st_mode & 0o777, 0o600)
            self.assertGreaterEqual(len(control_token.read_text(encoding="utf-8").strip()), 32)
            certbot_token = project / "control/certbot.token"
            self.assertTrue(certbot_token.is_file())
            self.assertEqual(certbot_token.stat().st_mode & 0o777, 0o600)
            self.assertGreaterEqual(len(certbot_token.read_text(encoding="utf-8").strip()), 32)
            self.assertNotEqual(control_token.read_text(), certbot_token.read_text())
            self.assertEqual((project / "control").stat().st_mode & 0o777, 0o700)
            vhost_dir = project / "apache/vhosts"
            self.assertEqual((vhost_dir.stat().st_mode & 0o7777), 0o2775)
            self.assertEqual((vhost_dir / "10-example.conf").stat().st_mode & 0o777, 0o664)
            self.assertEqual((vhost_dir.stat().st_uid, vhost_dir.stat().st_gid), (uid, gid))
            self.assertEqual(
                ((vhost_dir / "10-example.conf").stat().st_uid, (vhost_dir / "10-example.conf").stat().st_gid),
                (uid, gid),
            )
            compose = (project / "docker-compose.yml").read_text(encoding="utf-8")
            web_block = compose.split("  php:", 1)[0]
            self.assertIn("WIN_HOST_IP: ${WIN_HOST_IP:-127.0.0.1}", web_block)
            self.assertIn("  ui:", compose)
            self.assertIn('${MEOWHOME_HOST_PROJECT_DIR:-.}/htdocs:/var/www:rw', compose)
            self.assertIn('${MEOWHOME_HOST_PROJECT_DIR:-.}:/meowhome:rw', compose)
            self.assertIn("  control:", compose)
            self.assertIn("container_name: meowhome_control", compose)
            ui_block = compose.split("  ui:", 1)[1].split("\nnetworks:", 1)[0]
            certbot_block = compose.split("  certbot:", 1)[1].split("\n  dns_updater:", 1)[0]
            control_block = compose.split("  control:", 1)[1].split("\n  ui:", 1)[0]
            self.assertNotIn("/var/run/docker.sock", certbot_block)
            self.assertIn("/var/run/docker.sock", control_block)
            self.assertIn("control_net", ui_block)
            self.assertIn("control_net", certbot_block)
            self.assertIn("control/certbot.token", certbot_block)
            self.assertNotIn("control/control.token", certbot_block)
            self.assertIn("control/control.token", ui_block)
            self.assertTrue((project / "CHANGELOG.md").is_file())
            self.assertTrue((project / "AGENTS.md").is_file())
            self.assertTrue((project / "ARCHITECTURE.md").is_file())
            self.assertEqual((project / "VERSION").read_text(encoding="utf-8").strip(), (ROOT / "VERSION").read_text(encoding="utf-8").strip())
            self.assertTrue((project / "tools/meowhome.py").is_file())
            self.assertIn("ftp/users.sqlite", (project / ".gitignore").read_text(encoding="utf-8"))
            example_vhost = (project / "apache/vhosts/10-example.conf").read_text(encoding="utf-8")
            self.assertIn("Include /etc/apache2/snippets/php-fpm.conf", example_vhost)
            ftp_entrypoint = (project / "ftp/entrypoint.sh").read_text(encoding="utf-8")
            self.assertIn("require_ssl_reuse=NO", ftp_entrypoint)
            web_dockerfile = (project / "web/Dockerfile").read_text(encoding="utf-8")
            self.assertIn("Options -Indexes +FollowSymLinks", web_dockerfile)
            aop_ca = project / "apache/snippets/cloudflare-origin-pull-ca.pem"
            self.assertTrue(aop_ca.is_file())
            self.assertIn("BEGIN CERTIFICATE", aop_ca.read_text(encoding="utf-8"))
            ui_main = (project / "meowhome-ui/app/main.py").read_text(encoding="utf-8")
            self.assertIn('"/v1/repair-control-plane"', ui_main)
            self.assertIn("mode=0o664", ui_main)
            base_template = (project / "meowhome-ui/app/templates/base.html").read_text(encoding="utf-8")
            self.assertIn(".col-7{grid-column:span 7}", base_template)
            self.assertIn(".col-5{grid-column:span 5}", base_template)
            self.assertIn("Websites & Domains", base_template)
            self.assertIn("Datenbanken", base_template)
            self.assertIn("Advanced VHosts", base_template)

    def test_clean_install_vhost_modes_ignore_restrictive_umask(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-install-umask-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            env = self.installer_env()
            subprocess.run(
                ["bash", "-c", 'umask 077; exec bash "$1" "$2"', "install-test", str(INSTALLER), str(project)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertEqual((project / "apache/vhosts").stat().st_mode & 0o7777, 0o2775)
            self.assertEqual((project / "apache/vhosts/10-example.conf").stat().st_mode & 0o777, 0o664)

    def test_root_install_requires_sudo_identity_before_creating_target(self):
        if os.name != "posix" or os.getuid() != 0:
            self.skipTest("direct-root guard can only be tested as root")
        with tempfile.TemporaryDirectory(prefix="meowhome-root-guard-") as tmp:
            project = pathlib.Path(tmp) / "must-not-exist"
            env = self.installer_env()
            env.pop("SUDO_UID", None)
            env.pop("SUDO_GID", None)
            result = subprocess.run(
                ["bash", str(INSTALLER), str(project)],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SUDO_UID/SUDO_GID", result.stderr)
            self.assertFalse(project.exists())

    def test_sudo_clean_install_hands_new_project_to_invoking_user(self):
        if os.name != "posix":
            self.skipTest("POSIX ownership test")
        env = self.installer_env()
        if os.getuid() != 0:
            sudo = shutil.which("sudo")
            if not sudo or subprocess.run([sudo, "-n", "true"], capture_output=True).returncode != 0:
                self.skipTest("passwordless sudo is unavailable")
        uid, gid = self.installer_owner_ids(env)
        with tempfile.TemporaryDirectory(prefix="meowhome-sudo-install-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            if os.getuid() == 0:
                cmd = ["bash", str(INSTALLER), str(project)]
                run_env = env
            else:
                cmd = [shutil.which("sudo") or "sudo", "-n", "env", f"SUDO_UID={uid}", f"SUDO_GID={gid}", "bash", str(INSTALLER), str(project)]
                run_env = env
            subprocess.run(cmd, cwd=ROOT, env=run_env, text=True, capture_output=True, check=True)
            for rel in (".env", "htdocs", "htdocs/example.com", "htdocs/example.com/index.php", "apache/vhosts", "apache/vhosts/10-example.conf", "control/control.token"):
                st = (project / rel).stat()
                self.assertEqual((st.st_uid, st.st_gid), (uid, gid), rel)

    def test_incomplete_package_fails_before_creating_target(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-preflight-") as tmp:
            base = pathlib.Path(tmp)
            package = base / "package"
            shutil.copytree(ROOT, package, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
            (package / "ARCHITECTURE.md").unlink()
            project = base / "runtime"
            result = subprocess.run(
                ["bash", str(package / "init-meowhome.sh"), str(project)],
                cwd=package,
                env=self.installer_env(),
                text=True,
                capture_output=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("incomplete installer package; missing ARCHITECTURE.md", result.stderr)
            self.assertFalse(project.exists())

    def test_upgrade_preserves_user_owned_seed_files(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-upgrade-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            (project / "htdocs/example.com").mkdir(parents=True)
            (project / "apache/vhosts").mkdir(parents=True)
            webroot_file = project / "htdocs/example.com/index.php"
            webroot_file.write_text("CUSTOM WEBROOT\n", encoding="utf-8")
            webroot_file.chmod(0o755)
            (project / "apache/vhosts/10-example.conf").write_text("CUSTOM VHOST\n", encoding="utf-8")
            (project / "apache/vhosts/20-templates.conf").write_text("CUSTOM TEMPLATE\n", encoding="utf-8")
            env_file = project / ".env"
            env_file.write_text(
                "PUID=1234\nPGID=2345\nMEOWHOME_HOST_PROJECT_DIR=/old/location\nDOMAINS=example.org\nDB_ROOT_PASSWORD=x\nDB_PASSWORD=y\nFTP_BIND=127.0.0.1\nCERTBOT_ENABLED=false\nDNS_UPDATER_ENABLED=false\n",
                encoding="utf-8",
            )
            env_file.chmod(0o640)
            env_before = env_file.stat()
            self.run_installer(project)
            self.assertEqual(webroot_file.read_text(encoding="utf-8"), "CUSTOM WEBROOT\n")
            self.assertTrue(webroot_file.stat().st_mode & 0o111)
            self.assertEqual((project / "apache/vhosts/10-example.conf").read_text(encoding="utf-8"), "CUSTOM VHOST\n")
            self.assertEqual((project / "apache/vhosts/20-templates.conf").read_text(encoding="utf-8"), "CUSTOM TEMPLATE\n")
            env = env_file.read_text(encoding="utf-8")
            self.assertIn("PUID=1234", env)
            self.assertIn("PGID=2345", env)
            self.assertIn("DOMAINS=example.org", env)
            self.assertIn("DB_ROOT_PASSWORD=x", env)
            self.assertIn("DB_PASSWORD=y", env)
            self.assertIn("FTP_BIND=127.0.0.1", env)
            self.assertIn("CERTBOT_ENABLED=false", env)
            self.assertIn("DNS_UPDATER_ENABLED=false", env)
            self.assertIn(f"MEOWHOME_HOST_PROJECT_DIR={project.resolve()}", env)
            self.assertNotIn("MEOWHOME_HOST_PROJECT_DIR=/old/location", env)
            env_after = env_file.stat()
            self.assertEqual(env_after.st_mode & 0o777, env_before.st_mode & 0o777)
            self.assertEqual((env_after.st_uid, env_after.st_gid), (env_before.st_uid, env_before.st_gid))


    def test_upgrade_does_not_recreate_removed_example_site(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-removed-example-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            self.run_installer(project)
            shutil.rmtree(project / "htdocs/example.com")
            (project / "apache/vhosts/10-example.conf").unlink()
            self.run_installer(project)
            self.assertFalse((project / "htdocs/example.com").exists())
            self.assertFalse((project / "apache/vhosts/10-example.conf").exists())

    def test_upgrade_does_not_rewrite_existing_webroot_ownership_or_mode(self):
        if os.name != "posix":
            self.skipTest("POSIX ownership/mode test")
        with tempfile.TemporaryDirectory(prefix="meowhome-upgrade-permissions-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            webroot = project / "htdocs/example.com"
            webroot.mkdir(parents=True)
            marker = webroot / "marker.txt"
            marker.write_text("keep\n", encoding="utf-8")
            webroot.chmod(0o751)
            marker.chmod(0o640)
            before_dir = webroot.stat()
            before_file = marker.stat()
            (project / ".env").write_text(
                f"PUID={os.getuid()}\nPGID={os.getgid()}\nDOMAINS=example.org\nDB_ROOT_PASSWORD=x\nDB_PASSWORD=y\n",
                encoding="utf-8",
            )
            self.run_installer(project)
            after_dir = webroot.stat()
            after_file = marker.stat()
            self.assertEqual(after_dir.st_mode & 0o777, before_dir.st_mode & 0o777)
            self.assertEqual(after_file.st_mode & 0o777, before_file.st_mode & 0o777)
            self.assertEqual((after_dir.st_uid, after_dir.st_gid), (before_dir.st_uid, before_dir.st_gid))
            self.assertEqual((after_file.st_uid, after_file.st_gid), (before_file.st_uid, before_file.st_gid))

    def test_upgrade_migrates_legacy_ftp_uid_gid_to_canonical_ids(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-upgrade-legacy-ids-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            project.mkdir(parents=True)
            (project / ".env").write_text(
                "FTP_HOST_UID=4242\nFTP_HOST_GID=4343\nDOMAINS=example.org\nDB_ROOT_PASSWORD=x\nDB_PASSWORD=y\n",
                encoding="utf-8",
            )
            self.run_installer(project)
            env = (project / ".env").read_text(encoding="utf-8")
            self.assertIn("FTP_HOST_UID=4242", env)
            self.assertIn("FTP_HOST_GID=4343", env)
            self.assertIn("PUID=4242", env)
            self.assertIn("PGID=4343", env)


    def test_upgrade_collapses_duplicate_canonical_ids_preserving_last_value(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-upgrade-duplicate-ids-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            project.mkdir(parents=True)
            (project / ".env").write_text(
                "PUID=1000\nPGID=1000\nFTP_HOST_UID=1000\nFTP_HOST_GID=1000\nPUID=1001\nPGID=1001\n"
                "DOMAINS=example.org\nDB_ROOT_PASSWORD=x\nDB_PASSWORD=y\n",
                encoding="utf-8",
            )
            result = self.run_installer(project)
            env = (project / ".env").read_text(encoding="utf-8")
            self.assertEqual(env.count("PUID="), 1)
            self.assertEqual(env.count("PGID="), 1)
            self.assertIn("PUID=1001", env)
            self.assertIn("PGID=1001", env)
            self.assertIn("Duplicate PUID entries collapsed", result.stdout)
            self.assertIn("Duplicate PGID entries collapsed", result.stdout)

    def test_upgrade_migrates_legacy_published_ports_to_env(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-upgrade-ports-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            project.mkdir(parents=True)
            (project / ".env").write_text(
                "PUID=1001\nPGID=1001\nDOMAINS=example.org\nDB_ROOT_PASSWORD=x\nDB_PASSWORD=y\n",
                encoding="utf-8",
            )
            (project / "docker-compose.yml").write_text(
                """services:\n
  web:\n    ports:\n      - \"127.0.0.1:8088:80\"\n      - \"8443:443\"\n  phpmyadmin:\n    ports:\n      - \"127.0.0.1:9091:80\"\n  ftp:\n    ports:\n      - \"2121:21\"\n""",
                encoding="utf-8",
            )
            self.run_installer(project)
            env = (project / ".env").read_text(encoding="utf-8")
            self.assertIn("HTTP_BIND=127.0.0.1", env)
            self.assertIn("HTTP_PORT=8088", env)
            self.assertIn("HTTPS_BIND=0.0.0.0", env)
            self.assertIn("HTTPS_PORT=8443", env)
            self.assertIn("PHPMYADMIN_BIND=127.0.0.1", env)
            self.assertIn("PHPMYADMIN_PORT=9091", env)
            self.assertIn("FTP_BIND=0.0.0.0", env)
            self.assertIn("FTP_PORT=2121", env)
            compose = (project / "docker-compose.yml").read_text(encoding="utf-8")
            self.assertIn("${HTTP_BIND:-0.0.0.0}:${HTTP_PORT:-80}:80", compose)
            self.assertIn("${FTP_BIND:-0.0.0.0}:${FTP_PORT:-21}:21", compose)
            self.assertIn("${FTP_BIND:-0.0.0.0}:${FTP_PASV_MIN}-${FTP_PASV_MAX}:${FTP_PASV_MIN}-${FTP_PASV_MAX}", compose)



    def test_external_web_network_is_rendered_from_env(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-external-network-") as tmp:
            project = pathlib.Path(tmp) / "runtime"
            project.mkdir(parents=True)
            (project / ".env").write_text(
                f"PUID={os.getuid()}\nPGID={os.getgid()}\nDOMAINS=example.org\nDB_ROOT_PASSWORD=x\nDB_PASSWORD=y\nMEOWHOME_WEB_EXTERNAL_NETWORKS=streamguide_proxy\n",
                encoding="utf-8",
            )
            self.run_installer(project)
            compose = (project / "docker-compose.yml").read_text(encoding="utf-8")
            web_block = compose.split("  php:", 1)[0]
            self.assertIn("    networks:\n      - default\n      - streamguide_proxy", web_block)
            self.assertIn("networks:\n  control_net:\n    internal: true", compose)
            self.assertIn("  streamguide_proxy:\n    external: true\n    name: streamguide_proxy", compose)

    def test_control_adapter_pins_host_project_dir_and_ui_has_no_socket(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-installer-security-") as td:
            project = pathlib.Path(td) / "meowhome"
            result = self.run_installer(project)
            self.assertEqual(result.returncode, 0, result.stderr)
            compose = (project / "docker-compose.yml").read_text(encoding="utf-8")
            self.assertIn("MEOWHOME_HOST_PROJECT_DIR: ${MEOWHOME_HOST_PROJECT_DIR:?MEOWHOME_HOST_PROJECT_DIR must be set}", compose)
            ui_block = compose.split("  ui:", 1)[1]
            self.assertNotIn("/var/run/docker.sock", ui_block)
            certbot_block = compose.split("  certbot:", 1)[1].split("  dns_updater:", 1)[0]
            self.assertNotIn("/var/run/docker.sock", certbot_block)
            control_block = compose.split("  control:", 1)[1].split("  ui:", 1)[0]
        self.assertIn("${MEOWHOME_DOCKER_SOCKET:-/var/run/docker.sock}:/var/run/docker.sock", control_block)



if __name__ == "__main__":
    unittest.main()
