import importlib.util
import os
import pathlib
import stat
import tempfile
import unittest
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("meowhome_core_cli", ROOT / "assets/tools/meowhome.py")
core = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = core
assert SPEC.loader is not None
SPEC.loader.exec_module(core)


class CoreCliTests(unittest.TestCase):
    def make_project(self, env_text: str) -> pathlib.Path:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="meowhome-core-test-"))
        directory_paths = {"apache/vhosts", "htdocs"}
        for rel in core.CORE_PATHS:
            p = tmp / rel
            if rel in directory_paths:
                p.mkdir(parents=True, exist_ok=True)
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("# test\n", encoding="utf-8")
        (tmp / ".env").write_text(env_text, encoding="utf-8")
        control = tmp / "control"
        control.mkdir(parents=True, exist_ok=True)
        for name, char in (("control.token", "x"), ("certbot.token", "y")):
            token = control / name
            token.write_text(char * 64 + "\n", encoding="utf-8")
            token.chmod(0o600)
        return tmp

    def valid_env(self) -> str:
        return "\n".join([
            "PUID=1000", "PGID=1000", "MEOWHOME_HOST_PROJECT_DIR=/srv/meowhome",
            "DOMAINS=example.org", "FTP_PUBLIC_HOST=ftp.example.org",
            "CERTBOT_ENABLED=false", "DNS_UPDATER_ENABLED=false", "ACME_CHALLENGE=http",
            "DB_ROOT_PASSWORD=strong-root-secret", "DB_PASSWORD=strong-app-secret",
            "MEOWHOME_UI_BIND=127.0.0.1", "MEOWHOME_UI_PASS=strong-ui-secret",
            "FTP_PASV_MIN=21000", "FTP_PASV_MAX=21010", "FTP_TLS=NO",
        ])

    def test_cli_version_matches_release_version(self):
        expected = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual(core.VERSION, expected)

    def test_valid_static_config_has_no_errors(self):
        project = self.make_project(self.valid_env())
        report = core.doctor(project, include_runtime=False)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["summary"]["errors"], 0)


    def test_host_project_dir_is_required_and_absolute(self):
        missing = self.make_project(self.valid_env().replace("MEOWHOME_HOST_PROJECT_DIR=/srv/meowhome\n", ""))
        missing_codes = [issue.code for issue in core.validate_config(missing)]
        self.assertIn("host_project_dir_missing", missing_codes)

        relative = self.make_project(self.valid_env().replace("MEOWHOME_HOST_PROJECT_DIR=/srv/meowhome", "MEOWHOME_HOST_PROJECT_DIR=./meowhome"))
        relative_codes = [issue.code for issue in core.validate_config(relative)]
        self.assertIn("host_project_dir_relative", relative_codes)

    def test_control_socket_path_must_be_absolute(self):
        project = self.make_project(self.valid_env() + "\nMEOWHOME_DOCKER_SOCKET=relative.sock\n")
        self.assertIn("docker_socket_relative", {issue.code for issue in core.validate_config(project)})

    def test_cloudflare_requirement_is_explicit(self):
        project = self.make_project(self.valid_env().replace("CERTBOT_ENABLED=false", "CERTBOT_ENABLED=true").replace("ACME_CHALLENGE=http", "ACME_CHALLENGE=dns") + "\nLE_EMAIL=admin@example.org\nCLOUDFLARE_API_TOKEN=PASTE_TOKEN_HERE")
        report = core.doctor(project, include_runtime=False)
        codes = {item["code"] for item in report["issues"] if item["severity"] == "error"}
        self.assertIn("cloudflare_token_missing", codes)

    def test_legacy_and_numeric_config_are_reported(self):
        project = self.make_project(self.valid_env() + "\nFTP_ENABLED=true\nCERTBOT_RETRY_SECONDS=5")
        codes = [issue.code for issue in core.validate_config(project)]
        self.assertIn("legacy_ftp_enabled", codes)
        self.assertIn("numeric_range", codes)

    def test_lan_ui_with_default_password_is_error(self):
        env = self.valid_env().replace("MEOWHOME_UI_BIND=127.0.0.1", "MEOWHOME_UI_BIND=0.0.0.0").replace("MEOWHOME_UI_PASS=strong-ui-secret", "MEOWHOME_UI_PASS=admin")
        report = core.doctor(self.make_project(env), include_runtime=False)
        issues = [i for i in report["issues"] if i["code"] == "ui_default_password"]
        self.assertEqual(issues[0]["severity"], "error")


    def test_duplicate_canonical_ids_are_errors_and_last_value_is_effective(self):
        env = self.valid_env() + "\nPUID=1001\nPGID=1001"
        project = self.make_project(env)
        issues = core.validate_config(project)
        duplicate_issues = [i for i in issues if i.code == "duplicate_env_key"]
        self.assertEqual(len(duplicate_issues), 2)
        self.assertTrue(all(i.severity == "error" for i in duplicate_issues))
        self.assertEqual(core.read_env(project / ".env")["PUID"], "1001")
        self.assertEqual(core.read_env(project / ".env")["PGID"], "1001")

    def test_ftp_generated_state_drift_is_reported(self):
        project = self.make_project(self.valid_env())
        import sqlite3
        db_path = project / "ftp/users.sqlite"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        con = sqlite3.connect(db_path)
        try:
            con.execute("CREATE TABLE users (username TEXT PRIMARY KEY, pass_hash TEXT NOT NULL, home_rel TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1)")
            con.execute("INSERT INTO users VALUES ('testuser', 'hash', '', 1)")
            con.commit()
        finally:
            con.close()
        users_d = project / "ftp/data/users.d"
        users_d.mkdir(parents=True)
        (users_d / "testuser").write_text("local_root=/var/www\n", encoding="utf-8")
        (users_d / "test").write_text("local_root=/var/www\n", encoding="utf-8")
        codes = [issue.code for issue in core.validate_config(project)]
        self.assertIn("ftp_generated_state_drift", codes)
        self.assertIn("ftp_all_domains", codes)

    def test_sensitive_env_permissions_are_reported(self):
        project = self.make_project(self.valid_env())
        (project / ".env").chmod(0o644)
        codes = [issue.code for issue in core.validate_config(project)]
        self.assertIn("sensitive_permissions", codes)



    def test_repair_control_plane_normalizes_only_managed_apache_metadata(self):
        env = self.valid_env().replace("PUID=1000", f"PUID={os.getuid()}").replace("PGID=1000", f"PGID={os.getgid()}")
        project = self.make_project(env)
        snippets = project / "apache/snippets"
        snippets.mkdir(parents=True, exist_ok=True)
        vhost = project / "apache/vhosts/example.org.conf"
        vhost.write_text("<VirtualHost *:80>\n</VirtualHost>\n", encoding="utf-8")
        vhost.chmod(0o600)
        snippet = snippets / "ssl-common.conf"
        snippet.write_text("# managed\n", encoding="utf-8")
        snippet.chmod(0o600)

        result = core.repair_control_plane_permissions(project)

        self.assertEqual(stat.S_IMODE((project / "apache/vhosts").stat().st_mode), 0o2775)
        self.assertEqual(stat.S_IMODE(vhost.stat().st_mode), 0o664)
        self.assertEqual(stat.S_IMODE(snippet.stat().st_mode), 0o644)
        self.assertIn("apache/vhosts/example.org.conf", result["changed"])

    def test_doctor_reports_missing_managed_aop_ca(self):
        project = self.make_project(self.valid_env())
        (project / "apache/vhosts/example.org.conf").write_text(
            "SSLCACertificateFile /etc/apache2/snippets/cloudflare-origin-pull-ca.pem\nSSLVerifyClient require\n",
            encoding="utf-8",
        )
        report = core.doctor(project, include_runtime=False)
        issues = [item for item in report["issues"] if item["code"] == "cloudflare_aop_ca_missing"]
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["severity"], "error")

    def test_invalid_external_network_name_is_rejected(self):
        project = self.make_project(self.valid_env() + "\nMEOWHOME_WEB_EXTERNAL_NETWORKS=ok,bad network")
        codes = [issue.code for issue in core.validate_config(project)]
        self.assertIn("external_network_name", codes)

    def test_missing_control_token_is_error(self):
        project = self.make_project(self.valid_env())
        (project / "control/certbot.token").unlink()
        report = core.doctor(project, include_runtime=False)
        issues = [item for item in report["issues"] if item["code"] == "control_token_missing"]
        self.assertTrue(any("certbot.token" in item["message"] for item in issues))
        self.assertFalse(report["ok"])

    def test_historical_env_backup_permissions_are_reported(self):
        project = self.make_project(self.valid_env())
        backup = project / ".env.pre-2.6.2"
        backup.write_text("DB_PASSWORD=secret\n", encoding="utf-8")
        backup.chmod(0o644)
        issues = core.validate_config(project)
        matches = [i for i in issues if i.code == "sensitive_permissions" and ".env.pre-2.6.2" in i.message]
        self.assertEqual(len(matches), 1)

    def test_proxy_override_typo_outside_managed_domains_is_reported(self):
        project = self.make_project(self.valid_env() + "\nPROXIED_OVERRIDES=mail.it.phi.de=false")
        codes = [issue.code for issue in core.validate_config(project)]
        self.assertIn("proxied_override_outside_domains", codes)

    def test_spf_reconciliation_requires_complete_template(self):
        project = self.make_project(self.valid_env() + "\nSPF_UPDATE_example_org=true")
        report = core.doctor(project, include_runtime=False)
        codes = [item["code"] for item in report["issues"] if item["severity"] == "error"]
        self.assertIn("spf_template_missing", codes)

    def test_doctor_rejects_direct_ui_or_certbot_docker_socket(self):
        project = self.make_project(self.valid_env())
        (project / "docker-compose.yml").write_text(
            "services:\n"
            "  ui:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n"
            "  certbot:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n",
            encoding="utf-8",
        )
        issues = [i for i in core.validate_config(project) if i.code == "docker_socket_exposure"]
        self.assertEqual({"ui", "certbot"}, {i.message.split()[0] for i in issues})


if __name__ == "__main__":
    unittest.main()
