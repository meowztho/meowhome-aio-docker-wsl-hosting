import importlib.util
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("meowhome_control", ROOT / "meowhome-control/server.py")
control = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = control
assert SPEC.loader is not None
SPEC.loader.exec_module(control)


class ControlAdapterTests(unittest.TestCase):
    def test_ftp_adapter_rejects_unknown_commands(self):
        with self.assertRaises(ValueError):
            control.validate_ftp_args(["shell", "id"], None)

    def test_ftp_adapter_rejects_invalid_username(self):
        with self.assertRaises(ValueError):
            control.validate_ftp_args(["passwd", "../../root"], "secret")

    def test_database_identifier_rejects_sql_injection(self):
        self.assertIsNotNone(control.DATABASE_NAME_RE.fullmatch("shop_2026"))
        self.assertIsNone(control.DATABASE_NAME_RE.fullmatch("shop`; DROP DATABASE mysql; --"))

    def test_database_user_rejects_sql_injection_and_unsafe_password(self):
        self.assertEqual(control.validate_database_user("app_user", "A" * 20), "app_user")
        with self.assertRaises(ValueError):
            control.validate_database_user("user'@'%'", "A" * 20)
        with self.assertRaises(ValueError):
            control.validate_database_user("app_user", "unsafe'password")

    def test_site_path_rejects_traversal_and_symlink_escape(self):
        import os
        import tempfile
        with tempfile.TemporaryDirectory(prefix="meowhome-files-") as tmp:
            base = pathlib.Path(tmp)
            (base / ".env").write_text(f"PUID={os.getuid()}\nPGID={os.getgid()}\n")
            (base / "htdocs" / "example.com").mkdir(parents=True)
            outside = base / "outside"
            outside.mkdir()
            (base / "htdocs" / "example.com" / "escape").symlink_to(outside, target_is_directory=True)
            old = control.PROJECT_DIR
            try:
                control.PROJECT_DIR = base
                with self.assertRaises(ValueError):
                    control.safe_site_path("example.com", "../outside")
                with self.assertRaises(ValueError):
                    control.safe_site_path("example.com", "escape")
                broken = base / "htdocs" / "example.com" / "broken"
                broken.symlink_to(base / "missing")
                with self.assertRaises(ValueError):
                    control.safe_site_path("example.com", "broken", must_exist=False)
                root, path = control.safe_site_path("example.com", "")
                self.assertEqual(root, path)
                created = control.write_site_file("example.com", "hello.txt", "hello")
                self.assertTrue(created["ok"])
                self.assertEqual(control.read_site_file("example.com", "hello.txt")["content"], "hello")
                self.assertTrue(control.delete_site_path("example.com", "hello.txt")["ok"])
            finally:
                control.PROJECT_DIR = old

    def test_file_and_database_user_routes_are_fixed_capabilities(self):
        source = (ROOT / "meowhome-control/server.py").read_text(encoding="utf-8")
        for route in ("/v1/files", "/v1/file-read", "/v1/file-write", "/v1/file-upload", "/v1/file-mkdir", "/v1/file-delete", "/v1/database-users", "/v1/database-user-create", "/v1/database-user-drop"):
            self.assertIn(route, source)
        self.assertNotIn('/v1/cron-exec', source)
        self.assertNotIn('/v1/command', source)

    def test_resource_routes_remain_fixed_capabilities(self):
        source = (ROOT / "meowhome-control/server.py").read_text(encoding="utf-8")
        self.assertIn('/v1/databases', source)
        self.assertIn('/v1/database-create', source)
        self.assertIn('/v1/database-drop', source)
        self.assertIn('/v1/webroot-ensure', source)
        self.assertIn('/v1/doctor', source)

    def test_control_service_has_no_generic_exec_route(self):
        source = (ROOT / "meowhome-control/server.py").read_text(encoding="utf-8")
        self.assertNotIn('/v1/exec', source)
        self.assertNotIn('/v1/shell', source)

    def test_admin_and_certbot_tokens_have_distinct_roles(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix="meowhome-control-token-") as tmp:
            base = pathlib.Path(tmp)
            admin = base / "admin.token"
            certbot = base / "certbot.token"
            admin.write_text("a" * 64 + "\n", encoding="utf-8")
            certbot.write_text("b" * 64 + "\n", encoding="utf-8")
            old_admin, old_certbot = control.ADMIN_TOKEN_FILE, control.CERTBOT_TOKEN_FILE
            try:
                control.ADMIN_TOKEN_FILE = admin
                control.CERTBOT_TOKEN_FILE = certbot
                self.assertEqual(control.authorized_role("Bearer " + "a" * 64), "admin")
                self.assertEqual(control.authorized_role("Bearer " + "b" * 64), "certbot")
                self.assertIsNone(control.authorized_role("Bearer " + "c" * 64))
            finally:
                control.ADMIN_TOKEN_FILE = old_admin
                control.CERTBOT_TOKEN_FILE = old_certbot

    def test_certbot_role_is_scoped_to_apache_reload_in_router(self):
        source = (ROOT / "meowhome-control/server.py").read_text(encoding="utf-8")
        self.assertIn('parts.path == "/v1/apache-reload"', source)
        self.assertIn("allow_certbot_reload=True", source)
        self.assertIn("admin_only=True", source)


if __name__ == "__main__":
    unittest.main()
