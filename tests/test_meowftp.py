import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest import mock
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("meowftp_test", ROOT / "assets/tools/ftp/meowftp.py")
meowftp = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = meowftp
assert SPEC.loader is not None
SPEC.loader.exec_module(meowftp)


class MeowFtpTests(unittest.TestCase):
    def symlink_dir(self, link: pathlib.Path, target: pathlib.Path) -> None:
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory symlinks are unavailable: {exc}")

    def test_home_path_contract(self):
        self.assertEqual(meowftp.normalize_home_rel("shop/example.com"), "shop/example.com")
        self.assertEqual(meowftp.normalize_home_rel("foo..bar"), "foo..bar")
        self.assertEqual(meowftp.normalize_home_rel("./example.com"), "example.com")
        with self.assertRaises(SystemExit):
            meowftp.normalize_home_rel("../secret")
        with self.assertRaises(SystemExit):
            meowftp.normalize_home_rel("/absolute")

    def test_home_path_rejects_symlink_components(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-symlink-home-") as td:
            htdocs = pathlib.Path(td) / "htdocs"
            (htdocs / "owned.example").mkdir(parents=True)
            (htdocs / "other.example").mkdir()
            self.symlink_dir(htdocs / "owned.example" / "nested-link", htdocs / "other.example")
            self.symlink_dir(htdocs / "alias.example", htdocs / "other.example")
            old_htdocs = meowftp.HTDOCS
            try:
                meowftp.HTDOCS = str(htdocs)
                with self.assertRaises(SystemExit):
                    meowftp.normalize_home_rel("alias.example")
                with self.assertRaises(SystemExit):
                    meowftp.normalize_home_rel("owned.example/nested-link/private")
            finally:
                meowftp.HTDOCS = old_htdocs

    def test_domain_assignment_rejects_symlink_domain_root(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-symlink-domain-") as td:
            htdocs = pathlib.Path(td) / "htdocs"
            (htdocs / "owned.example").mkdir(parents=True)
            (htdocs / "other.example").mkdir()
            self.symlink_dir(htdocs / "alias.example", htdocs / "other.example")
            old_htdocs = meowftp.HTDOCS
            try:
                meowftp.HTDOCS = str(htdocs)
                self.assertEqual(meowftp.normalize_domain("owned.example"), "owned.example")
                self.assertEqual(meowftp.available_domains(), ["other.example", "owned.example"])
                with self.assertRaises(SystemExit):
                    meowftp.normalize_domain("alias.example")
                with self.assertRaises(SystemExit):
                    meowftp._local_root_for({
                        "username": "alice", "access_mode": "domains", "home_rel": "",
                        "domains": ["alias.example"],
                    })
                with self.assertRaises(SystemExit):
                    meowftp._compose_override_content([{
                        "username": "alice", "access_mode": "domains", "home_rel": "",
                        "domains": ["owned.example", "alias.example"],
                    }])
            finally:
                meowftp.HTDOCS = old_htdocs

    def test_apply_revalidates_persisted_symlink_roots_before_reconcile(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-symlink-apply-") as td:
            htdocs = pathlib.Path(td) / "htdocs"
            (htdocs / "other.example").mkdir(parents=True)
            self.symlink_dir(htdocs / "alias.example", htdocs / "other.example")
            old_htdocs = meowftp.HTDOCS
            try:
                meowftp.HTDOCS = str(htdocs)
                users = [
                    {
                        "username": "alice", "pass_hash": "$6$hash", "home_rel": "alias.example",
                        "enabled": True, "access_mode": "path", "domains": [],
                    },
                    {
                        "username": "bob", "pass_hash": "$6$hash", "home_rel": "",
                        "enabled": True, "access_mode": "domains", "domains": ["alias.example"],
                    },
                ]
                for user in users:
                    with self.subTest(access_mode=user["access_mode"]), \
                         mock.patch.object(meowftp.os, "geteuid", return_value=0), \
                         mock.patch.object(meowftp, "_user_records", return_value=[user]), \
                         mock.patch.object(meowftp, "compose") as compose, \
                         mock.patch.object(meowftp, "write_compose_override") as write_override:
                        with self.assertRaises(SystemExit):
                            meowftp.apply()
                        compose.assert_not_called()
                        write_override.assert_not_called()
            finally:
                meowftp.HTDOCS = old_htdocs

    def test_username_contract(self):
        self.assertEqual(meowftp.validate_username("alice-01_test"), "alice-01_test")
        for value in ("", "a b", "älice", "a" * 33, "alice/example"):
            with self.subTest(value=value), self.assertRaises(SystemExit):
                meowftp.validate_username(value)

    def test_password_hash_uses_stdin_not_process_args(self):
        captured = {}
        def fake(cmd, input=None, text=None):
            captured["cmd"] = cmd
            captured["input"] = input
            return "$6$hash\n"
        with mock.patch.object(meowftp.subprocess, "check_output", side_effect=fake):
            out = meowftp.hash_pw_sha512_crypt("super-secret")
        self.assertEqual(out, "$6$hash")
        self.assertNotIn("super-secret", captured["cmd"])
        self.assertEqual(captured["input"], "super-secret\n")
        self.assertIn("-stdin", captured["cmd"])

    def test_puid_pgid_are_authoritative(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-env-") as td:
            env = pathlib.Path(td) / ".env"
            env.write_text("PUID=1234\nPGID=2345\nFTP_HOST_UID=1000\nFTP_HOST_GID=1000\n", encoding="utf-8")
            old = meowftp.ENV_PATH
            try:
                meowftp.ENV_PATH = str(env)
                self.assertEqual(meowftp.host_uid_gid(), (1234, 2345))
            finally:
                meowftp.ENV_PATH = old


    def test_duplicate_puid_pgid_use_last_assignment(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-env-duplicate-") as td:
            env = pathlib.Path(td) / ".env"
            env.write_text(
                "PUID=1000\nPGID=1000\nFTP_HOST_UID=1000\nFTP_HOST_GID=1000\nPUID=1001\nPGID=1001\n",
                encoding="utf-8",
            )
            old = meowftp.ENV_PATH
            try:
                meowftp.ENV_PATH = str(env)
                self.assertEqual(meowftp.host_uid_gid(), (1001, 1001))
            finally:
                meowftp.ENV_PATH = old

    def test_user_database_permissions_are_private(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-db-") as td:
            old = meowftp.DB_PATH
            try:
                meowftp.DB_PATH = str(pathlib.Path(td) / "users.sqlite")
                con = meowftp.db()
                con.close()
                self.assertEqual(pathlib.Path(meowftp.DB_PATH).stat().st_mode & 0o777, 0o600)
            finally:
                meowftp.DB_PATH = old


    def test_legacy_database_migrates_access_mode_without_losing_users(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-migrate-") as td:
            root = pathlib.Path(td)
            db_path = root / "ftp" / "users.sqlite"
            db_path.parent.mkdir(parents=True)
            import sqlite3
            con = sqlite3.connect(db_path)
            con.execute("CREATE TABLE users (username TEXT PRIMARY KEY, pass_hash TEXT NOT NULL, home_rel TEXT NOT NULL DEFAULT '', enabled INTEGER NOT NULL DEFAULT 1)")
            con.execute("INSERT INTO users VALUES ('alluser', '$6$hash', '', 1)")
            con.execute("INSERT INTO users VALUES ('siteuser', '$6$hash', 'example.com', 1)")
            con.commit()
            con.close()
            old_db, old_env = meowftp.DB_PATH, meowftp.ENV_PATH
            try:
                meowftp.DB_PATH = str(db_path)
                meowftp.ENV_PATH = str(root / '.env')
                migrated = meowftp.db()
                try:
                    rows = dict(migrated.execute("SELECT username, access_mode FROM users"))
                finally:
                    migrated.close()
                self.assertEqual(rows, {"alluser": "all", "siteuser": "path"})
            finally:
                meowftp.DB_PATH, meowftp.ENV_PATH = old_db, old_env

    def test_domain_assignments_use_direct_root_for_one_and_view_for_multiple(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-local-root-") as td:
            htdocs = pathlib.Path(td) / "htdocs"
            (htdocs / "a.example").mkdir(parents=True)
            (htdocs / "b.example").mkdir()
            old_htdocs = meowftp.HTDOCS
            try:
                meowftp.HTDOCS = str(htdocs)
                one = {"username": "alice", "access_mode": "domains", "home_rel": "", "domains": ["a.example"]}
                many = {"username": "alice", "access_mode": "domains", "home_rel": "", "domains": ["a.example", "b.example"]}
                path = {"username": "alice", "access_mode": "path", "home_rel": "a.example"}
                all_domains = {"username": "alice", "access_mode": "all", "home_rel": ""}
                self.assertEqual(meowftp._local_root_for(one), "/var/www/a.example")
                self.assertEqual(meowftp._local_root_for(many), "/srv/meowftp/views/alice")
                self.assertEqual(meowftp._local_root_for(path), "/var/www/a.example")
                self.assertEqual(meowftp._local_root_for(all_domains), "/var/www")
            finally:
                meowftp.HTDOCS = old_htdocs

    def test_generated_compose_override_contains_only_multi_domain_mounts(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-override-") as td:
            root = pathlib.Path(td)
            htdocs = root / "htdocs"
            (htdocs / "a.example").mkdir(parents=True)
            (htdocs / "b.example").mkdir()
            override = root / "docker-compose.override.yml"
            old_htdocs = meowftp.HTDOCS
            old_override = meowftp.COMPOSE_OVERRIDE_PATH
            try:
                meowftp.HTDOCS = str(htdocs)
                meowftp.COMPOSE_OVERRIDE_PATH = str(override)
                users = [
                    {"username": "single", "access_mode": "domains", "home_rel": "", "domains": ["a.example"]},
                    {"username": "multi", "access_mode": "domains", "home_rel": "", "domains": ["a.example", "b.example"]},
                ]
                self.assertTrue(meowftp.write_compose_override(users))
                text = override.read_text(encoding="utf-8")
                self.assertTrue(text.startswith(meowftp.GENERATED_OVERRIDE_MARKER))
                self.assertIn('${MEOWHOME_HOST_PROJECT_DIR:-.}/htdocs/a.example', text)
                self.assertIn('/srv/meowftp/views/multi/a.example', text)
                self.assertIn('/srv/meowftp/views/multi/b.example', text)
                self.assertNotIn('/srv/meowftp/views/single/', text)
            finally:
                meowftp.HTDOCS = old_htdocs
                meowftp.COMPOSE_OVERRIDE_PATH = old_override

    def test_generated_override_is_removed_when_no_longer_needed(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-override-remove-") as td:
            override = pathlib.Path(td) / "docker-compose.override.yml"
            override.write_text(meowftp.GENERATED_OVERRIDE_MARKER + "\nservices: {}\n", encoding="utf-8")
            old_override = meowftp.COMPOSE_OVERRIDE_PATH
            try:
                meowftp.COMPOSE_OVERRIDE_PATH = str(override)
                self.assertTrue(meowftp.write_compose_override([]))
                self.assertFalse(override.exists())
            finally:
                meowftp.COMPOSE_OVERRIDE_PATH = old_override

    def test_custom_compose_override_is_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix="meowftp-custom-override-") as td:
            root = pathlib.Path(td)
            htdocs = root / "htdocs"
            (htdocs / "a.example").mkdir(parents=True)
            (htdocs / "b.example").mkdir()
            override = root / "docker-compose.override.yml"
            override.write_text("services:\n  php:\n    environment:\n      CUSTOM: yes\n", encoding="utf-8")
            old_htdocs = meowftp.HTDOCS
            old_override = meowftp.COMPOSE_OVERRIDE_PATH
            try:
                meowftp.HTDOCS = str(htdocs)
                meowftp.COMPOSE_OVERRIDE_PATH = str(override)
                users = [{"username": "alice", "access_mode": "domains", "home_rel": "", "domains": ["a.example", "b.example"]}]
                with self.assertRaises(SystemExit):
                    meowftp.write_compose_override(users)
                self.assertIn("CUSTOM", override.read_text(encoding="utf-8"))
            finally:
                meowftp.HTDOCS = old_htdocs
                meowftp.COMPOSE_OVERRIDE_PATH = old_override

if __name__ == "__main__":
    unittest.main()
