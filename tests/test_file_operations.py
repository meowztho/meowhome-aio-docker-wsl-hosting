import base64
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("file_control", ROOT / "meowhome-control/server.py")
control = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = control
SPEC.loader.exec_module(control)


class FileOperationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="meowhome-file-regression-")
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name)
        self.site = self.base / "htdocs" / "example.com"
        self.site.mkdir(parents=True)
        (self.base / ".env").write_text(f"PUID={os.getuid()}\nPGID={os.getgid()}\n")
        self.old_project = control.PROJECT_DIR
        control.PROJECT_DIR = self.base
        self.addCleanup(setattr, control, "PROJECT_DIR", self.old_project)

    def test_delete_link_preserves_target_and_link(self):
        target = self.site / "real.txt"
        target.write_text("keep me")
        link = self.site / "alias.txt"
        link.symlink_to("real.txt")
        with self.assertRaises(ValueError):
            control.delete_site_path("example.com", "alias.txt")
        self.assertEqual(target.read_text(), "keep me")
        self.assertTrue(link.is_symlink())
        self.assertEqual({x["name"]: x["kind"] for x in control.list_site_files("example.com", "")["entries"]},
                         {"real.txt": "file", "alias.txt": "symlink"})

    def test_upload_rejects_dangling_link(self):
        target = self.base / "outside.txt"
        (self.site / "broken.txt").symlink_to(target)
        with self.assertRaises(ValueError):
            control.upload_site_file("example.com", "", "broken.txt", base64.b64encode(b"bad").decode(), True)
        self.assertFalse(target.exists())

    def test_site_root_cannot_alias_another_site(self):
        (self.base / "htdocs" / "alias.com").symlink_to(self.site, target_is_directory=True)
        with self.assertRaises(ValueError):
            control.list_site_files("alias.com", "")
        with self.assertRaises(OSError):
            control.ensure_webroot("alias.com", True)
        self.assertFalse((self.site / "index.html").exists())

    def test_symlink_swap_after_validation_cannot_write_outside(self):
        folder = self.site / "files"
        folder.mkdir()
        outside = self.base / "outside"
        outside.mkdir()
        target = outside / "important.txt"
        target.write_text("original")
        original_open = os.open

        def swap(path, flags, *args, **kwargs):
            if path == "files" and not folder.is_symlink():
                folder.rmdir()
                folder.symlink_to(outside, target_is_directory=True)
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(control.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                control.write_site_file("example.com", "files/important.txt", "bad")
        self.assertEqual(target.read_text(), "original")

    def test_leaf_symlink_swap_cannot_truncate_target(self):
        outside = self.base / "outside.txt"
        outside.write_text("original")
        target = self.site / "upload.txt"
        original_open = os.open

        def swap(path, flags, *args, **kwargs):
            if path == "upload.txt" and not target.is_symlink():
                target.symlink_to(outside)
            return original_open(path, flags, *args, **kwargs)

        with mock.patch.object(control.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                control.write_site_file("example.com", "upload.txt", "bad")
        self.assertEqual(outside.read_text(), "original")

    def test_hard_link_is_not_overwritten(self):
        original = self.base / "original.txt"
        original.write_text("keep me")
        os.link(original, self.site / "linked.txt")
        with self.assertRaises(ValueError):
            control.write_site_file("example.com", "linked.txt", "bad")
        self.assertEqual(original.read_text(), "keep me")

    def test_normal_file_lifecycle_and_no_implicit_overwrite(self):
        control.mkdir_site("example.com", "", "assets")
        control.upload_site_file("example.com", "assets", "hello.txt", base64.b64encode(b"hello").decode(), False)
        with self.assertRaises(FileExistsError):
            control.upload_site_file("example.com", "assets", "hello.txt", base64.b64encode(b"bad").decode(), False)
        self.assertEqual(control.read_site_file("example.com", "assets/hello.txt")["content"], "hello")
        control.write_site_file("example.com", "assets/hello.txt", "short")
        control.write_site_file("example.com", "assets/hello.txt", "x")
        self.assertEqual(control.read_site_file("example.com", "assets/hello.txt")["content"], "x")
        self.assertEqual((self.site / "assets").stat().st_mode & 0o7777, 0o2775)
        self.assertEqual((self.site / "assets/hello.txt").stat().st_mode & 0o777, 0o664)
        control.delete_site_path("example.com", "assets/hello.txt")
        control.delete_site_path("example.com", "assets")
        with self.assertRaises(ValueError):
            control.delete_site_path("example.com", "")
        self.assertTrue(self.site.exists())

    def test_webroot_reuse_preserves_existing_metadata_and_content(self):
        self.site.chmod(0o750)
        (self.site / "index.html").write_text("keep")
        result = control.ensure_webroot("example.com", True)
        self.assertFalse(result["created"])
        self.assertEqual(self.site.stat().st_mode & 0o777, 0o750)
        self.assertEqual((self.site / "index.html").read_text(), "keep")
        result = control.ensure_webroot("new.example.com", True)
        self.assertTrue(result["created"])
        self.assertTrue((self.base / "htdocs/new.example.com/index.html").is_file())


if __name__ == "__main__":
    unittest.main()
