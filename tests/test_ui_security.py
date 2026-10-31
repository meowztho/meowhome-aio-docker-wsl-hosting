import importlib.util
import json
import pathlib
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

from starlette.requests import Request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "meowhome-ui"))
ui = importlib.import_module("app.main")


class UiSecurityTests(unittest.TestCase):
    def request(self, headers=None, cookies=None):
        raw_headers = []
        for k, v in (headers or {}).items():
            raw_headers.append((k.lower().encode(), v.encode()))
        if cookies:
            cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
            raw_headers.append((b"cookie", cookie.encode()))
        scope = {
            "type": "http", "http_version": "1.1", "method": "POST", "scheme": "http",
            "path": "/", "raw_path": b"/", "query_string": b"", "headers": raw_headers,
            "client": ("127.0.0.1", 12345), "server": ("127.0.0.1", 9090),
        }
        return Request(scope)

    def test_same_origin_accepts_matching_origin(self):
        req = self.request({"Host": "127.0.0.1:9090", "Origin": "http://127.0.0.1:9090"})
        self.assertTrue(ui._same_origin_request(req))

    def test_same_origin_rejects_foreign_origin(self):
        req = self.request({"Host": "127.0.0.1:9090", "Origin": "https://evil.example"})
        self.assertFalse(ui._same_origin_request(req))

    def test_same_origin_rejects_scheme_mismatch(self):
        req = self.request({"Host": "127.0.0.1:9090", "Origin": "https://127.0.0.1:9090"})
        self.assertFalse(ui._same_origin_request(req))

    def test_csrf_token_is_bound_to_cookie_value(self):
        req1 = self.request({"Host": "127.0.0.1:9090"}, {ui.CSRF_COOKIE: "A" * 40})
        req2 = self.request({"Host": "127.0.0.1:9090"}, {ui.CSRF_COOKIE: "B" * 40})
        self.assertNotEqual(ui.csrf_token_for_request(req1), ui.csrf_token_for_request(req2))

    def test_every_post_route_requires_csrf_dependency(self):
        missing = []
        for route in ui.app.routes:
            methods = getattr(route, "methods", set()) or set()
            if "POST" not in methods:
                continue
            calls = [getattr(dep, "call", None) for dep in route.dependant.dependencies]
            if ui.require_csrf not in calls:
                missing.append(route.path)
        self.assertEqual(missing, [])

    def test_every_post_form_contains_csrf_field(self):
        forms = 0
        tokens = 0
        for path in (ROOT / "meowhome-ui/app/templates").glob("*.html"):
            text = path.read_text(encoding="utf-8")
            forms += len(re.findall(r'<form\b[^>]*method=["\']post["\']', text, re.I))
            tokens += text.count('name="csrf_token"')
        self.assertGreater(forms, 0)
        self.assertEqual(tokens, forms)

    def test_audit_records_only_actor_action_target_outcome(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-audit-") as td:
            log = pathlib.Path(td) / "audit.jsonl"
            with patch.object(ui, "AUDIT_LOG", str(log)), patch.object(ui, "set_host_file_metadata"):
                ui.audit_event("operator", "file_write", "example.org/index.php", False,
                               "synthetic password=do-not-persist")
            event = json.loads(log.read_text())
            self.assertEqual(set(event), {"ts", "actor", "action", "target", "success"})
            self.assertFalse(event["success"])
            self.assertNotIn("do-not-persist", log.read_text())

    def test_ui_image_has_no_docker_client_dependency(self):
        dockerfile = (ROOT / "meowhome-ui/Dockerfile").read_text(encoding="utf-8")
        self.assertNotIn("docker:27-cli", dockerfile)
        self.assertNotIn("docker==", dockerfile)


if __name__ == "__main__":
    unittest.main()
