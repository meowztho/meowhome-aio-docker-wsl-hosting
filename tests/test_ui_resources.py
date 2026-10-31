import importlib.util
import pathlib
import sys
import tempfile
import unittest
from fastapi import HTTPException

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "meowhome-ui"))
ui = importlib.import_module("app.main")


class UiResourceTests(unittest.TestCase):
    def test_hostname_validation_rejects_config_injection(self):
        with self.assertRaises(HTTPException):
            ui.validate_hostname("example.com\nInclude /tmp/evil.conf")

    def test_proxy_target_rejects_quotes_and_userinfo(self):
        with self.assertRaises(HTTPException):
            ui.generate_site_vhost("proxy.example.com", [], "proxy", False, 'http://backend:8000/"\nInclude x', "")
        with self.assertRaises(HTTPException):
            ui.generate_site_vhost("proxy.example.com", [], "proxy", False, "http://user:pass@backend:8000", "")

    def test_generated_website_vhost_uses_selected_certificate(self):
        conf = ui.generate_site_vhost("www.example.com", ["example.com"], "website", True, "", "example.com")
        self.assertIn("ServerName www.example.com", conf)
        self.assertIn("ServerAlias example.com", conf)
        self.assertIn("DocumentRoot /var/www/www.example.com", conf)
        self.assertIn("Redirect permanent / https://www.example.com/", conf)
        self.assertIn("/etc/letsencrypt/live/example.com/fullchain.pem", conf)
        self.assertIn("php-fpm.conf", conf)

    def test_parse_vhost_record_classifies_reverse_proxy(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-vhost-") as tmp:
            path = pathlib.Path(tmp) / "video.example.com.conf"
            path.write_text('''<VirtualHost *:443>\nServerName video.example.com\nSSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem\nProxyPass "/" "http://10.0.0.2:8096/"\n</VirtualHost>\n''', encoding="utf-8")
            row = ui.parse_vhost_record(path)
            self.assertEqual(row["host"], "video.example.com")
            self.assertEqual(row["kind"], "proxy")
            self.assertEqual(row["proxy_target"], "http://10.0.0.2:8096/")
            self.assertEqual(row["cert_domain"], "example.com")
            self.assertTrue(row["tls"])

    def test_site_inventory_ignores_helper_configs_without_server_name(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-sites-") as tmp:
            base = pathlib.Path(tmp)
            (base / "20-templates.conf").write_text("# helper only\n", encoding="utf-8")
            (base / "real.example.com.conf").write_text("<VirtualHost *:80>\nServerName real.example.com\n</VirtualHost>\n", encoding="utf-8")
            old = ui.VHOST_DIR
            try:
                ui.VHOST_DIR = str(base)
                sites = ui.site_inventory()
            finally:
                ui.VHOST_DIR = old
            self.assertEqual([row["host"] for row in sites], ["real.example.com"])

    def test_certificate_inventory_ignores_non_certificate_entries(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-certs-") as tmp:
            root = pathlib.Path(tmp)
            live = root / "letsencrypt" / "live"
            live.mkdir(parents=True)
            (live / "README").write_text("not a certificate", encoding="utf-8")
            incomplete = live / "broken.example.com"
            incomplete.mkdir()
            (incomplete / "fullchain.pem").write_text("placeholder", encoding="utf-8")
            old = ui.PROJECT_DIR
            try:
                ui.PROJECT_DIR = str(root)
                certs = ui.certificate_inventory()
            finally:
                ui.PROJECT_DIR = old
            self.assertEqual(certs, [])


if __name__ == "__main__":
    unittest.main()
