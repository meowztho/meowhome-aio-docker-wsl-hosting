import importlib.util
import os
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class DnsHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="meowhome-dns-test-")
        os.environ["CLOUDFLARE_API_TOKEN"] = "test-token"
        os.environ["DOMAINS"] = "example.org"
        os.environ["STATE_DIR"] = cls.tmp.name
        spec = importlib.util.spec_from_file_location("dns_updater_test", ROOT / "DNSUpdatecloudflare.py")
        cls.mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(cls.mod)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_spf_template_renders_public_ip(self):
        self.assertEqual(
            self.mod.render_spf_template("v=spf1 a mx ip4:{PUBLIC_IP} ~all", "203.0.113.5"),
            "v=spf1 a mx ip4:203.0.113.5 ~all",
        )

    def test_spf_template_rejects_non_spf_content(self):
        with self.assertRaises(ValueError):
            self.mod.render_spf_template("ip4:{PUBLIC_IP}", "203.0.113.5")

    def test_spf_updates_are_opt_in_by_default(self):
        entry = self.mod.load_domains_from_env()[0]
        self.assertFalse(entry["spf_update"])


if __name__ == "__main__":
    unittest.main()
