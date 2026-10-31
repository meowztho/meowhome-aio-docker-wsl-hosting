from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WarmupContractTests(unittest.TestCase):
    def test_warmup_requires_real_engine_and_fresh_bind_probe_before_recreate(self):
        text = (ROOT / "assets/tools/warmup.sh").read_text(encoding="utf-8")
        self.assertNotIn("docker info >/dev/null", text)
        self.assertIn("MEOWHOME_DOCKER_SERVER={{.Server.Version}}", text)
        self.assertIn("MEOWHOME_BIND_OK", text)
        self.assertIn('test -f /meowhome-probe/VERSION', text)
        self.assertIn("seq 1 180", text)
        self.assertIn("compose up -d --force-recreate --no-build", text)
        self.assertNotIn("compose restart", text)


if __name__ == "__main__":
    unittest.main()
