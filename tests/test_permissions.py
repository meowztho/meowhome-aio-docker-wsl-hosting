import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "assets/tools/permissions_hardening.sh"


class PermissionsHardeningTests(unittest.TestCase):
    def test_duplicate_ids_use_last_assignment(self):
        with tempfile.TemporaryDirectory(prefix="meowhome-perm-test-") as td:
            base = pathlib.Path(td)
            project = base / "runtime"
            webroot = project / "htdocs"
            webroot.mkdir(parents=True)
            (project / ".env").write_text(
                "PUID=1000\nPGID=1000\nPUID=1001\nPGID=1001\n",
                encoding="utf-8",
            )

            fakebin = base / "bin"
            fakebin.mkdir()
            log = base / "sudo.log"
            (fakebin / "id").write_text(
                "#!/bin/sh\nif [ \"$1\" = \"-u\" ]; then echo 1001; else /usr/bin/id \"$@\"; fi\n",
                encoding="utf-8",
            )
            (fakebin / "sudo").write_text(
                f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {log}\nexit 0\n",
                encoding="utf-8",
            )
            (fakebin / "id").chmod(0o755)
            (fakebin / "sudo").chmod(0o755)

            env = os.environ.copy()
            env["PATH"] = f"{fakebin}:{env['PATH']}"
            env["SUDO_UID"] = "1001"
            env["SUDO_GID"] = "1001"
            subprocess.run(
                ["bash", str(SCRIPT), "--project", str(project), "--apply"],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=True,
            )
            calls = log.read_text(encoding="utf-8")
            self.assertIn(f"chown -R 1001:1001 {webroot}", calls)
            self.assertNotIn("chown -R 1000:1000", calls)


if __name__ == "__main__":
    unittest.main()
