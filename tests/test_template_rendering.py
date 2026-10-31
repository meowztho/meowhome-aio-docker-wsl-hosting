import importlib
import pathlib
import re
import sys
import unittest
from subprocess import CompletedProcess
from unittest.mock import patch

from fastapi.testclient import TestClient


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "meowhome-ui"))
ui = importlib.import_module("app.main")


class TemplateRenderingTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(ui.app)
        self.auth = (ui.UI_USER, ui.UI_PASS)

    def csrf_token(self):
        with patch.object(ui, "ensure_backup_tool"), patch.object(ui, "list_backups", return_value=[]):
            response = self.client.get("/backup", auth=self.auth)
        self.assertEqual(response.status_code, 200)
        match = re.search(r'name="csrf_token" value="([a-f0-9]+)"', response.text)
        self.assertIsNotNone(match)
        return match.group(1)

    def test_real_get_routes_render_templates(self):
        with patch.object(ui, "ensure_backup_tool") as ensure_backup, patch.object(
            ui, "list_backups", return_value=[{"name": "meowhome-backup-a.tar.gz", "size": 12, "mtime": 1}]
        ):
            response = self.client.get("/backup", auth=self.auth)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Neues Backup", response.text)
        self.assertIn("meowhome-backup-a.tar.gz", response.text)
        ensure_backup.assert_called_once_with()

        with patch.object(ui, "certificate_inventory", return_value=[]), patch.object(
            ui, "site_inventory", return_value=[]
        ):
            sites = self.client.get("/sites", auth=self.auth)
        self.assertEqual(sites.status_code, 200)
        self.assertIn("0 Hosting-Einträge", sites.text)
        self.assertIn("Noch keine VHosts vorhanden", sites.text)

    def test_real_post_route_renders_success_and_error_templates(self):
        token = self.csrf_token()
        headers = {"Origin": "http://testserver"}

        with patch.object(ui, "ensure_backup_tool"), patch.object(ui, "list_backups", return_value=[]), patch.object(
            ui,
            "control_proc",
            return_value=CompletedProcess(
                ["backup"], 0, "[backup] Fertig: /backups/meowhome-backup-test.tar.gz", "",
            ),
        ) as control_proc, patch.object(ui, "audit_event") as audit_event:
            success = self.client.post(
                "/backup/create",
                data={"csrf_token": token, "with_htdocs": "true"},
                headers=headers,
                auth=self.auth,
            )
        self.assertEqual(success.status_code, 200)
        self.assertIn("Neues Backup", success.text)
        self.assertIn("meowhome-backup-test.tar.gz", success.text)
        self.assertIn("Backup erstellen", success.text)
        control_proc.assert_called_once_with("/v1/backup-create", {"with_htdocs": True}, timeout=3600)
        audit_event.assert_called_once_with(ui.UI_USER, "backup_create", "with_htdocs", True)

        token = self.csrf_token()
        with patch.object(ui, "ensure_backup_tool"), patch.object(ui, "list_backups", return_value=[]), patch.object(
            ui,
            "control_proc",
            return_value=CompletedProcess(["backup"], 1, "<script>failed</script>", ""),
        ) as control_proc, patch.object(ui, "audit_event") as audit_event:
            error = self.client.post(
                "/backup/create",
                data={"csrf_token": token},
                headers=headers,
                auth=self.auth,
            )
        self.assertEqual(error.status_code, 200)
        self.assertIn("Neues Backup", error.text)
        self.assertIn("&lt;script&gt;failed&lt;/script&gt;", error.text)
        self.assertNotIn("<script>failed</script>", error.text)
        control_proc.assert_called_once_with("/v1/backup-create", {"with_htdocs": False}, timeout=3600)
        audit_event.assert_called_once_with(ui.UI_USER, "backup_create", "core", False)

    def test_real_post_route_rejects_unauthenticated_and_foreign_origin_without_side_effects(self):
        token = self.csrf_token()
        with patch.object(ui, "ensure_backup_tool") as ensure_backup, patch.object(ui, "control_proc") as control_proc, patch.object(
            ui, "audit_event"
        ) as audit_event:
            unauthenticated = self.client.post(
                "/backup/create",
                data={"csrf_token": token},
                headers={"Origin": "http://testserver"},
            )
            foreign_origin = self.client.post(
                "/backup/create",
                data={"csrf_token": token},
                headers={"Origin": "https://attacker.example"},
                auth=self.auth,
            )

        self.assertEqual(unauthenticated.status_code, 401)
        self.assertEqual(foreign_origin.status_code, 403)
        ensure_backup.assert_not_called()
        control_proc.assert_not_called()
        audit_event.assert_not_called()


if __name__ == "__main__":
    unittest.main()
