import importlib.util
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('core295', ROOT/'assets/tools/meowhome.py')
core=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=core
spec.loader.exec_module(core)

class LegacyFtpCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)/'meowhome'
        self.root.mkdir()
        self.backup=self.root.parent/'.meowhome-upgrade'
        self.backup.mkdir(mode=0o700)
        self.env=self.root/'.env'
        self.original=(b'# comment\nPUID=1001\nPGID=1001\nFTP_ENABLED=true\n'
                       b'FTP_HOST_UID=1000\nFTP_HOST_GID=1000\n'
                       b'MEOWHOME_UI_PASS=admin\nDB_PASSWORD=secret-string\n')
        self.env.write_bytes(self.original)
        self.env.chmod(0o600)

    def test_preview_no_write_no_backup(self):
        result=core.cleanup_legacy_ftp_env(self.root,apply=False)
        self.assertEqual(result['keys'],['FTP_ENABLED','FTP_HOST_GID','FTP_HOST_UID'])
        self.assertFalse(result['applied'])
        self.assertEqual(self.env.read_bytes(),self.original)
        self.assertFalse(list(self.backup.rglob('*.backup')))

    def test_apply_keeps_secret_bytes_and_modes_and_is_idempotent(self):
        result=core.cleanup_legacy_ftp_env(self.root,apply=True)
        self.assertTrue(result['applied'])
        self.assertEqual(self.env.stat().st_mode & 0o777,0o600)
        self.assertEqual(Path(result['backup']).read_bytes(),self.original)
        self.assertEqual(Path(result['backup']).stat().st_mode & 0o777,0o600)
        changed=self.env.read_bytes()
        self.assertIn(b'MEOWHOME_UI_PASS=admin',changed)
        self.assertIn(b'DB_PASSWORD=secret-string',changed)
        for k in ('FTP_ENABLED','FTP_HOST_GID','FTP_HOST_UID'):
            self.assertNotIn(k.encode(),changed)
        second=core.cleanup_legacy_ftp_env(self.root,apply=True)
        self.assertFalse(second['changed'])
        self.assertEqual(len(list(self.backup.rglob('*.backup'))),1)

    def test_rejects_missing_canonical_or_duplicate(self):
        self.env.write_text('FTP_HOST_UID=1000\n')
        with self.assertRaises(ValueError):core.cleanup_legacy_ftp_env(self.root,apply=True)
        self.env.write_text('PUID=1001\nPUID=1000\nPGID=1001\nFTP_ENABLED=on\n')
        with self.assertRaises(ValueError):core.cleanup_legacy_ftp_env(self.root,apply=True)

    def test_rejects_insecure_env_or_symlink(self):
        self.env.chmod(0o644)
        with self.assertRaises(PermissionError):core.cleanup_legacy_ftp_env(self.root,apply=True)
        self.env.unlink()
        self.env.symlink_to(self.root/'fake')
        with self.assertRaises(ValueError):core.cleanup_legacy_ftp_env(self.root,apply=True)

    def test_ownership_exceptions_are_reported_not_mutated(self):
        h=self.root/'htdocs';h.mkdir()
        f=h/'old-site';f.mkdir()
        db=self.root/'ftp/users.sqlite'
        db.parent.mkdir()
        with sqlite3.connect(db) as c:
            c.execute("CREATE TABLE users(username TEXT, pass_hash TEXT, home_rel TEXT, enabled INT, access_mode TEXT)")
            c.execute("INSERT INTO users VALUES('legacy-admin','fake','',1,'all')")
        report=core.access_review(self.root)
        self.assertEqual(report['ftp_all_domain_users'],['legacy-admin'])
        self.assertEqual(report['legacy_env_keys'],['FTP_ENABLED','FTP_HOST_GID','FTP_HOST_UID'])
        self.assertEqual(f.stat().st_uid,os.getuid())
        self.assertEqual(self.env.read_bytes(),self.original)

    def test_both_commands_run_without_compose(self):
        p=core.build_parser()
        self.assertEqual(p.parse_args(['cleanup-legacy-ftp-env']).command,'cleanup-legacy-ftp-env')
        self.assertEqual(p.parse_args(['access-review','--json']).command,'access-review')

if __name__=='__main__':unittest.main()
