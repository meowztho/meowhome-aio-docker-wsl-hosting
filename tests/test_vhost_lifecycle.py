import unittest,sys,tempfile,pathlib
from unittest.mock import patch
from fastapi import HTTPException
sys.path.insert(0,'/workspace/meowhome-ui')
from app import main as ui
V='<VirtualHost *:80>\nServerName demo.example.com\nDocumentRoot /var/www/demo\n</VirtualHost>\n'
class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=pathlib.Path(self.tmp.name)
        self.p=patch.object(ui,'VHOST_DIR',str(self.root));self.p.start();self.addCleanup(self.p.stop)
    def runop(self,file,revision,value,side=None):
        with patch.object(ui,'ensure_vhost_control_plane_metadata'),patch.object(ui,'apache_test_and_reload',side_effect=side or [{'ok':True}]),patch.object(ui,'audit_event'):
            return ui.vhost_apply_transaction(file,revision,value,'test','test')
    def test_create_and_prevent_duplicate(self):
        self.runop('demo.conf','new',V)
        self.assertEqual((self.root/'demo.conf').read_text(),V)
        with self.assertRaises(HTTPException):self.runop('other.conf','new',V)
    def test_create_rollback(self):
        with self.assertRaises(HTTPException):self.runop('demo.conf','new',V,[{'ok':False},{'ok':True}])
        self.assertFalse((self.root/'demo.conf').exists())
    def test_delete_and_rollback(self):
        file=self.root/'demo.conf';file.write_text(V);old=ui.vhost_revision(file)
        with self.assertRaises(HTTPException):self.runop('demo.conf',old,None,[{'ok':False},{'ok':True}])
        self.assertEqual(file.read_text(),V)
        self.runop('demo.conf',old,None)
        self.assertFalse(file.exists())
        self.assertTrue(list(self.root.glob('demo.conf.bak.*')))
    def test_noop_and_stale_revision(self):
        file=self.root/'demo.conf';file.write_text(V);rev=ui.vhost_revision(file)
        self.runop('demo.conf',rev,V)
        self.assertFalse(list(self.root.glob('*.bak.*')))
        file.write_text(V+'# another edit\n')
        with self.assertRaises(HTTPException) as ctx:self.runop('demo.conf',rev,None)
        self.assertEqual(ctx.exception.status_code,409)
    def test_helper_delete_guard(self):
        f=self.root/'helper.conf';f.write_text('# helper\n')
        with self.assertRaises(HTTPException) as ctx:ui.vhosts_delete(file='helper.conf',revision=ui.vhost_revision(f),confirm='helper.conf',user='test',_csrf=None)
        self.assertEqual(ctx.exception.status_code,409)
    def test_csrf_post_routes(self):
        routes={r.path:r for r in ui.app.routes}
        for path in ['/vhosts/preview','/vhosts/save','/vhosts/delete']:
            self.assertIn(ui.require_csrf,[d.call for d in routes[path].dependant.dependencies])
if __name__=='__main__':unittest.main()
