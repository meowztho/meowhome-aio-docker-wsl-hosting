"""Custom Apache VHost alias editing must preserve unrelated bytes and reject ambiguity."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'meowhome-ui'))
from app import main as ui
from app.vhost_alias_editor import plan_alias_edit, UnsupportedVhost

CONFIG = ('''# hand crafted site\n<VirtualHost *:80>\n    ServerName app.example.com\n    ServerAlias www.example.com\n    RewriteRule ^/old /new [R=301,L]\n</VirtualHost>\n\n<VirtualHost *:443>\n    ServerName app.example.com\n    ServerAlias www.example.com\n    SSLCertificateFile /etc/letsencrypt/live/example.com/fullchain.pem\n    SSLCertificateKeyFile /etc/letsencrypt/live/example.com/privkey.pem\n    Header always set X-Test "yes"\n    <Location /app>\n      ProxyPass http://backend:8080/app\n    </Location>\n</VirtualHost>\n''')
CERTS = [{'domain':'example.com','exists':True,'status':'ok','dns_names':['example.com','*.example.com']}]

class AliasPlannerTests(unittest.TestCase):
    def test_preserves_entire_custom_configuration_except_alias_lines(self):
        p = plan_alias_edit(CONFIG, 'app.example.com', ['mobile.example.com'])
        self.assertEqual(p.after, CONFIG.replace('ServerAlias www.example.com', 'ServerAlias mobile.example.com'))
        self.assertIn('-    ServerAlias www.example.com',p.diff)
        self.assertNotIn('Header always set X-Test',p.diff)
        self.assertNotIn('ProxyPass',p.diff)

    def test_insert_and_remove_aliases_both_vhosts(self):
        original=CONFIG.replace('    ServerAlias www.example.com\n','')
        changed=plan_alias_edit(original,'app.example.com',['new.example.com'])
        self.assertEqual(changed.after.count('    ServerAlias new.example.com'),2)
        removed=plan_alias_edit(CONFIG,'app.example.com',[])
        self.assertEqual(removed.after,original)

    def test_noop_is_noop(self):
        p=plan_alias_edit(CONFIG,'app.example.com',['www.example.com'])
        self.assertEqual(p.after,CONFIG)
        self.assertEqual(p.diff,'')

    def test_windows_newlines_preserved(self):
        original=CONFIG.replace('\n','\r\n')
        changed=plan_alias_edit(original,'app.example.com',['new.example.com'])
        self.assertEqual(changed.after,original.replace('ServerAlias www.example.com','ServerAlias new.example.com'))

    def test_fail_closed_on_ambiguous_layouts(self):
        invalid=[
            CONFIG.replace('    ServerName app.example.com','    ServerName other.example.com',1),
            CONFIG.replace('    ServerAlias www.example.com\n','    ServerAlias *.example.com\n',1),
            CONFIG.replace('    ServerAlias www.example.com\n','    ServerAlias www.example.com # note\n',1),
            CONFIG.replace('    ServerAlias www.example.com\n','    ServerAlias www.example.com\n    ServerAlias a.example.com\n',1),
            CONFIG.replace('    ServerAlias www.example.com','    ServerAlias www.other.example.com',1),
            CONFIG.replace('    ServerName app.example.com','    <IfModule mod_headers.c>\n       ServerName app.example.com\n    </IfModule>',1),
            CONFIG.replace('</VirtualHost>','',1),
            CONFIG.replace('    ServerAlias www.example.com\n','    ServerAlias www.example.com\r\n',1),
        ]
        for raw in invalid:
            with self.subTest(raw=raw[:80]), self.assertRaises(UnsupportedVhost):
                plan_alias_edit(raw,'app.example.com',['new.example.com'])

class AliasRouteTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory(); self.addCleanup(folder.cleanup)
        self.base=Path(folder.name)
        self.p=self.base/'app.example.com.conf'
        self.p.write_text(CONFIG,encoding='utf-8')
        ctx=patch.object(ui,'VHOST_DIR',str(self.base));ctx.start();self.addCleanup(ctx.stop)
        self.rev=hashlib.sha256(self.p.read_bytes()).hexdigest()

    def test_preview_does_not_write_anything(self):
        from starlette.requests import Request
        scope={'type':'http','http_version':'1.1','scheme':'http','method':'GET',
               'path':'/sites/app.example.com/aliases/preview','query_string':b'',
               'headers':[(b'host',b'localhost')], 'client':('127.0.0.1',123), 'server':('127.0.0.1',9090)}
        request=Request(scope)
        with patch.object(ui,'certificate_inventory',return_value=CERTS):
            response=ui.site_aliases_preview(request,'app.example.com',revision=self.rev,aliases='mobile.example.com',user='admin',_csrf=None)
        body=response.body.decode()
        self.assertIn('ServerAlias mobile.example.com',body)
        self.assertIn('name="csrf_token"',body)
        self.assertEqual(self.p.read_text(),CONFIG)

    def test_apply_and_rollback(self):
        with patch.object(ui,'certificate_inventory',return_value=CERTS),\
             patch.object(ui,'ensure_vhost_control_plane_metadata'),\
             patch.object(ui,'apache_test_and_reload',return_value={'ok':True}) as reload,\
             patch.object(ui,'audit_event'):
            res=ui.site_aliases_apply('app.example.com',revision=self.rev,aliases='mobile.example.com',user='admin',_csrf=None)
        self.assertEqual(res.status_code,303)
        changed=self.p.read_text()
        self.assertEqual(changed,CONFIG.replace('www.example.com','mobile.example.com'))
        self.assertEqual(reload.call_count,1)
        with patch.object(ui,'certificate_inventory',return_value=CERTS),\
             patch.object(ui,'ensure_vhost_control_plane_metadata'),\
             patch.object(ui,'apache_test_and_reload',side_effect=[{'ok':False},{'ok':True}]) as reload,\
             patch.object(ui,'audit_event'):
            res=ui.site_aliases_apply('app.example.com',revision=hashlib.sha256(self.p.read_bytes()).hexdigest(),aliases='new.example.com',user='admin',_csrf=None)
        self.assertEqual(res.status_code,400)
        self.assertEqual(self.p.read_text(),changed)
        self.assertEqual(reload.call_count,2)

    def test_conflict_does_not_write_and_revision_guard(self):
        with patch.object(ui,'certificate_inventory',return_value=CERTS):
            with self.assertRaises(HTTPException) as ctx:
                ui.site_aliases_apply('app.example.com',revision='a'*64,aliases='mobile.example.com',user='admin',_csrf=None)
            self.assertEqual(ctx.exception.status_code,409)
            other=self.base/'other.conf'
            other.write_text('<VirtualHost *:80>\n ServerName other.example.com\n ServerAlias mobile.example.com\n</VirtualHost>\n')
            with self.assertRaises(HTTPException) as ctx:
                ui.site_aliases_apply('app.example.com',revision=self.rev,aliases='mobile.example.com',user='admin',_csrf=None)
            self.assertEqual(ctx.exception.status_code,409)
        self.assertEqual(self.p.read_text(),CONFIG)

    def test_tls_missing_coverage_refused(self):
        with patch.object(ui,'certificate_inventory',return_value=CERTS):
            with self.assertRaises(HTTPException) as ctx:
                ui.site_aliases_apply('app.example.com',revision=self.rev,aliases='nested.a.example.com',user='admin',_csrf=None)
            self.assertEqual(ctx.exception.status_code,400)
        self.assertEqual(self.p.read_text(),CONFIG)

    def test_apply_requires_csrf_and_auth_routes(self):
        routes={r.path:r for r in ui.app.routes if getattr(r,'path',None)}
        for endpoint in ('/sites/{host}/aliases/preview','/sites/{host}/aliases/apply'):
            deps=[d.call for d in routes[endpoint].dependant.dependencies]
            self.assertIn(ui.require_csrf,deps)
            self.assertIn(ui.require_auth,deps)

if __name__=='__main__':unittest.main()
