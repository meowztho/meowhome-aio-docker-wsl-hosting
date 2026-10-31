"""Structured Apache VHost editor contract; no live DNS/ACME mutations."""
import hashlib
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch
from fastapi import HTTPException

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'meowhome-ui'))
from app import main as ui

CERTS=[{'domain':'example.com','exists':True,'status':'ok','dns_names':['example.com','*.example.com']},
       {'domain':'other.example','exists':True,'status':'expired','dns_names':['*.other.example']}]

class SiteSettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base=pathlib.Path(self.tmp.name)
        self.vhosts=self.base/'vhosts'
        self.vhosts.mkdir()
        self.patcher=patch.object(ui,'VHOST_DIR',str(self.vhosts))
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def add_site(self,host='app.example.com',kind='website',aliases=(),php=True,proxy='',cert='example.com'):
        path=self.vhosts/(host+'.conf')
        path.write_text(ui.generate_site_vhost(host,list(aliases),kind,php,proxy,cert),encoding='utf-8')
        return path

    def test_roundtrip_managed_and_custom_are_distinct(self):
        path=self.add_site(aliases=['www.example.com'])
        self.assertTrue(ui.site_is_generated(ui.parse_vhost_record(path)))
        path.write_text(path.read_text()+'\nHeader set X-Custom 1\n')
        self.assertFalse(ui.site_is_generated(ui.parse_vhost_record(path)))
        with self.assertRaises(HTTPException) as ctx:
            ui.site_settings_save('app.example.com',revision='0'*64,aliases='',php='true',
                                  user='admin',_csrf=None)
        self.assertEqual(ctx.exception.status_code,409)

    def test_unrecognized_manual_root_is_readonly(self):
        p=self.add_site()
        p.write_text(p.read_text().replace('/var/www/app.example.com','/srv/app'))
        self.assertFalse(ui.site_is_generated(ui.parse_vhost_record(p)))

    def test_resolves_tls_using_existing_wildcard_only(self):
        with patch.object(ui,'certificate_inventory',return_value=CERTS):
            self.assertEqual(ui.selected_site_certificate('app.example.com',['www.example.com'],'auto'),'example.com')
            with self.assertRaises(HTTPException):
                ui.selected_site_certificate('app.example.com',['a.b.example.com'],'keep','example.com')
            with self.assertRaises(HTTPException):
                ui.selected_site_certificate('x.other.example',[],'auto')
        self.assertEqual(ui.selected_site_certificate('app.example.com',[],'none'), '')

    def test_duplicate_names_rejected_across_vhosts(self):
        self.add_site('alpha.example.com',aliases=['www.example.com'])
        with self.assertRaises(HTTPException) as ctx:
            ui.site_name_conflicts('beta.example.com',['www.example.com'])
        self.assertEqual(ctx.exception.status_code,409)
        ui.site_name_conflicts('alpha.example.com',['www.example.com'],current_file='alpha.example.com.conf')

    def test_wildcard_alias_of_custom_vhost_rejects_host(self):
        path=self.vhosts/'custom.conf'
        path.write_text('<VirtualHost *:80>\nServerName primary.example.com\nServerAlias *.example.com\n</VirtualHost>\n')
        with self.assertRaises(HTTPException) as ctx:
            ui.site_name_conflicts('something.example.com',[])
        self.assertEqual(ctx.exception.status_code,409)
        # Apache ServerAlias wildcards are globs, unlike TLS wildcards (one DNS label).
        with self.assertRaises(HTTPException):
            ui.site_name_conflicts('nested.something.example.com',[])

    def test_revision_conflict_makes_no_changes(self):
        path=self.add_site()
        before=path.read_bytes()
        with self.assertRaises(HTTPException) as ctx:
            ui.site_settings_save('app.example.com',revision='f'*64,aliases='www.example.com',php='true',cert_domain='keep',user='admin',_csrf=None)
        self.assertEqual(ctx.exception.status_code,409)
        self.assertEqual(path.read_bytes(),before)

    def test_apply_and_apache_rollback(self):
        path=self.add_site()
        before=path.read_text()
        revision=hashlib.sha256(path.read_bytes()).hexdigest()
        with patch.object(ui,'certificate_inventory',return_value=CERTS), \
             patch.object(ui,'ensure_vhost_control_plane_metadata'), \
             patch.object(ui,'apache_test_and_reload',return_value={'ok':True}) as reload, \
             patch.object(ui,'audit_event'):
            result=ui.site_settings_save('app.example.com',revision=revision,aliases='www.example.com',php=None,cert_domain='keep',user='admin',_csrf=None)
        self.assertEqual(result.status_code,303)
        self.assertIn('ServerAlias www.example.com',path.read_text())
        self.assertNotIn('php-fpm.conf',path.read_text())
        self.assertTrue(reload.called)
        changed=path.read_text()
        with patch.object(ui,'certificate_inventory',return_value=CERTS), \
             patch.object(ui,'ensure_vhost_control_plane_metadata'), \
             patch.object(ui,'apache_test_and_reload',side_effect=[{'ok':False},{'ok':True}]) as reload, \
             patch.object(ui,'audit_event') as audit:
            result=ui.site_settings_save('app.example.com',revision=hashlib.sha256(path.read_bytes()).hexdigest(),aliases='',php=None,cert_domain='keep',user='admin',_csrf=None)
        self.assertEqual(result.status_code,400)
        self.assertEqual(path.read_text(),changed)
        self.assertEqual(reload.call_count,2)
        self.assertFalse(audit.call_args.args[3])
        self.assertNotEqual(path.read_text(),before)

    def test_noop_does_not_rewrite_or_reload(self):
        path=self.add_site()
        revision=hashlib.sha256(path.read_bytes()).hexdigest()
        with patch.object(ui,'certificate_inventory',return_value=CERTS), \
             patch.object(ui,'ensure_vhost_control_plane_metadata') as ensure, \
             patch.object(ui,'apache_test_and_reload') as reload:
            response=ui.site_settings_save('app.example.com',revision=revision,aliases='',php='true',cert_domain='keep',user='admin',_csrf=None)
        self.assertEqual(response.status_code,303)
        ensure.assert_not_called()
        reload.assert_not_called()

    def test_browser_template_contains_settings_and_no_credentials(self):
        from starlette.requests import Request
        path=self.add_site(kind='proxy',php=False,proxy='http://internal:8080')
        scope={'type':'http','http_version':'1.1','scheme':'http','method':'GET',
               'path':'/sites/app.example.com/settings','raw_path':b'/sites/app.example.com/settings',
               'query_string':b'','headers':[(b'host',b'127.0.0.1:9090')],
               'client':('127.0.0.1',12345),'server':('127.0.0.1',9090)}
        request=Request(scope)
        with patch.object(ui,'certificate_inventory',return_value=CERTS):
            response=ui.site_settings(request,'app.example.com',user='admin')
        page=response.body.decode('utf-8')
        self.assertIn('name="csrf_token"',page)
        self.assertIn('name="revision"',page)
        self.assertIn('http://internal:8080/',page)
        self.assertIn('DNS-Updater',page)
        self.assertIn('Certbot',page)
        self.assertNotIn('DB_ROOT_PASSWORD',page)
        self.assertEqual(path.read_text(),ui.generate_site_vhost('app.example.com',[],'proxy',False,'http://internal:8080','example.com'))

    def test_routes_and_post_form_keep_auth_csrf(self):
        paths={getattr(r,'path',''):r for r in ui.app.routes}
        self.assertIn('/sites/{host}/settings',paths)
        self.assertIn(ui.require_auth, [d.call for d in paths['/sites/{host}/settings'].dependant.dependencies])
        self.assertIn(ui.require_csrf, [d.call for d in paths['/sites/{host}/settings'].dependant.dependencies])

if __name__=='__main__': unittest.main()
