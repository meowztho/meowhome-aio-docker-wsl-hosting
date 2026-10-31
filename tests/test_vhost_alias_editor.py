"""Regression tests for safe ServerAlias-only transformations."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'meowhome-ui'))
from app.vhost_alias_editor import plan_alias_edit,UnsupportedVhost

VHOST='''<VirtualHost *:80>
    ServerName app.example.com
    ServerAlias www.example.com
    Header always set X-Example "unchanged"
</VirtualHost>
<VirtualHost *:443>
    ServerName app.example.com
    ServerAlias www.example.com
    ProxyPass / http://app:8080/
</VirtualHost>
'''

class AliasTests(unittest.TestCase):
    def test_changes_only_alias_directives(self):
        p=plan_alias_edit(VHOST,'app.example.com',['new.example.com'])
        self.assertEqual(p.after,VHOST.replace('ServerAlias www.example.com','ServerAlias new.example.com'))
        self.assertNotIn('ProxyPass',p.diff)
    def test_noop(self):
        self.assertEqual(plan_alias_edit(VHOST,'app.example.com',['www.example.com']).after,VHOST)
    def test_removal(self):
        p=plan_alias_edit(VHOST,'app.example.com',[])
        self.assertEqual(p.after.count('ServerAlias'),0)
    def test_malformed_and_conflicting_host(self):
        for bad in [VHOST.replace('ServerName app.example.com','ServerName another.example.com',1),
                    VHOST.replace('ServerAlias www.example.com','ServerAlias *.example.com',1),
                    VHOST.replace('ServerAlias www.example.com','ServerAlias www.example.com # comment',1),
                    VHOST.replace('</VirtualHost>','',1)]:
            with self.subTest(bad=bad[:20]),self.assertRaises(UnsupportedVhost):
                plan_alias_edit(bad,'app.example.com',['new.example.com'])
    def test_crlf_roundtrip(self):
        old=VHOST.replace('\n','\r\n')
        new=plan_alias_edit(old,'app.example.com',['new.example.com']).after
        self.assertEqual(new,old.replace('www.example.com','new.example.com'))
if __name__=='__main__':unittest.main()
