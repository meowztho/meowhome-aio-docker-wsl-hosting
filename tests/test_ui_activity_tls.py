"""Read-only domain/TLS and audit projection regressions."""
import pathlib
import sys
import tempfile
import unittest
import json
import importlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'meowhome-ui'))
tls = importlib.import_module('app.domain_tls_health')
activity = importlib.import_module('app.activity')
ui = importlib.import_module('app.main')

CERTS = [
    {'domain': 'example.com', 'status': 'ok', 'dns_names': ['example.com', '*.example.com']},
    {'domain': 'another.example', 'status': 'expired', 'dns_names': ['*.another.example']},
    {'domain': 'site.example.com', 'status': 'warning', 'dns_names': ['site.example.com', 'www.site.example.com']},
]

class DomainTlsTests(unittest.TestCase):
    def test_hostname_coverage_and_wildcard_depth(self):
        self.assertTrue(tls.certificate_covers_hostname('EXAMPLE.COM.', CERTS[0]['dns_names']))
        self.assertTrue(tls.certificate_covers_hostname('video.example.com', CERTS[0]['dns_names']))
        self.assertFalse(tls.certificate_covers_hostname('www.video.example.com', CERTS[0]['dns_names']))
        self.assertFalse(tls.certificate_covers_hostname('example.com', ['*.example.com']))
        self.assertFalse(tls.certificate_covers_hostname('a..example.com', CERTS[0]['dns_names']))

    def test_uncovered_alias_does_not_claim_tls_healthy(self):
        site = {'host': 'video.example.com', 'aliases': ['deep.video.example.com'], 'tls': True, 'cert_domain': 'example.com'}
        result = tls.site_tls_health(site, CERTS)
        self.assertEqual(result['tls_status'], 'not_covered')
        self.assertEqual(result['tls_uncovered_hosts'], ['deep.video.example.com'])
        self.assertNotIn('tls_status', site)

    def test_auto_selection_rejects_expired_or_uncovered(self):
        self.assertEqual(tls.choose_covered_certificate(['site.example.com', 'www.site.example.com'], CERTS), 'site.example.com')
        self.assertIsNone(tls.choose_covered_certificate(['a.another.example'], CERTS))
        self.assertIsNone(tls.choose_covered_certificate(['deep.video.example.com'], CERTS[:1]))
        self.assertIsNone(tls.choose_covered_certificate([], CERTS))

    def test_certificate_status_missing_unknown_and_http(self):
        base = {'host':'a.example.com', 'aliases':[], 'cert_domain':'example.com', 'tls':False}
        self.assertEqual(tls.site_tls_health(base, CERTS)['tls_status'], 'not_enabled')
        base['tls'] = True
        self.assertEqual(tls.site_tls_health(base, [])['tls_status'], 'missing')
        self.assertEqual(tls.site_tls_health(base, [{'domain':'example.com','status':'unknown'}])['tls_status'], 'unknown')

class ActivityTests(unittest.TestCase):
    def test_missing_file_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(activity.recent_activity(pathlib.Path(d)/'missing'), [])

    def test_newest_first_bounded_and_never_exposes_details(self):
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d) / 'control-audit.jsonl'
            with log.open('w', encoding='utf-8') as fh:
                fh.write('not json\n')
                for i in range(125):
                    fh.write(json.dumps({'ts':str(i),'actor':'admin','action':'update','target':str(i),'success': i%2==0, 'detail': 'SECRET_NEVER_SHOW', 'password': 'SECRET_NEVER_SHOW'})+'\n')
            result = activity.recent_activity(log, limit=200)
            self.assertEqual(len(result),100)
            self.assertEqual(result[0]['target'],'124')
            self.assertEqual(result[-1]['target'],'25')
            self.assertTrue(all(set(r) == {'ts','actor','action','target','success'} for r in result))
            self.assertNotIn('SECRET_NEVER_SHOW',repr(result))

    def test_partial_tail_and_malformed_lines(self):
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d)/'log'
            log.write_text(('X'*524288)+'\n'+json.dumps({'ts':'yes','success':True})+'\n', encoding='utf-8')
            result=activity.recent_activity(log)
            self.assertEqual(len(result),1)
            self.assertEqual(result[0]['ts'],'yes')

    def test_activity_route_auth_required(self):
        matching = [r for r in ui.app.routes if getattr(r,'path',None) == '/activity']
        self.assertEqual(len(matching),1)
        self.assertEqual(getattr(matching[0],'methods',set()),{'GET'})
        self.assertIn(ui.require_auth, [getattr(d,'call',None) for d in matching[0].dependant.dependencies])

if __name__ == '__main__':
    unittest.main()
