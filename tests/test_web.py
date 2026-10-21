"""Local dashboard and in-memory scan regression checks."""
import http.client
import json
import threading
import unittest

from secretguard.scanner import scan_documents
from secretguard.web import create_server, demo_report


class InMemoryScanTests(unittest.TestCase):
    def test_same_detection_and_no_secret_leak(self):
        secret = 'sk_live_' + 'Z' * 25
        data = scan_documents([{'path': 'project/.env', 'content': f'PAYMENT_KEY={secret}\n'}])
        self.assertEqual(data['severity_counts']['critical'], 1)
        self.assertEqual(data['files_scanned'], 1)
        self.assertNotIn(secret, json.dumps(data))

    def test_oversized_marks_incomplete(self):
        report = scan_documents([{'path': 'app/huge.txt', 'oversized': True}])
        self.assertTrue(report['incomplete'])
        self.assertEqual(report['verdict'], 'INCOMPLETE')

    def test_ignored_vendor_folder(self):
        report = scan_documents([{'path': 'app/node_modules/token.js', 'content': 'sk_live_' + 'T' * 20}])
        self.assertEqual(report['files_scanned'], 0)

    def test_path_traversal_blocked(self):
        for name in ('../secrets', 'C:/Users/me/secrets', '/absolute/file', 'a/../../out'):
            with self.subTest(path=name), self.assertRaises(ValueError):
                scan_documents([{'path': name, 'content': 'test'}])

    def test_demo_uses_synthetic_fixtures(self):
        report = demo_report()
        self.assertEqual(report['findings_count'], 2)
        self.assertIn('Synthetic', report['target'])


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def get(self, path, host=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request('GET', path, headers={'Host': host or f'127.0.0.1:{self.server.server_port}'})
        res = conn.getresponse()
        data = res.read()
        status, headers = res.status, dict(res.getheaders())
        conn.close()
        return status, headers, data

    def post(self, data, *, origin=True, header=True):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        headers = {'Content-Type': 'application/json',
                   'Host': f'127.0.0.1:{self.server.server_port}'}
        if origin:
            headers['Origin'] = f'http://127.0.0.1:{self.server.server_port}'
        if header:
            headers['X-SecretGuard-Request'] = 'local-ui'
        conn.request('POST', '/api/scan', body=json.dumps(data), headers=headers)
        res = conn.getresponse()
        body = res.read()
        conn.close()
        return res.status, json.loads(body)

    def test_dashboard_served_with_csp(self):
        code, headers, body = self.get('/')
        self.assertEqual(code, 200)
        self.assertIn(b'Your workspace, under control', body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_extension_demo_page_and_script_are_locally_served(self):
        status, _, html = self.get('/extension-demo')
        self.assertEqual(status, 200)
        self.assertIn(b'/extension-demo.js', html)
        status, headers, js = self.get('/extension-demo.js')
        self.assertEqual(status, 200)
        self.assertIn(b'sk_live_', js)
        self.assertIn(b'ghp_', js)
        self.assertIn('application/javascript', headers['Content-Type'])

    def test_unknown_host_rejected(self):
        status, _, _ = self.get('/', host='evil.example')
        self.assertEqual(status, 403)

    def test_posts_require_same_origin(self):
        payload = {'folder': 'test', 'files': [{'path': 'safe.txt', 'content': 'hello'}]}
        self.assertEqual(self.post(payload, origin=False)[0], 403)
        self.assertEqual(self.post(payload, header=False)[0], 403)

    def test_local_api_never_returns_secrets(self):
        secret = 'ghp_' + 'A' * 36
        data = {'folder': 'example', 'files': [{'path': 'app/config.py', 'content': f'token = "{secret}"'}]}
        status, response = self.post(data)
        self.assertEqual(status, 200)
        self.assertEqual(response['findings_count'], 1)
        self.assertNotIn(secret, json.dumps(response))


if __name__ == '__main__':
    unittest.main()
