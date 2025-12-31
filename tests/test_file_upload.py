import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.tt_loader import load_tt


tt = load_tt()

KNDYSFramework = tt.KNDYSFramework
AdvancedFileUploadTester = tt.AdvancedFileUploadTester
FileUploadPayload = tt.FileUploadPayload


class FileUploadProfileResolutionTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.config = {'user_agent': 'UnitTestAgent/1.0', 'lhost': '127.0.0.1'}
        self.framework.module_options = {}

    def test_profile_resolution_handles_enhanced_options(self):
        self.framework.module_options = {
            'url': 'https://target.local/upload.php',
            'method': 'put',
            'parameter': 'upload',
            'extra_fields': 'token=abc123&submit=Upload',
            'payload_profile': 'aggressive',
            'custom_payload': '<?php echo 1;?>',
            'webshell_type': 'asp',
            'max_payloads': '3',
            'verify_paths': 'files,images',
            'auto_shell_verify': 'false',
            'shell_param': 'exec',
            'shell_command': 'whoami',
            'shell_success_indicators': 'uid=,nt authority',
            'success_keywords': 'stored,file saved',
            'allow_status': '201,204',
            'threads': '2',
            'timeout': '15',
            'verify_timeout': '8',
            'throttle': '0.5',
            'verify_ssl': 'true',
            'rate_limit': '4',
            'custom_headers': 'X-Test: 1',
            'cookies': 'session=abc',
            'proxies': 'http=http://127.0.0.1:8080',
            'report_prefix': 'fu'
        }

        profile = self.framework._resolve_file_upload_profile()

        self.assertEqual(profile['parameter'], 'upload')
        self.assertEqual(profile['method'], 'put')
        self.assertEqual(profile['payload_profile'], 'aggressive')
        self.assertEqual(profile['extra_fields']['token'], 'abc123')
        self.assertEqual(profile['headers']['X-Test'], '1')
        self.assertEqual(profile['cookies']['session'], 'abc')
        self.assertEqual(profile['proxies']['http'], 'http://127.0.0.1:8080')
        self.assertTrue(profile['verify_ssl'])
        self.assertEqual(profile['verify_paths'], ['files', 'images'])
        self.assertEqual(profile['allow_status'], [201, 204])
        self.assertAlmostEqual(profile['throttle'], 0.5)
        self.assertEqual(profile['threads'], 2)
        self.assertIsNotNone(profile['rate_limiter'])


class AdvancedFileUploadTesterTests(unittest.TestCase):
    class DummyResponse:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status
            self.content = text.encode('utf-8')
            self.headers = {}

    def setUp(self):
        self.profile = {
            'url': 'http://target.local/upload.php',
            'method': 'post',
            'parameter': 'file',
            'extra_fields': {},
            'payload_profile': 'balanced',
            'custom_payload': '',
            'webshell_type': 'php',
            'max_payloads': 1,
            'verify_paths': ['uploads'],
            'auto_shell_verify': False,
            'shell_param': 'cmd',
            'shell_command': 'id',
            'shell_success_indicators': ['uid='],
            'success_keywords': ['upload success'],
            'allow_status': [200, 201],
            'threads': 2,
            'timeout': 5.0,
            'verify_timeout': 3.0,
            'throttle': 0.0,
            'verify_ssl': False,
            'rate_limiter': None,
            'headers': {},
            'cookies': {},
            'proxies': None,
            'report_prefix': 'file_upload'
        }
        self.framework_stub = SimpleNamespace(rate_limiter=None, logger=None)

    def test_tester_confirms_retrievable_payload(self):
        payload = FileUploadPayload(
            name='php_basic',
            filename='shell_deadbeef.php',
            content=b'<?php echo "deadbeef";?>',
            content_type='application/x-httpd-php',
            description='test payload',
            vector='webshell',
            marker='deadbeef',
            path_hint='uploads',
            exec_capable=False
        )

        def fake_post(self_obj, url, files=None, data=None, headers=None, timeout=None, verify=None, cookies=None, proxies=None, allow_redirects=True):
            return AdvancedFileUploadTesterTests.DummyResponse('upload success path /uploads/shell_deadbeef.php', 201)

        def fake_get(url, **kwargs):
            if 'uploads' in url:
                return AdvancedFileUploadTesterTests.DummyResponse('payload deadbeef marker', 200)
            return AdvancedFileUploadTesterTests.DummyResponse('missing', 404)

        with patch.object(tt.FileUploadPayloadFactory, 'generate', return_value=[payload]):
            with patch('tt.requests.Session.post', new=fake_post):
                with patch('tt.requests.get', side_effect=fake_get):
                    tester = AdvancedFileUploadTester(self.profile, self.framework_stub)
                    result = tester.execute()

        self.assertEqual(len(result['findings']), 1)
        finding = result['findings'][0]
        self.assertEqual(finding.verification, 'retrieval')
        self.assertEqual(finding.severity, 'High')
        self.assertIn('uploads', finding.access_url)


if __name__ == '__main__':
    unittest.main()
