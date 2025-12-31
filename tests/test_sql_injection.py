import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.tt_loader import load_tt

tt = load_tt()

AdvancedSQLiScanner = tt.AdvancedSQLiScanner
KNDYSFramework = tt.KNDYSFramework
SQLiFinding = tt.SQLiFinding


class SQLiProfileResolutionTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.config = {'user_agent': 'UnitTestAgent/1.0', 'lhost': '127.0.0.1'}
        self.framework.module_options = {}

    def test_resolve_sqli_profile_parses_mutable_inputs(self):
        self.framework.module_options = {
            'url': 'https://target.local/login.php?id=1',
            'method': 'post',
            'parameters': 'id,token',
            'injection_location': 'query',
            'techniques': 'union, time',
            'max_depth': '4',
            'max_payloads': '5',
            'max_total_payloads': '25',
            'threads': '2',
            'timeout': '10',
            'throttle': '0.5',
            'verify_ssl': 'true',
            'length_threshold': '200',
            'delay_threshold': '4',
            'custom_headers': 'X-Test: 1;X-Trace: abc',
            'cookies': 'session=abc123;theme=dark',
            'proxies': 'http=http://127.0.0.1:8080,https=http://127.0.0.1:8443',
            'body': 'id=1&token=abc'
        }

        profile = self.framework._resolve_sqli_profile()

        self.assertEqual(profile['headers']['X-Test'], '1')
        self.assertEqual(profile['headers']['X-Trace'], 'abc')
        self.assertEqual(profile['cookies']['session'], 'abc123')
        self.assertEqual(profile['cookies']['theme'], 'dark')
        self.assertEqual(profile['proxies']['https'], 'http://127.0.0.1:8443')
        self.assertTrue(profile['verify_ssl'])
        self.assertEqual(profile['techniques'], ['union', 'time'])
        self.assertAlmostEqual(profile['throttle'], 0.5)
        self.assertEqual(profile['body'], 'id=1&token=abc')


class AdvancedSQLiScannerTests(unittest.TestCase):
    class DummyResponse:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status
            self.content = text.encode('utf-8')

    def test_execute_records_error_based_finding(self):
        profile = {
            'url': 'http://target.local/item.php?id=1',
            'method': 'get',
            'parameters': 'id',
            'injection_location': 'query',
            'techniques': ['error'],
            'max_depth': 1,
            'max_payloads': 1,
            'max_total_payloads': 1,
            'threads': 1,
            'timeout': 5.0,
            'throttle': 0.0,
            'verify_ssl': False,
            'length_threshold': 120,
            'delay_threshold': 3.0,
            'headers': {},
            'cookies': {},
            'proxies': None,
            'body': ''
        }

        framework_stub = SimpleNamespace(rate_limiter=None, logger=None)
        scanner = AdvancedSQLiScanner(profile, framework_stub)

        responses = [
            self.DummyResponse("Baseline page"),
            self.DummyResponse("You have an error in your SQL syntax near 'test'", status=500)
        ]

        def fake_request(method, **kwargs):
            if responses:
                return responses.pop(0)
            return self.DummyResponse("Fallback", status=200)

        with patch('tt.requests.request', side_effect=fake_request):
            with patch.object(AdvancedSQLiScanner, '_export_results', return_value=[]):
                scanner.execute()

        self.assertEqual(len(scanner.findings), 1)
        finding = scanner.findings[0]
        self.assertIsInstance(finding, SQLiFinding)
        self.assertEqual(finding.parameter, 'id')
        self.assertIn('error', finding.evidence.lower())


if __name__ == '__main__':
    unittest.main()
