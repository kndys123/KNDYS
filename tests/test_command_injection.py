import unittest
from types import SimpleNamespace
from unittest.mock import patch

from tests.tt_loader import load_tt


tt = load_tt()

KNDYSFramework = tt.KNDYSFramework
AdvancedCommandInjectionScanner = tt.AdvancedCommandInjectionScanner
CommandInjectionPayload = tt.CommandInjectionPayload


class CommandInjectionProfileResolutionTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.config = {
            'user_agent': 'UnitTestAgent/1.0',
            'lhost': '127.0.0.1'
        }
        self.framework.module_options = {}

    def test_profile_resolution_parses_structured_inputs(self):
        self.framework.module_options = {
            'url': 'https://target.local/cmd.php?cmd=list',
            'method': 'post',
            'parameters': 'cmd,input',
            'body': 'cmd=list',
            'injection_location': 'body',
            'os_profile': 'windows',
            'attack_modes': 'detect,blind',
            'confirm_command': 'dir',
            'custom_payload': '& whoami && echo {{MARK}}',
            'encoder': 'url',
            'max_payloads': '5',
            'max_total_payloads': '20',
            'threads': '2',
            'timeout': '6',
            'throttle': '0.1',
            'blind_delay': '4',
            'verify_ssl': 'true',
            'response_indicators': 'administrator,windows ip',
            'success_regex': 'administrator',
            'rate_limit': '3',
            'custom_headers': 'X-Trace: 1',
            'cookies': 'session=abc',
            'proxies': 'http=http://127.0.0.1:8080',
            'report_prefix': 'cmdi_report'
        }

        profile = self.framework._resolve_command_injection_profile()

        self.assertEqual(profile['headers']['X-Trace'], '1')
        self.assertEqual(profile['cookies']['session'], 'abc')
        self.assertEqual(profile['proxies']['http'], 'http://127.0.0.1:8080')
        self.assertTrue(profile['verify_ssl'])
        self.assertEqual(profile['encoder'], 'url')
        self.assertEqual(profile['attack_modes'], ['detect', 'blind'])
        self.assertEqual(profile['os_profile'], 'windows')
        self.assertEqual(profile['confirm_command'], 'dir')
        self.assertAlmostEqual(profile['blind_delay'], 4.0)
        self.assertIsNotNone(profile['rate_limiter'])


class AdvancedCommandInjectionScannerTests(unittest.TestCase):
    class DummyResponse:
        def __init__(self, text, status=200):
            self.text = text
            self.status_code = status
            self.content = text.encode('utf-8')

    def test_scanner_records_marker_based_finding(self):
        profile = {
            'url': 'http://target.local/cmd.php?cmd=1',
            'method': 'get',
            'parameters': 'cmd',
            'body': '',
            'injection_location': 'query',
            'os_profile': 'linux',
            'attack_modes': ['detect'],
            'confirm_command': 'whoami',
            'custom_payload': '',
            'encoder': 'none',
            'max_payloads': 5,
            'max_total_payloads': 10,
            'threads': 1,
            'timeout': 5.0,
            'throttle': 0.0,
            'blind_delay': 5.0,
            'verify_ssl': False,
            'indicators': ['uid='],
            'success_regex': 'uid=',
            'rate_limiter': None,
            'headers': {},
            'cookies': {},
            'proxies': None,
            'report_prefix': 'cmdi'
        }

        framework_stub = SimpleNamespace(rate_limiter=None, logger=None)
        scanner = AdvancedCommandInjectionScanner(profile, framework_stub)

        payload = CommandInjectionPayload(
            name='marker-test',
            payload='; echo deadbeef',
            category='detect',
            os='linux',
            marker='deadbeef',
            command='whoami',
            description='unit'
        )

        def fake_request(*_args, **_kwargs):
            return self.DummyResponse("uid=1000 deadbeef")

        with patch.object(tt.CommandInjectionPayloadFactory, 'generate', return_value=[payload]):
            with patch('tt.requests.Session.request', side_effect=fake_request):
                result = scanner.execute()

        self.assertEqual(len(result['findings']), 1)
        finding = result['findings'][0]
        self.assertEqual(finding.parameter, 'cmd')
        self.assertEqual(finding.payload_name, 'marker-test')
        self.assertEqual(finding.indicator, 'marker')


if __name__ == '__main__':
    unittest.main()
