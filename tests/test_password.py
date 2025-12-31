import unittest
from unittest.mock import MagicMock

from tests.tt_loader import load_tt


tt = load_tt()
KNDYSFramework = tt.KNDYSFramework
RateLimiter = tt.RateLimiter


class DummyPool:
    def __init__(self):
        self.max_connections = 10

    def acquire(self):
        return None

    def release(self):
        return None

    def get_active_count(self):
        return 0


class BruteForceModuleTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework.connection_pool = DummyPool()
        self.framework.rate_limiter = RateLimiter(1000, 60)
        self.framework.wordlists = {
            'passwords': ['Password123', 'Secret!', 'letmein'],
            'usernames': ['admin', 'root']
        }
        self.framework.config = {'rhost': '10.0.0.5'}
        self.framework.session_id = 'test-session'

    def test_profile_resolution_defaults(self):
        self.framework.module_options = {'target': '10.0.0.5:2222'}
        profile = self.framework._resolve_brute_force_profile()
        self.assertEqual(profile['service'], 'ssh')
        self.assertEqual(profile['port'], 2222)
        self.assertTrue(profile['stop_on_success'])
        self.assertGreater(profile['combo_limit'], 0)

    def test_mock_connector_success_flow(self):
        self.framework.module_options = {
            'service': 'mock',
            'target': 'mock',
            'usernames_inline': 'alpha',
            'passwords_inline': 'wrong,secret!',
            'mock_success_password': 'secret!',
            'delay': '0',
            'jitter': '0',
            'stop_on_success': 'true',
            'audit_log': 'none'
        }
        self.framework._export_brute_force_results = MagicMock(return_value=[])
        result = self.framework.run_brute_force()
        self.assertEqual(len(result['successes']), 1)
        self.assertLessEqual(result['attempts'], 2)
        self.framework.logger.save_credential.assert_called_once()

    def test_lockout_threshold_prevents_extra_attempts(self):
        self.framework.module_options = {
            'service': 'mock',
            'target': 'mock',
            'usernames_inline': 'locked',
            'passwords_inline': 'p1,p2,p3,p4',
            'lockout_threshold': '2',
            'delay': '0',
            'jitter': '0',
            'concurrency': '1',
            'stop_on_success': 'false',
            'audit_log': 'none'
        }
        self.framework._export_brute_force_results = MagicMock(return_value=[])
        result = self.framework.run_brute_force()
        self.assertIn('locked', result['lockouts'])
        self.assertLessEqual(result['attempts'], 2)


class SprayModuleTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework.connection_pool = DummyPool()
        self.framework.wordlists = {
            'passwords': ['Password123', 'Secret!', 'letmein'],
            'password_profiles': {
                'core': ['Password123', 'Secret!'],
                'spray': ['Spring2024!', 'Secret!', 'Welcome2025!']
            },
            'usernames': ['admin', 'root'],
            'username_profiles': {
                'core': ['admin', 'root']
            }
        }
        self.framework.config = {'rhost': 'https://example.com/login'}
        self.framework.session_id = 'spray-session'

    def test_spray_profile_resolution_defaults(self):
        self.framework.module_options = {'target': 'https://example.com/login'}
        profile = self.framework._resolve_spray_profile()
        self.assertEqual(profile['service'], 'http')
        self.assertEqual(profile['password_profile'], 'spray')
        self.assertTrue(profile['stop_on_success'])

    def test_spray_mock_success(self):
        self.framework.module_options = {
            'service': 'mock',
            'target': 'mock',
            'usernames_inline': 'alpha,beta',
            'passwords_inline': 'wrong,secret!',
            'mock_success_password': 'secret!',
            'attempt_delay': '0',
            'attempt_jitter': '0',
            'password_cooldown': '0',
            'password_jitter': '0',
            'stop_on_success': 'true',
            'audit_log': 'none'
        }
        self.framework._export_spray_results = MagicMock(return_value=[])
        result = self.framework.run_spray_attack()
        self.assertIsNotNone(result)
        self.assertEqual(result['summary'].successes, 1)
        self.framework.logger.save_credential.assert_called_once()

    def test_spray_lockout_threshold(self):
        self.framework.module_options = {
            'service': 'mock',
            'target': 'mock',
            'usernames_inline': 'locked',
            'passwords_inline': 'a,b,c',
            'lockout_threshold': '1',
            'attempt_delay': '0',
            'password_cooldown': '0',
            'stop_on_success': 'false',
            'audit_log': 'none',
            'mock_success_password': 'never'
        }
        self.framework._export_spray_results = MagicMock(return_value=[])
        result = self.framework.run_spray_attack()
        self.assertIn('locked', result['lockouts'])
        self.assertLessEqual(result['summary'].attempts, 1)


if __name__ == '__main__':
    unittest.main()
