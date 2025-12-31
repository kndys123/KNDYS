import os
import stat
import tempfile
import threading
import unittest
from collections import OrderedDict
from unittest.mock import MagicMock

from tests.tt_loader import load_tt


tt = load_tt()
KNDYSFramework = tt.KNDYSFramework
PrivEscFinding = tt.PrivEscFinding


class PrivEscModuleTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework._explorer_cache = OrderedDict()
        self.framework._explorer_cache_lock = threading.Lock()

    def test_profile_resolution_includes_defaults(self):
        self.framework.module_options = {
            'session': 'demo',
            'checks': 'suid,path',
            'max_items': '25',
            'include_home': 'false',
            'allow_sudo': 'true'
        }
        profile = self.framework._resolve_privesc_profile()
        self.assertEqual(profile['session_id'], 'demo')
        self.assertEqual(profile['checks'], ['suid', 'path'])
        self.assertEqual(profile['max_items'], 25)
        self.assertFalse(profile['include_home'])
        self.assertTrue(profile['allow_sudo'])

    def test_suid_check_detects_custom_path(self):
        with tempfile.TemporaryDirectory() as tempdir:
            suid_target = os.path.join(tempdir, 'suid_bin')
            with open(suid_target, 'w', encoding='utf-8') as fh:
                fh.write('mock')
            os.chmod(suid_target, stat.S_IRWXU | stat.S_ISUID)
            self.framework.module_options = {
                'session': 'sess',
                'checks': 'suid',
                'suid_paths': '',
                'additional_paths': tempdir,
                'include_home': 'false',
                'max_items': '5'
            }
            profile = self.framework._resolve_privesc_profile()
            findings, errors = self.framework._privesc_check_suid(profile)
            self.assertFalse(errors)
            self.assertTrue(any(find.metadata.get('path') == suid_target for find in findings))

    def test_path_hijack_detects_world_writable(self):
        with tempfile.TemporaryDirectory() as tempdir:
            os.chmod(tempdir, 0o777)
            self.framework.module_options = {
                'session': 'sess',
                'checks': 'path',
                'path_override': f"/usr/bin{os.pathsep}{tempdir}",
                'max_items': '10'
            }
            profile = self.framework._resolve_privesc_profile()
            findings, _ = self.framework._privesc_check_path_hijack(profile)
            self.assertTrue(any(find.category == 'path' and find.severity == 'High' for find in findings))

    def test_execute_checks_generates_summary(self):
        with tempfile.TemporaryDirectory() as tempdir:
            os.chmod(tempdir, 0o777)
            self.framework.module_options = {
                'session': 'sess',
                'checks': 'writable',
                'writable_paths': tempdir,
                'max_items': '5',
                'max_workers': '1'
            }
            profile = self.framework._resolve_privesc_profile()
            result = self.framework._execute_privesc_checks(profile)
            self.assertGreaterEqual(result['summary'].total_findings, 1)
            self.assertIsInstance(result['findings'][0], PrivEscFinding)


if __name__ == '__main__':
    unittest.main()
