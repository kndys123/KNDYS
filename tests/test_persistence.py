import os
import tempfile
import unittest
from unittest.mock import MagicMock

from tests.tt_loader import load_tt


tt = load_tt()
KNDYSFramework = tt.KNDYSFramework


class PersistenceModuleTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework.config = {'lhost': '127.0.0.1', 'lport': 4444}
        self.framework.session_id = 'sess'

    def test_profile_resolution_defaults(self):
        profile = self.framework._resolve_persistence_profile()
        self.assertEqual(profile['mode'], 'balanced')
        self.assertIn(profile['target_os'], {'linux', 'windows', 'mac'})
        self.assertEqual(profile['methods'], ['auto'])
        self.assertTrue(profile['include_cleanup'])
        self.assertEqual(profile['risk_ceiling'], 'high')

    def test_plan_contains_requested_method(self):
        self.framework.module_options = {
            'session': 'alpha',
            'method': 'systemd',
            'os': 'linux',
            'risk_ceiling': 'critical',
            'include_cleanup': 'false',
            'generate_scripts': 'false'
        }
        profile = self.framework._resolve_persistence_profile()
        plan = self.framework._build_persistence_plan(profile)
        self.assertGreaterEqual(len(plan.techniques), 1)
        self.assertTrue(any(tech.category == 'systemd' for tech in plan.techniques))

    def test_export_persistence_plan_creates_files(self):
        with tempfile.TemporaryDirectory() as tempdir:
            prefix = os.path.join(tempdir, 'persist_plan')
            self.framework.module_options = {
                'session': 'beta',
                'method': 'cron',
                'os': 'linux',
                'report_prefix': prefix,
                'generate_scripts': 'false'
            }
            profile = self.framework._resolve_persistence_profile()
            plan = self.framework._build_persistence_plan(profile)
            paths = self.framework._export_persistence_plan(profile, plan)
            self.assertEqual(len(paths), 2)
            for path in paths:
                self.assertTrue(os.path.exists(path))

    def test_script_generation_respects_script_dir(self):
        with tempfile.TemporaryDirectory() as tempdir:
            self.framework.module_options = {
                'session': 'gamma',
                'method': 'cron',
                'os': 'linux',
                'script_dir': tempdir,
                'generate_scripts': 'true'
            }
            profile = self.framework._resolve_persistence_profile()
            plan = self.framework._build_persistence_plan(profile)
            scripts = self.framework._generate_persistence_scripts(profile, plan)
            self.assertEqual(len(scripts), 1)
            self.assertTrue(os.path.exists(scripts[0]))
            self.assertTrue(scripts[0].endswith('.sh'))


if __name__ == '__main__':
    unittest.main()
