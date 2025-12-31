import os
import tempfile
import unittest
from unittest.mock import MagicMock

from tests.tt_loader import load_tt


tt = load_tt()
KNDYSFramework = tt.KNDYSFramework


class PivotModuleTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework.config = {'lhost': '10.0.0.5', 'lport': 4444, 'rhost': 'gateway.local'}
        self.framework.session_id = 'sess'

    def test_profile_resolution_defaults(self):
        profile = self.framework._resolve_pivot_profile()
        self.assertEqual(profile['session_id'], 'sess')
        self.assertEqual(profile['entry_host'], 'gateway.local')
        self.assertEqual(profile['target_network'], '192.168.2.0/24')
        self.assertEqual(profile['methods'], ['auto'])
        self.assertTrue(profile['generate_scripts'])

    def test_plan_generation_with_method_filter(self):
        self.framework.module_options = {
            'session': 'alpha',
            'method': 'ssh',
            'transport': 'socks',
            'max_routes': '2'
        }
        profile = self.framework._resolve_pivot_profile()
        plan = self.framework._build_pivot_plan(profile)
        self.assertGreaterEqual(len(plan.routes), 1)
        self.assertTrue(all(route.technique.category == 'ssh' for route in plan.routes))

    def test_export_and_scripts_creation(self):
        self.framework.module_options = {
            'session': 'beta',
            'method': 'chisel',
            'target': '10.10.0.0/16',
            'generate_scripts': 'true'
        }
        profile = self.framework._resolve_pivot_profile()
        plan = self.framework._build_pivot_plan(profile)
        with tempfile.TemporaryDirectory() as tempdir:
            profile['script_dir'] = tempdir
            scripts = self.framework._generate_pivot_scripts(profile, plan)
            self.assertTrue(scripts)
            self.assertTrue(os.path.exists(scripts[0]))
            exports = self.framework._export_pivot_plan(profile, plan)
            self.assertEqual(len(exports), 2)
            for path in exports:
                self.assertTrue(os.path.exists(path))


if __name__ == '__main__':
    unittest.main()
