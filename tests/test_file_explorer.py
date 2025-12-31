import os
import threading
import tempfile
import unittest
from collections import OrderedDict
from unittest.mock import MagicMock

from tests.tt_loader import load_tt


tt = load_tt()
KNDYSFramework = tt.KNDYSFramework
ExplorerEntry = tt.ExplorerEntry


class FileExplorerProfileTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework._explorer_cache = OrderedDict()
        self.framework._explorer_cache_lock = threading.Lock()

    def test_safe_path_enforces_root(self):
        root = tempfile.mkdtemp()
        outside = '/etc/passwd'
        with self.assertRaises(ValueError):
            self.framework._safe_explorer_path(outside, root, allow_outside=False)

    def test_profile_resolution_defaults(self):
        base = tempfile.mkdtemp()
        self.framework.module_options = {
            'session': '42',
            'root': base,
            'path': base,
            'mode': 'search',
            'pattern': '*.log',
            'pattern_mode': 'glob',
            'max_depth': '3',
            'max_entries': '50',
            'include_hidden': 'true',
            'hash_files': 'true',
            'preview': 'true'
        }
        profile = self.framework._resolve_file_explorer_profile()
        self.assertIsNotNone(profile)
        self.assertEqual(profile['session_id'], '42')
        self.assertEqual(profile['mode'], 'search')
        self.assertEqual(profile['max_depth'], 3)
        self.assertTrue(profile['include_hidden'])
        self.assertTrue(profile['hash_files'])
        self.assertTrue(profile['preview'])
        self.assertEqual(profile['pattern'], '*.log')


class FileExplorerExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        base = self.tempdir.name
        with open(os.path.join(base, 'visible.txt'), 'w', encoding='utf-8') as fh:
            fh.write('hello world')
        with open(os.path.join(base, '.hidden.txt'), 'w', encoding='utf-8') as fh:
            fh.write('secret')
        subdir = os.path.join(base, 'logs')
        os.makedirs(subdir, exist_ok=True)
        with open(os.path.join(subdir, 'notes.txt'), 'w', encoding='utf-8') as fh:
            fh.write('nested file')
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework._explorer_cache = OrderedDict()
        self.framework._explorer_cache_lock = threading.Lock()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_execute_respects_filters_and_hashing(self):
        base = self.tempdir.name
        self.framework.module_options = {
            'session': 'sess',
            'root': base,
            'path': base,
            'mode': 'recursive',
            'pattern': '*.txt',
            'pattern_mode': 'glob',
            'file_types': 'files',
            'include_hidden': 'false',
            'max_depth': '5',
            'max_entries': '10',
            'hash_files': 'true',
            'hash_limit': '2048',
            'preview': 'false'
        }
        profile = self.framework._resolve_file_explorer_profile()
        result = self.framework._execute_file_explorer(profile)
        entries = result['entries']
        self.assertEqual(len(entries), 2)
        names = {entry.name for entry in entries}
        self.assertIn('visible.txt', names)
        self.assertIn('notes.txt', names)
        self.assertTrue(all(entry.hash for entry in entries if entry.name == 'visible.txt'))
        self.assertTrue(all(not name.startswith('.') for name in names))


if __name__ == '__main__':
    unittest.main()
