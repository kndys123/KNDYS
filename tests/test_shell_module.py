import os
import subprocess
import unittest
from unittest.mock import patch, MagicMock

from tests.tt_loader import load_tt


tt = load_tt()
KNDYSFramework = tt.KNDYSFramework
ShellCommandRecord = tt.ShellCommandRecord


class ShellProfileResolutionTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.SHELL_DEFAULT_ALLOWLIST = {'whoami', 'ls'}
        self.framework.SHELL_BLOCKED_COMMANDS = {'rm'}
        self.framework._safe_float = KNDYSFramework._safe_float.__get__(self.framework)
        self.framework._safe_int = KNDYSFramework._safe_int.__get__(self.framework)
        self.framework._parse_bool_option = KNDYSFramework._parse_bool_option.__get__(self.framework)
        self.framework._parse_list_option = KNDYSFramework._parse_list_option.__get__(self.framework)
        self.framework._build_env_map = KNDYSFramework._build_env_map.__get__(self.framework)
        self.framework.validator = tt.InputValidator()

    def test_resolves_defaults_with_safe_values(self):
        self.framework.module_options = {
            'session': '42',
            'mode': 'batch',
            'timeout': '15',
            'throttle': '0.1',
            'history_limit': '80',
            'history_capture': '1024',
            'record_transcript': 'false',
            'transcript_path': 'custom.log',
            'cwd': '.',
            'allow_commands': 'ipconfig,dir',
            'deny_commands': 'dir',
            'env': 'FOO=bar;HELLO=world',
            'commands': 'whoami\nls',
            'command': 'whoami'
        }
        profile = KNDYSFramework._resolve_shell_profile(self.framework)
        self.assertEqual(profile['session_id'], '42')
        self.assertEqual(profile['mode'], 'batch')
        self.assertAlmostEqual(profile['timeout'], 15.0)
        self.assertAlmostEqual(profile['throttle'], 0.1)
        self.assertEqual(profile['history_limit'], 80)
        self.assertEqual(profile['capture_limit'], 1024)
        self.assertFalse(profile['record_transcript'])
        self.assertEqual(profile['transcript_path'], 'custom.log')
        self.assertIn('whoami', profile['allowlist'])
        self.assertNotIn('dir', profile['allowlist'])
        self.assertEqual(profile['env']['FOO'], 'bar')
        self.assertEqual(len(profile['commands_queue']), 3)


class ShellExecutionTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.validator = tt.InputValidator()
        self.framework.error_handler = MagicMock()
        self.framework.session_manager = MagicMock()
        self.framework.session_manager.get_session.return_value = {'commands': []}
        self.framework.session_manager.create_session.return_value = '1'
        self.framework.session_manager.update_session = MagicMock()
        self.framework.session_manager.close_session = MagicMock()
        self.framework.SHELL_DEFAULT_ALLOWLIST = {'whoami'}
        self.framework.SHELL_BLOCKED_COMMANDS = set()

    @patch('subprocess.run')
    def test_executes_allowed_command_and_records_history(self, mock_run):
        completed = MagicMock()
        completed.stdout = 'demo\n'
        completed.stderr = ''
        completed.returncode = 0
        mock_run.return_value = completed
        profile = {
            'session_id': '1',
            'history_limit': 10,
            'capture_limit': 256,
            'timeout': 5,
            'cwd': os.getcwd(),
            'env': {},
            'allowlist': {'whoami'},
            'denylist': set(),
            'record_transcript': False
        }
        record = KNDYSFramework._execute_shell_command(self.framework, '1', {'commands': []}, profile, 'whoami')
        self.assertIsInstance(record, ShellCommandRecord)
        self.framework.session_manager.update_session.assert_called()

    @patch('subprocess.run', side_effect=subprocess.TimeoutExpired(cmd='whoami', timeout=1))
    def test_handles_timeout(self, mock_run):
        profile = {
            'session_id': '1',
            'history_limit': 10,
            'capture_limit': 256,
            'timeout': 1,
            'cwd': os.getcwd(),
            'env': {},
            'allowlist': {'whoami'},
            'denylist': set(),
            'record_transcript': False
        }
        record = KNDYSFramework._execute_shell_command(self.framework, '1', {'commands': []}, profile, 'whoami')
        self.assertIsInstance(record, ShellCommandRecord)
        self.assertEqual(record.exit_code, -1)
        self.assertIn('Timeout', record.stderr)


if __name__ == '__main__':
    unittest.main()
