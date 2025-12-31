import os
import tempfile
import unittest
from unittest.mock import MagicMock

from tests.tt_loader import load_tt


tt = load_tt()
KNDYSFramework = tt.KNDYSFramework


class CredentialDumperTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.module_options = {}
        self.framework.logger = MagicMock()
        self.framework.error_handler = MagicMock()
        self.framework.save_credential = MagicMock()
        self.framework.config = {'user_agent': 'test-agent'}

    def test_profile_resolution_respects_custom_options(self):
        custom_path = os.path.join(tempfile.gettempdir(), 'creds.txt')
        self.framework.module_options = {
            'session': 'cred-demo',
            'mode': 'fast',
            'os': 'linux',
            'preview_bytes': '256',
            'max_artifacts': '15',
            'include_env': 'false',
            'include_processes': 'false',
            'secret_keywords': 'api,token',
            'custom_paths': custom_path,
            'audit_log': 'off'
        }
        profile = self.framework._resolve_credential_profile()
        self.assertEqual(profile['session_id'], 'cred-demo')
        self.assertEqual(profile['target_os'], 'linux')
        self.assertFalse(profile['collect_env'])
        self.assertIn(os.path.expanduser(custom_path), profile['custom_paths'])
        self.assertIn('api', profile['secret_keywords'])
        self.assertEqual(profile['preview_bytes'], 256)

    def test_file_artifact_detection_masks_secret(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as fh:
            fh.write('username=alice\npassword=s3cr3tValue\n')
            secret_path = fh.name
        self.framework.module_options = {
            'session': 'cred-test',
            'mode': 'fast',
            'os': 'linux',
            'include_env': 'false',
            'include_processes': 'false',
            'custom_paths': secret_path,
            'audit_log': 'off'
        }
        profile = self.framework._resolve_credential_profile()
        source = {'name': 'Test Secret', 'type': 'file', 'paths': [secret_path], 'category': 'test', 'artifact_type': 'text'}
        try:
            artifact, warnings, consumed = self.framework._collect_file_artifact(secret_path, source, profile)
            self.assertIsNotNone(artifact)
            self.assertFalse(warnings)
            self.assertGreater(consumed, 0)
            self.assertIn('credential_hits', artifact.metadata)
            self.assertNotIn('s3cr3tValue', artifact.preview)
            self.assertEqual(len(artifact.hash_preview), 64)
            self.framework.save_credential.assert_called_once()
        finally:
            os.unlink(secret_path)

    def test_execute_collection_reports_summary(self):
        with tempfile.NamedTemporaryFile('w', delete=False) as fh:
            fh.write('token=abc1234567890')
            custom_path = fh.name
        self.framework.module_options = {
            'session': 'exec-demo',
            'mode': 'fast',
            'os': 'linux',
            'include_env': 'false',
            'include_processes': 'false',
            'audit_log': 'off'
        }
        profile = self.framework._resolve_credential_profile()
        sources = [{'name': 'Custom Artifact', 'type': 'file', 'paths': [custom_path], 'category': 'custom', 'artifact_type': 'text'}]
        try:
            result = self.framework._execute_credential_collection(profile, sources)
            self.assertGreaterEqual(result['summary'].total_artifacts, 1)
            self.assertIn('custom', result['summary'].categories)
            self.assertTrue(any(os.path.realpath(custom_path) == art.path for art in result['artifacts']))
        finally:
            os.unlink(custom_path)


if __name__ == '__main__':
    unittest.main()
