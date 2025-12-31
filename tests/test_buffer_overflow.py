import unittest

from tests.tt_loader import load_tt


tt = load_tt()

KNDYSFramework = tt.KNDYSFramework
CyclicPatternGenerator = tt.CyclicPatternGenerator
BufferOverflowPayloadPlanner = tt.BufferOverflowPayloadPlanner


class BufferOverflowProfileResolutionTests(unittest.TestCase):
    def setUp(self):
        self.framework = KNDYSFramework.__new__(KNDYSFramework)
        self.framework.config = {'user_agent': 'UnitTestAgent/1.0'}
        self.framework.module_options = {}

    def test_profile_resolution_handles_custom_inputs(self):
        self.framework.module_options = {
            'target': '10.0.0.5:1337',
            'protocol': 'udp',
            'payload_strategy': 'progressive,custom-lengths',
            'start_length': '128',
            'max_length': '512',
            'step_length': '128',
            'cyclic_length': '1024',
            'max_payloads': '5',
            'custom_lengths': '700,900',
            'custom_payloads': 'ABC||DEF',
            'command_template': 'OVERFLOW1 {{PAYLOAD}}\\r\\n',
            'encoding': 'latin-1',
            'connection_timeout': '2.5',
            'response_timeout': '4',
            'settle_delay': '0.2',
            'max_retries': '2',
            'crash_indicators': 'connection reset,no response',
            'stop_on_crash': 'false',
            'offset_value': '0x39654138',
            'threads': '2',
            'report_prefix': 'bo_test'
        }

        profile = self.framework._resolve_buffer_overflow_profile()

        self.assertEqual(profile['host'], '10.0.0.5')
        self.assertEqual(profile['port'], 1337)
        self.assertEqual(profile['protocol'], 'udp')
        self.assertIn('custom-lengths', profile['payload_strategy'])
        self.assertIn('custom-payloads', profile['payload_strategy'])
        self.assertEqual(profile['command_template'], 'OVERFLOW1 {{PAYLOAD}}\\r\\n')
        self.assertFalse(profile['stop_on_crash'])
        self.assertEqual(profile['threads'], 2)
        self.assertEqual(profile['custom_lengths'], [700, 900])
        self.assertEqual(profile['custom_payloads'], ['ABC', 'DEF'])
        self.assertEqual(profile['offset_value'], '0x39654138')


class CyclicPatternGeneratorTests(unittest.TestCase):
    def test_offset_calculation_matches_pattern(self):
        generator = CyclicPatternGenerator()
        pattern = generator.generate(400)
        self.assertEqual(len(pattern), 400)
        token = pattern[210:214]
        token_hex = token[::-1].encode('latin-1').hex()
        offset = generator.find_offset('0x' + token_hex, search_space=600)
        self.assertEqual(offset, 210)


class BufferOverflowPayloadPlannerTests(unittest.TestCase):
    def test_planner_builds_expected_payloads(self):
        profile = {
            'payload_strategy': ['progressive', 'custom-lengths', 'custom-payloads', 'cyclic'],
            'start_length': 64,
            'max_length': 128,
            'step_length': 64,
            'cyclic_length': 96,
            'max_payloads': 6,
            'custom_lengths': [512],
            'custom_payloads': ['XYZ123'],
            'encoding': 'latin-1'
        }

        planner = BufferOverflowPayloadPlanner(profile)
        payloads = planner.build()

        names = [payload.name for payload in payloads]
        self.assertIn('progressive_64', names)
        self.assertIn('custom_len_512', names)
        self.assertTrue(any(payload.cyclic for payload in payloads))
        self.assertEqual(payloads[0].length, 64)


if __name__ == '__main__':
    unittest.main()
