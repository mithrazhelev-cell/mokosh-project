"""Oracle regression tests. Fake results here are NOT native Windows/macOS evidence."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('probe', Path(__file__).with_name('probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def sample(system='Linux'):
    rows = []
    for mode in probe.MODES:
        row = {'mode': mode, 'exit': 0, 'reaped': True, 'timed_out': False, 'events': []}
        if mode == 'roundtrip':
            row['events'] = [dict(event='ROUNDTRIP_OK', locked=True, reopened=True, own_page_zeroed=True, released=True)]
        else:
            row['events'] = [dict(event='READY', mode=mode, lock_api_succeeded=True, initial_readback=True)]
            if mode in ('readonly_write', 'noaccess_read'):
                row['exit'] = 0xc0000005 if system == 'Windows' else -11
            elif mode == 'timeout':
                row.update(exit=-9, timed_out=True)
            else:
                row['events'].append(dict(event='ACCESS_SUCCEEDED', mode=mode))
        rows.append(row)
    return rows


class OracleTests(unittest.TestCase):
    def test_complete_linux_reference(self):
        self.assertTrue(all(probe.assess(sample(), 'Linux').values()))

    def test_complete_windows_reference_only(self):
        self.assertTrue(all(probe.assess(sample('Windows'), 'Windows').values()))

    def test_complete_macos_reference_only(self):
        self.assertTrue(all(probe.assess(sample(), 'Darwin').values()))

    def test_windows_seh_translation(self):
        row = sample('Windows')[1]
        row['exit'] = 31
        self.assertFalse(probe.denial_observed(row, 'Windows'))
        row['events'].append(dict(event='ACCESS_VIOLATION'))
        self.assertTrue(probe.denial_observed(row, 'Windows'))

    def test_windows_signed_exit(self):
        row = sample('Windows')[1]
        row['exit'] = -1073741819
        self.assertTrue(probe.denial_observed(row, 'Windows'))

    def test_macos_bus_signal_is_target_specific(self):
        row = sample()[1]
        row['exit'] = -10
        self.assertTrue(probe.denial_observed(row, 'Darwin'))
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_linux_bus_signal_is_target_specific(self):
        row = sample()[1]
        row['exit'] = -7
        self.assertTrue(probe.denial_observed(row, 'Linux'))
        self.assertFalse(probe.denial_observed(row, 'Darwin'))

    def test_signal_without_ready_is_not_protection(self):
        row = sample()[1]
        row['events'] = []
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_failed_lock_is_not_protection(self):
        row = sample()[1]
        row['events'][0]['lock_api_succeeded'] = False
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_initial_bytes_not_checked_is_not_protection(self):
        row = sample()[1]
        row['events'][0]['initial_readback'] = False
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_wrong_case_marker_is_not_protection(self):
        row = sample()[1]
        row['events'][0]['mode'] = 'noaccess_read'
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_timeout_is_not_memory_protection(self):
        row = sample()[1]
        row['timed_out'] = True
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_not_reaped_rejects(self):
        row = sample()[1]
        row['reaped'] = False
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_unrelated_failure_is_not_denial(self):
        row = sample()[1]
        for code in (1, 2, -9, 0):
            row['exit'] = code
            self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_access_then_fault_not_prevention(self):
        row = sample()[1]
        row['events'].append(dict(event='ACCESS_SUCCEEDED'))
        self.assertFalse(probe.denial_observed(row, 'Linux'))

    def test_missing_case_rejected(self):
        with self.assertRaises(ValueError):
            probe.assess(sample()[:-1], 'Linux')

    def test_duplicate_case_rejected(self):
        rows = sample()
        with self.assertRaises(ValueError):
            probe.assess(rows + [rows[0]], 'Linux')

    def test_control_failure_breaks_total(self):
        rows = sample()
        rows[3]['exit'] = 1
        self.assertFalse(all(probe.assess(rows, 'Linux').values()))

    def test_missing_cleanup_cannot_pass(self):
        rows = sample()
        rows[0]['events'][0]['released'] = False
        self.assertFalse(all(probe.assess(rows, 'Linux').values()))

    def test_timeout_must_have_started(self):
        rows = sample()
        rows[-1]['events'] = []
        self.assertFalse(all(probe.assess(rows, 'Linux').values()))

    def test_unknown_system_rejected(self):
        with self.assertRaises(ValueError):
            probe.assess(sample(), 'Other')

    def test_existing_output_refused_without_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            sentinel = Path(folder) / 'RESULT.json'
            sentinel.write_text('unchanged')
            with self.assertRaises(FileExistsError):
                probe.run(folder)
            self.assertEqual(sentinel.read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main(verbosity=2)
