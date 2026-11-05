"""Oracle regression tests. Fake results here are NOT native Windows/macOS evidence."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import ctypes
from contextlib import ExitStack
from unittest import mock

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


class FakeFunction:
    def __init__(self, fn):
        self.fn = fn

    def __call__(self, *args):
        return self.fn(*args)


class FakeWindowsAPI:
    """Deterministic API model, never a real Windows execution or protection."""
    def __init__(self, fail=None, lose_lock_on_none=False, invalid_query=False):
        self.buffer = ctypes.create_string_buffer(probe.mmap.PAGESIZE)
        self.address = ctypes.addressof(self.buffer)
        self.error = 0
        self.locked = False
        self.protection = 4
        self.fail = fail or {}
        self.lose_lock_on_none = lose_lock_on_none
        self.invalid_query = invalid_query
        self.calls = []
        for name in ('VirtualAlloc','VirtualFree','VirtualLock','VirtualUnlock','VirtualProtect',
                     'GetCurrentProcess','K32QueryWorkingSetEx','SetErrorMode'):
            setattr(self, name, FakeFunction(lambda *args, n=name: self.call(n, *args)))

    def call(self, name, *args):
        self.calls.append(name)
        if name in self.fail:
            self.error = self.fail[name]
            return 0
        if name == 'VirtualAlloc':
            return self.address
        if name == 'VirtualLock':
            self.locked = True
        elif name == 'VirtualUnlock':
            if not self.locked:
                self.error = 158
                return 0
            self.locked = False
        elif name == 'VirtualProtect':
            self.protection = args[2]
            if self.protection == 1 and self.lose_lock_on_none:
                self.locked = False
        elif name == 'K32QueryWorkingSetEx':
            # Invalid entries deliberately carry a stale Locked bit: it must be ignored.
            flags = (1 << 22) if self.invalid_query else (1 | (self.protection << 4) | (int(self.locked) << 22))
            args[1]._obj.VirtualAttributes = flags
        return 1


class WindowsInstrumentationTests(unittest.TestCase):
    def environment(self, api, perturb_error_on_emit=False):
        self.events = []
        stack = ExitStack()
        stack.enter_context(mock.patch.object(probe.sys, 'platform', 'win32'))
        stack.enter_context(mock.patch.object(ctypes, 'WinDLL', return_value=api, create=True))
        stack.enter_context(mock.patch.object(ctypes, 'set_last_error', side_effect=lambda v: setattr(api,'error',v), create=True))
        stack.enter_context(mock.patch.object(ctypes, 'get_last_error', side_effect=lambda: api.error, create=True))
        def emit(event, **fields):
            self.events.append(dict(event=event, **fields))
            if perturb_error_on_emit:
                api.error = 999
        stack.enter_context(mock.patch.object(probe, 'emit', side_effect=emit))
        return stack

    def test_pointer_layout_matches_two_native_words(self):
        class W(ctypes.Structure):
            _fields_=[('address',ctypes.c_void_p),('flags',ctypes.c_size_t)]
        self.assertEqual(ctypes.sizeof(W),2*ctypes.sizeof(ctypes.c_void_p))

    def test_locked_bit_is22_and_protection_is_bits4_to14(self):
        self.assertEqual(probe.decode_working_set(1|(1<<22)|(4<<4)),dict(valid=True,locked=True,protection=4))

    def test_valid_unlocked_entry(self):
        self.assertEqual(probe.decode_working_set(1|(2<<4)),dict(valid=True,locked=False,protection=2))

    def test_invalid_entry_cannot_claim_locked(self):
        self.assertEqual(probe.decode_working_set(1<<22),dict(valid=False,locked=None,protection=None))

    def test_invalid_flags_rejected(self):
        for value in (-1, True, None, '1'):
            with self.assertRaises(ValueError):
                probe.decode_working_set(value)

    def test_model_healthy_full_close_zeros_the_entire_page(self):
        api=FakeWindowsAPI()
        with self.environment(api):
            page=probe.Page(case='control_read')
            ctypes.memset(page.address,0x77,page.size)
            page.close()
            self.assertIsNone(page.address)
            self.assertFalse(page.locked)
            page.close()
        self.assertEqual(api.buffer.raw[:probe.mmap.PAGESIZE],bytes(probe.mmap.PAGESIZE))
        self.assertEqual(api.calls.count('VirtualFree'),1)
        self.assertEqual(api.calls.count('VirtualUnlock'),1)
        zero=next(e for e in self.events if e['event']=='MEMORY_ZEROED')
        self.assertEqual(zero['readback_bytes'],probe.mmap.PAGESIZE)

    def test_last_error_captured_before_emit_can_overwrite_it(self):
        api=FakeWindowsAPI(fail={'VirtualUnlock':158})
        with self.environment(api,True):
            page=probe.Page(case='roundtrip')
            with self.assertRaises(probe.NativeCallError) as ctx:
                page.close()
        self.assertEqual(ctx.exception.win32_code,158)
        self.assertEqual(ctx.exception.operation,'VirtualUnlock')
        row=next(e for e in self.events if e.get('operation')=='VirtualUnlock')
        self.assertEqual(row['win32_error'],158)
        self.assertFalse(row['succeeded'])
        self.assertEqual(api.calls.count('VirtualFree'),1)

    def test_noaccess_lock_loss_model_is_reported_and_not_accepted(self):
        api=FakeWindowsAPI(lose_lock_on_none=True)
        with self.environment(api):
            page=probe.Page(case='roundtrip')
            page.protect('none')
            page.protect('rw')
            with self.assertRaises(probe.NativeCallError) as ctx:
                page.close()
        self.assertEqual(ctx.exception.win32_code,158)
        before=next(e for e in self.events if e['event']=='PAGE_STATE' and e['phase']=='initial_readback')
        after=next(e for e in self.events if e['event']=='PAGE_STATE' and e['phase']=='before_unlock')
        self.assertTrue(before['locked'])
        self.assertFalse(after['locked'])
        self.assertEqual(api.calls.count('VirtualLock'),1)  # no silent relock

    def test_invalid_query_entry_remains_unknown(self):
        api=FakeWindowsAPI(invalid_query=True)
        with self.environment(api):
            page=probe.Page(case='control_read');page.close()
        states=[e for e in self.events if e['event']=='PAGE_STATE']
        self.assertTrue(states)
        self.assertTrue(all(e['locked'] is None for e in states))

    def test_allocator_failure_retains_error_without_invalid_free(self):
        api=FakeWindowsAPI(fail={'VirtualAlloc':8})
        with self.environment(api):
            with self.assertRaises(probe.NativeCallError) as ctx:
                probe.Page(case='control_read')
        self.assertEqual(ctx.exception.win32_code,8)
        self.assertNotIn('VirtualFree',api.calls)

    def test_lock_failure_frees_page_without_attempting_unlock(self):
        api=FakeWindowsAPI(fail={'VirtualLock':1453})
        with self.environment(api):
            with self.assertRaises(probe.NativeCallError) as ctx:
                probe.Page(case='control_read')
        self.assertEqual(ctx.exception.win32_code,1453)
        self.assertIn('VirtualFree',api.calls)
        self.assertNotIn('VirtualUnlock',api.calls)

    def test_query_failure_is_failure_and_release_still_attempted(self):
        api=FakeWindowsAPI(fail={'K32QueryWorkingSetEx':5})
        with self.environment(api):
            with self.assertRaises(probe.NativeCallError) as ctx:
                probe.Page(case='control_read')
        self.assertEqual(ctx.exception.win32_code,5)
        self.assertIn('VirtualFree',api.calls)

    def test_protect_failure_not_ignored(self):
        api=FakeWindowsAPI()
        with self.environment(api):
            page=probe.Page(case='roundtrip');api.fail['VirtualProtect']=87
            with self.assertRaises(probe.NativeCallError) as ctx:
                page.close()
        self.assertEqual(ctx.exception.win32_code,87)
        self.assertIn('VirtualFree',api.calls)

    def test_free_failure_is_still_failure(self):
        api=FakeWindowsAPI(fail={'VirtualFree':87})
        with self.environment(api):
            page=probe.Page(case='control_read')
            with self.assertRaises(probe.NativeCallError) as ctx:
                page.close()
        self.assertEqual(ctx.exception.operation,'VirtualFree')
        self.assertEqual(ctx.exception.win32_code,87)

    def test_two_cleanup_failures_have_two_exact_trace_records(self):
        api=FakeWindowsAPI(fail={'VirtualUnlock':158,'VirtualFree':87})
        with self.environment(api):
            page=probe.Page(case='roundtrip')
            with self.assertRaises(probe.NativeCallError):
                page.close()
        errors={(e['operation'],e['win32_error']) for e in self.events if e['event']=='API_CALL' and not e['succeeded']}
        self.assertEqual(errors,{('VirtualUnlock',158),('VirtualFree',87)})

    def test_noaccess_then_rw_keeps_both_ordered_state_witnesses(self):
        api=FakeWindowsAPI()
        with self.environment(api):
            page=probe.Page(case='roundtrip');page.protect('none');page.protect('rw');page.close()
        phases=[e['phase'] for e in self.events if e['event']=='PAGE_STATE']
        self.assertLess(phases.index('before_protect:none'),phases.index('after_protect:none'))
        self.assertLess(phases.index('after_protect:none'),phases.index('before_protect:rw'))
        self.assertLess(phases.index('after_protect:rw'),phases.index('before_unlock'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
