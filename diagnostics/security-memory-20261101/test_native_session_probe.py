"""Oracle controls over modeled API traces, not real Windows outcomes."""
import copy,ctypes,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import native_session_probe as n
import test_windows_binding as binding

def reference():
    rows=[]
    for mode in n.MODES:
        if mode=='timeout':
            rows.append(dict(mode=mode,exit=1,timed_out=True,reaped=True,elapsed_seconds=5,events=[dict(event='READY',mode=mode,phase='OWNED_TEST_WAIT')],stderr=''));continue
        env=binding.WindowsBindingTests('test_exact_same_process_and_whole_page_length');env.setUp()
        original=ctypes.memset
        def write(address,value,length):
            if length==1 and env.api.protection==2:raise OSError('access violation writing synthetic readonly address')
            return original(address,value,length)
        try:
            with patch.object(ctypes,'memset',side_effect=write):code=n.child(mode)
            events=[json.loads(line) for line in env.output.getvalue().splitlines()]
        finally:env.doCleanups()
        rows.append(dict(mode=mode,exit=code,timed_out=False,reaped=True,elapsed_seconds=0,events=events,stderr=''))
    return rows

class NativeOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.rows=reference()
    def altered(self,mode,change):
        rows=copy.deepcopy(self.rows);change(next(r for r in rows if r['mode']==mode));self.assertFalse(all(n.assess(rows).values()))
    def test_complete_modeled_reference(self):self.assertTrue(all(n.assess(copy.deepcopy(self.rows)).values()))
    def test_missing_case_rejected(self):
        with self.assertRaises(ValueError):n.assess(self.rows[:-1])
    def test_wrong_timeout_ready_rejected(self):self.altered('timeout',lambda r:r['events'][0].update(phase='ACTIVE_PLAINTEXT'))
    def test_not_reaped_rejected(self):
        self.altered('retained_roundtrip',lambda r:r.update(reaped=False))
        self.altered('retained_roundtrip',lambda r:r.update(tool_error='injected output failure'))
    def test_ignored_encrypt_error_rejected(self):
        self.altered('consumer_exception',lambda r:next(e for e in r['events'] if e['event']=='MEMORY_CRYPT').update(succeeded=False,win32_error=5))
    def test_missing_reprotect_rejected(self):
        self.altered('consumer_exception',lambda r:r.update(events=[e for i,e in enumerate(r['events']) if i!=max(j for j,v in enumerate(r['events']) if v['event']=='MEMORY_CRYPT')]))
    def test_partial_wipe_rejected(self):self.altered('control_write',lambda r:next(e for e in r['events'] if e['event']=='MEMORY_ZEROED').update(readback_bytes=32))
    def test_plaintext_idle_rejected(self):self.altered('retained_roundtrip',lambda r:next(e for e in r['events'] if e['event']=='SESSION_PARKED').update(fixture_not_plaintext=False))
    def test_same_key_mismatch_rejected(self):self.altered('retained_roundtrip',lambda r:next(e for e in r['events'] if e['event']=='SAME_FIXTURE').update(cycle=99))
    def test_wrong_denial_phase_rejected(self):self.altered('idle_readonly_write',lambda r:next(e for e in r['events'] if e['event']=='ACCESS_VIOLATION').update(phase='ACTIVE_PLAINTEXT'))
    def test_access_success_not_counted_as_denial(self):self.altered('active_readonly_write',lambda r:next(e for e in r['events'] if e['event']=='ACCESS_VIOLATION').update(event='ACCESS_SUCCEEDED'))
    def test_cross_process_scope_not_counted_as_same_process(self):self.altered('retained_roundtrip',lambda r:next(e for e in r['events'] if e['event']=='MEMORY_CRYPT').update(scope='CROSS_PROCESS'))
    def test_unknown_lock_rejected(self):self.altered('retained_roundtrip',lambda r:next(e for e in r['events'] if e.get('phase')=='session_lock_guard').update(locked=None,valid=False))
    def test_key_marker_before_unprotect_rejected(self):
        def change(r):
            i=next(i for i,e in enumerate(r['events']) if e['event']=='SAME_FIXTURE');r['events'].insert(0,r['events'].pop(i))
        self.altered('retained_roundtrip',change)
    def test_writable_key_marker_rejected(self):self.altered('retained_roundtrip',lambda r:next(e for e in r['events'] if e['event']=='SAME_FIXTURE').update(readonly=False))

if __name__=='__main__':unittest.main(verbosity=2)
