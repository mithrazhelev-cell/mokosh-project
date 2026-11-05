"""State/attack controls with a modeled Windows API; never native OS evidence."""
import copy
import ctypes
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent
def read_module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
safe=read_module('safe_probe',ROOT/'safe_probe.py')
fixtures=read_module('fixtures',ROOT/'test_probe.py')
fixtures.probe=safe.base


def modeled_case(mode):
    api=fixtures.FakeWindowsAPI(lose_lock_on_none=True)
    h=fixtures.WindowsInstrumentationTests()
    original=ctypes.string_at
    def guarded_read(address,size):
        if api.protection==1:raise OSError('exception: access violation reading modeled page')
        return original(address,size)
    with h.environment(api),mock.patch.object(ctypes,'string_at',side_effect=guarded_read):
        code=safe.child(mode)
    return dict(mode=mode,exit=code,reaped=True,timed_out=False,elapsed_seconds=0.1,stderr='',events=h.events)


def all_model_rows():
    return [modeled_case(m) if m!='timeout' else dict(mode=m,exit=1,reaped=True,timed_out=True,
             elapsed_seconds=5.01,stderr='',events=[dict(event='READY',mode=m)]) for m in safe.MODES]


class SafeProtocolTests(unittest.TestCase):
    def test_six_model_paths_meet_scoped_contract_only(self):
        rows=all_model_rows();self.assertTrue(all(safe.assess(rows).values()))

    def test_live_page_refuses_noaccess_before_any_native_transition(self):
        r=modeled_case('live_noaccess_refused')
        self.assertFalse(any(e.get('phase')=='protect:none' for e in r['events']))
        self.assertEqual(r['exit'],0)

    def test_explicit_empty_unlock_happens_before_noaccess(self):
        r=modeled_case('parked_noaccess_read');e=r['events']
        wipe=next(i for i,x in enumerate(e) if x['event']=='PARK_WIPED')
        unlock=next(i for i,x in enumerate(e) if x.get('phase')=='park_unlock_empty')
        none=next(i for i,x in enumerate(e) if x.get('phase')=='protect:none')
        self.assertLess(wipe,unlock);self.assertLess(unlock,none)
        self.assertEqual(sum(x.get('operation')=='VirtualUnlock' for x in e),1)

    def test_reload_has_observed_lock_before_fixture_write(self):
        e=modeled_case('park_reload')['events']
        lock=next(i for i,x in enumerate(e) if x.get('phase')=='reload_lock_empty')
        guard=next(i for i,x in enumerate(e) if x.get('phase')=='before_public_reload')
        loaded=next(i for i,x in enumerate(e) if x['event']=='PUBLIC_FIXTURE_RELOADED')
        self.assertLess(lock,guard);self.assertLess(guard,loaded)

    def test_actual_model_bytes_are_empty_when_reload_lock_is_called(self):
        api=fixtures.FakeWindowsAPI();h=fixtures.WindowsInstrumentationTests()
        with h.environment(api):
            p=safe.SyntheticPage('test');p.park_empty();previous=api.VirtualLock.fn
            def lock_empty(*args):
                self.assertEqual(api.buffer.raw[:p.size],bytes(p.size))
                return previous(*args)
            api.VirtualLock=fixtures.FakeFunction(lock_empty)
            p.reload_public_fixture();p.close()

    def test_actual_model_bytes_are_empty_before_every_unlock(self):
        api=fixtures.FakeWindowsAPI();h=fixtures.WindowsInstrumentationTests()
        with h.environment(api):
            p=safe.SyntheticPage('test');previous=api.VirtualUnlock.fn;observed=[]
            def unlock_empty(*args):
                self.assertEqual(api.buffer.raw[:p.size],bytes(p.size));observed.append(True)
                return previous(*args)
            api.VirtualUnlock=fixtures.FakeFunction(unlock_empty)
            p.park_empty();p.reload_public_fixture();p.close()
        self.assertEqual(len(observed),2)

    def test_unknown_initial_lock_is_refused(self):
        api=fixtures.FakeWindowsAPI(invalid_query=True);h=fixtures.WindowsInstrumentationTests()
        with h.environment(api),self.assertRaises(safe.ProtocolError):safe.SyntheticPage('test')
        self.assertIn('VirtualFree',api.calls)

    def test_lock_failure_during_empty_reload_cannot_load_fixture(self):
        api=fixtures.FakeWindowsAPI();h=fixtures.WindowsInstrumentationTests()
        with h.environment(api):
            p=safe.SyntheticPage('test');p.park_empty();api.fail['VirtualLock']=1453
            with self.assertRaises(safe.base.NativeCallError):p.reload_public_fixture()
            self.assertNotIn(safe.base.VALUE,api.buffer.raw)
            self.assertFalse(any(e['event']=='PUBLIC_FIXTURE_RELOADED' for e in h.events));p.close()

    def test_failed_explicit_unlock_cannot_enter_noaccess(self):
        api=fixtures.FakeWindowsAPI();h=fixtures.WindowsInstrumentationTests()
        with h.environment(api):
            p=safe.SyntheticPage('test');api.fail['VirtualUnlock']=158
            with self.assertRaises(safe.base.NativeCallError):p.park_empty()
            self.assertFalse(any(e.get('phase')=='protect:none' for e in h.events))
            with self.assertRaises(safe.base.NativeCallError):p.close()

    def test_partial_wipe_is_rejected_before_unlock(self):
        api=fixtures.FakeWindowsAPI();h=fixtures.WindowsInstrumentationTests();real=ctypes.memset
        with h.environment(api):
            p=safe.SyntheticPage('test');real(p.address,119,p.size)
            with mock.patch.object(ctypes,'memset',side_effect=lambda a,v,n:real(a,v,len(safe.base.VALUE))):
                with self.assertRaises(safe.ProtocolError):p.park_empty()
            self.assertNotIn('VirtualUnlock',api.calls);p.close()

    def test_bad_reload_order_refused(self):
        api=fixtures.FakeWindowsAPI();h=fixtures.WindowsInstrumentationTests()
        with h.environment(api):
            p=safe.SyntheticPage('test')
            with self.assertRaises(safe.ProtocolError):p.reload_public_fixture()
            p.close()

    def test_closed_page_cannot_park(self):
        api=fixtures.FakeWindowsAPI();h=fixtures.WindowsInstrumentationTests()
        with h.environment(api):
            p=safe.SyntheticPage('test');p.close()
            with self.assertRaises(safe.ProtocolError):p.park_empty()

    def test_non_windows_refused_before_allocation(self):
        with mock.patch.object(safe.sys,'platform','linux'),self.assertRaises(safe.ProtocolError):safe.SyntheticPage('test')

    def test_legacy_unsafe_mode_names_cannot_masquerade_as_safe_protocol(self):
        rows=all_model_rows();rows[0]['mode']='roundtrip'
        with self.assertRaises(safe.ProtocolError):safe.assess(rows)

    def test_assessor_detects_missing_wipe_or_wrong_phase_or_missing_lock(self):
        baseline=all_model_rows()
        for event,field in [('PARK_WIPED','verified'),('PAGE_STATE','locked'),('PUBLIC_FIXTURE_RELOADED','locked_before_load')]:
            rows=copy.deepcopy(baseline);r=next(x for x in rows if x['mode']=='park_reload')
            e=next(x for x in r['events'] if x['event']==event and (event!='PAGE_STATE' or x.get('phase')=='before_public_reload'))
            e[field]=False
            self.assertFalse(safe.assess(rows)['park_reload'])

    def test_wrong_denial_mode_and_cleanup_failure_are_rejected(self):
        for mutation in ('wrong_mode','cleanup_fail','access_succeeded','unreaped'):
            rows=all_model_rows();r=next(x for x in rows if x['mode']=='parked_noaccess_read')
            if mutation=='wrong_mode':next(x for x in r['events'] if x['event']=='ACCESS_VIOLATION')['mode']='park_reload'
            elif mutation=='cleanup_fail':r['exit']=1
            elif mutation=='access_succeeded':r['events'].append(dict(event='ACCESS_SUCCEEDED',mode=r['mode']))
            else:r['reaped']=False
            self.assertFalse(safe.assess(rows)['parked_noaccess_read'])

    def test_model_timeout_must_reach_its_own_ready(self):
        rows=all_model_rows();rows[-1]['events'][0]['mode']='park_reload'
        self.assertFalse(safe.assess(rows)['timeout'])

    def test_duplicate_case_rejected(self):
        rows=all_model_rows();rows[1]=copy.deepcopy(rows[0])
        with self.assertRaises(safe.ProtocolError):safe.assess(rows)


if __name__=='__main__':unittest.main(verbosity=2)
