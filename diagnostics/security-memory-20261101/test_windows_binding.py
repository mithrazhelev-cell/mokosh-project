"""Modeled Win32/DPAPI call boundary; no actual Windows encryption here."""
import ctypes,io,json,sys,unittest
from contextlib import ExitStack,redirect_stdout
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
from session_key import RetainedSessionKey,WindowsMemoryBackend,SessionKeyError
from test_probe import FakeWindowsAPI,FakeFunction
from test_session_key import PUBLIC_KEY

class FakeCrypt32:
    def __init__(self,kernel):
        self.kernel=kernel;self.calls=[];self.fail={}
        for name in ('CryptProtectMemory','CryptUnprotectMemory'):
            setattr(self,name,FakeFunction(lambda *args,n=name:self.call(n,*args)))
    def call(self,name,address,length,flags):
        self.calls.append(dict(operation=name,length=length,flags=flags))
        if name in self.fail:self.kernel.error=self.fail[name];return 0
        raw=ctypes.string_at(address,length)
        ctypes.memmove(address,bytes(v^0x5a for v in raw),length) # fake only
        return 1

class WindowsBindingTests(unittest.TestCase):
    def setUp(self):
        self.api=FakeWindowsAPI();self.crypto=FakeCrypt32(self.api);self.output=io.StringIO();self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch('sys.platform','win32'))
        self.dll=self.stack.enter_context(patch.object(ctypes,'WinDLL',side_effect=lambda name,**kw:self.crypto if name=='crypt32' else self.api,create=True))
        self.stack.enter_context(patch.object(ctypes,'set_last_error',side_effect=lambda v:setattr(self.api,'error',v),create=True))
        self.stack.enter_context(patch.object(ctypes,'get_last_error',side_effect=lambda:self.api.error,create=True))
        self.stack.enter_context(redirect_stdout(self.output))
    def make(self):
        k=RetainedSessionKey(WindowsMemoryBackend(),PUBLIC_KEY);self.addCleanup(k.close);return k
    def test_exact_same_process_and_whole_page_length(self):
        k=self.make()
        with k.use() as v:self.assertEqual(bytes(v),PUBLIC_KEY)
        self.assertEqual([c['operation'] for c in self.crypto.calls],['CryptProtectMemory','CryptUnprotectMemory','CryptProtectMemory'])
        self.assertTrue(all(c['length']==4096 and c['flags']==0 for c in self.crypto.calls))
        self.dll.assert_any_call('crypt32',use_last_error=True,winmode=0x00000800)
    def test_readonly_idle_and_active_no_noaccess(self):
        k=self.make();self.assertEqual(self.api.protection,2)
        with k.use() as v:self.assertTrue(v.readonly);self.assertEqual(self.api.protection,2)
        self.assertTrue(self.api.locked);self.assertEqual(self.api.protection,2)
        self.assertNotIn('protect:none',self.output.getvalue())
    def test_initial_encrypt_error_zeros_and_releases(self):
        self.crypto.fail['CryptProtectMemory']=5
        with self.assertRaisesRegex(SessionKeyError,'failed:5'):self.make()
        self.assertIn('VirtualFree',self.api.calls);self.assertEqual(self.api.buffer.raw[:4096],bytes(4096))
    def test_unprotect_error_is_not_replaced_by_readback(self):
        k=self.make();self.crypto.fail['CryptUnprotectMemory']=87
        with self.assertRaisesRegex(SessionKeyError,'failed:87'):
            with k.use():self.fail('failed decrypt yielded')
        self.assertEqual(k.state,'FAILED');self.assertEqual(self.api.buffer.raw[:4096],bytes(4096))
    def test_reprotect_error_is_not_tolerated(self):
        k=self.make()
        with self.assertRaisesRegex(SessionKeyError,'failed:5'):
            with k.use():self.crypto.fail['CryptProtectMemory']=5
        self.assertEqual(k.state,'FAILED');self.assertIn('VirtualFree',self.api.calls)
    def test_zero_before_unlock_and_free(self):
        k=self.make();observed=[];original=self.api.VirtualUnlock.fn
        def unlock(*args):observed.append(self.api.buffer.raw[:4096]);return original(*args)
        self.api.VirtualUnlock.fn=unlock;k.close()
        self.assertEqual(observed,[bytes(4096)]);self.assertEqual(self.api.calls.count('VirtualFree'),1)
    def test_unknown_working_set_cannot_load_key(self):
        backend=WindowsMemoryBackend();self.api.invalid_query=True
        with self.assertRaises(SessionKeyError):RetainedSessionKey(backend,PUBLIC_KEY)
        self.assertFalse(self.crypto.calls);self.assertIn('VirtualFree',self.api.calls)
    def test_lock_loss_during_crypto_aborts(self):
        k=self.make();original=self.crypto.CryptUnprotectMemory.fn
        def lose(*args):result=original(*args);self.api.locked=False;return result
        self.crypto.CryptUnprotectMemory.fn=lose
        with self.assertRaises(Exception):
            with k.use():self.fail('lost lock yielded')
        self.assertEqual(k.state,'FAILED');self.assertIn('VirtualFree',self.api.calls)
    def test_native_free_failure_is_not_success(self):
        k=self.make();self.api.fail['VirtualFree']=87
        with self.assertRaises(OSError):k.close()
        self.assertEqual(k.state,'FAILED')

if __name__=='__main__':unittest.main(verbosity=2)
