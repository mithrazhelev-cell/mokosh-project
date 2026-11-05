"""Lifecycle POLICY models. XOR is a fake OS, never encryption evidence."""
import copy,pickle,sys,threading,unittest
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from session_key import RetainedSessionKey,SessionKeyError,WindowsMemoryBackend
PUBLIC_KEY=bytes(range(32))

class FakeOSBackend:
    """NOT CRYPTOGRAPHY: deterministic reversible bytes for state/fault testing."""
    def __init__(self):
        self.buffer=bytearray(4096);self.locked=True;self.ro=False;self.closed=False
        self.encrypted=False;self.events=[];self.fail_next=None
    def op(self,name):
        self.events.append(name)
        if self.fail_next==name:self.fail_next=None;raise SessionKeyError('injected '+name)
        if self.closed:raise SessionKeyError('closed backend')
    def store(self,key):self.op('store');self.buffer[:32]=key
    def assert_locked(self):
        self.op('guard')
        if not self.locked:raise SessionKeyError('lock unavailable')
    def writable(self):self.op('writable');self.ro=False
    def readonly(self):self.op('readonly');self.ro=True
    def protect(self):
        self.op('protect')
        if self.ro or self.encrypted:raise SessionKeyError('bad protect state')
        self.buffer[:]=bytes(v^0xa5 for v in self.buffer);self.encrypted=True
    def unprotect(self):
        self.op('unprotect')
        if self.ro or not self.encrypted:raise SessionKeyError('bad unprotect state')
        self.buffer[:]=bytes(v^0xa5 for v in self.buffer);self.encrypted=False
    def view(self):
        self.op('view')
        if self.encrypted or not self.ro:raise SessionKeyError('view in wrong state')
        return memoryview(self.buffer)[:32].toreadonly()
    def wipe_release(self):
        self.events.append('wipe_release');self.buffer[:]=bytes(4096)
        self.locked=False;self.closed=True;self.encrypted=False

class LifecycleTests(unittest.TestCase):
    def make(self):
        b=FakeOSBackend();k=RetainedSessionKey(b,PUBLIC_KEY);self.addCleanup(k.close);return k,b
    def test_idle_is_encrypted_and_readonly(self):
        k,b=self.make();self.assertEqual(k.state,'PARKED_ENCRYPTED');self.assertTrue(b.encrypted and b.ro and b.locked);self.assertNotEqual(bytes(b.buffer[:32]),PUBLIC_KEY)
    def test_same_key_survives_repeated_scopes(self):
        k,b=self.make()
        for _ in range(5):
            with k.use() as v:self.assertEqual(bytes(v),PUBLIC_KEY);self.assertTrue(v.readonly and b.locked);self.assertFalse(b.encrypted)
            self.assertTrue(b.encrypted and b.ro)
    def test_view_released_on_normal_exit(self):
        k,b=self.make()
        with k.use() as v:pass
        with self.assertRaises(ValueError):len(v)
    def test_readonly_view_rejects_write(self):
        k,b=self.make()
        with k.use() as v:
            with self.assertRaises(TypeError):v[0]=7
    def test_consumer_exception_reseals(self):
        k,b=self.make()
        with self.assertRaisesRegex(ValueError,'consumer'):
            with k.use():raise ValueError('consumer')
        self.assertEqual(k.state,'PARKED_ENCRYPTED');self.assertTrue(b.encrypted and b.ro)
    def test_keyboard_interrupt_reseals(self):
        k,b=self.make()
        with self.assertRaises(KeyboardInterrupt):
            with k.use():raise KeyboardInterrupt()
        self.assertTrue(b.encrypted)
    def test_nested_use_refused(self):
        k,b=self.make()
        with k.use():
            with self.assertRaises(SessionKeyError):
                with k.use():pass
    def test_close_inside_scope_refused(self):
        k,b=self.make()
        with k.use():
            with self.assertRaises(SessionKeyError):k.close()
            self.assertFalse(b.closed)
    def test_close_is_idempotent_and_zeros_whole_page(self):
        k,b=self.make();k.close();k.close();self.assertEqual(bytes(b.buffer),bytes(4096));self.assertEqual(b.events.count('wipe_release'),1)
    def test_closed_cannot_be_reopened(self):
        k,b=self.make();k.close()
        with self.assertRaises(SessionKeyError):
            with k.use():pass
    def test_copy_and_pickle_refused(self):
        k,b=self.make()
        for f in (copy.copy,copy.deepcopy,pickle.dumps):
            with self.subTest(operation=f.__name__),self.assertRaises(TypeError):f(k)
    def test_representation_has_no_key(self):
        k,b=self.make();self.assertEqual(repr(k),'RetainedSessionKey(state=PARKED_ENCRYPTED)')
    def test_invalid_input_closes_backend(self):
        for value in (b'',b'A'*31,b'A'*33,bytearray(32),'password'):
            b=FakeOSBackend()
            with self.subTest(type=type(value).__name__),self.assertRaises(SessionKeyError):RetainedSessionKey(b,value)
            self.assertTrue(b.closed);self.assertEqual(bytes(b.buffer),bytes(4096))
    def test_initial_failures_do_not_fall_back(self):
        for operation in ('store','guard','protect','readonly'):
            b=FakeOSBackend();b.fail_next=operation
            with self.subTest(operation=operation),self.assertRaises(SessionKeyError):RetainedSessionKey(b,PUBLIC_KEY)
            self.assertTrue(b.closed)
    def test_open_failures_never_yield(self):
        for operation in ('guard','writable','unprotect','readonly','view'):
            k,b=self.make();b.fail_next=operation
            with self.subTest(operation=operation),self.assertRaises(SessionKeyError):
                with k.use():self.fail('yielded after failure')
            self.assertEqual(k.state,'FAILED');self.assertTrue(b.closed);self.assertEqual(bytes(b.buffer),bytes(4096))
    def test_exit_failures_close_and_propagate(self):
        for operation in ('writable','protect','guard','readonly'):
            k,b=self.make()
            with self.subTest(operation=operation),self.assertRaises(SessionKeyError):
                with k.use():b.fail_next=operation
            self.assertEqual(k.state,'FAILED');self.assertTrue(b.closed)
    def test_lost_lock_is_not_tolerated(self):
        k,b=self.make();b.locked=False
        with self.assertRaises(SessionKeyError):
            with k.use():self.fail('unlocked key exposed')
        self.assertTrue(b.closed)
    def test_cleanup_failure_remains_failed(self):
        k,b=self.make()
        def broken():raise OSError('release unavailable')
        b.wipe_release=broken
        with self.assertRaises(OSError):k.close()
        self.assertEqual(k.state,'FAILED')
        with self.assertRaises(SessionKeyError):
            with k.use():pass
    def test_other_thread_close_waits_for_borrower(self):
        k,b=self.make();ready=threading.Event();done=threading.Event()
        def close():ready.set();k.close();done.set()
        with k.use() as view:
            t=threading.Thread(target=close);t.start();self.assertTrue(ready.wait(1));self.assertFalse(done.wait(.03));self.assertEqual(bytes(view),PUBLIC_KEY)
        t.join(2);self.assertFalse(t.is_alive());self.assertTrue(done.is_set());self.assertTrue(b.closed)
    def test_concurrent_borrowers_are_serialized(self):
        k,b=self.make();ready=threading.Event();entered=threading.Event();fail=[]
        def borrower():
            ready.set()
            try:
                with k.use() as view:self.assertEqual(bytes(view),PUBLIC_KEY);entered.set()
            except BaseException as e:fail.append(repr(e))
        with k.use():
            t=threading.Thread(target=borrower);t.start();self.assertTrue(ready.wait(1));self.assertFalse(entered.wait(.03))
        t.join(2);self.assertFalse(t.is_alive());self.assertTrue(entered.is_set());self.assertFalse(fail)
    def test_non_windows_has_no_native_fallback(self):
        with patch('session_key.sys.platform','linux'):
            with self.assertRaises(SessionKeyError):WindowsMemoryBackend()

if __name__=='__main__':unittest.main(verbosity=2)
