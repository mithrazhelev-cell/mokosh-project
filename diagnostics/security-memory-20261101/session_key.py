"""ISOLATED LABORATORY retained-key policy. Never imports MOKOSH.

Windows API use is a candidate, not native-qualified yet. CryptProtectMemory
is not authentication, persistence, a hostile-process sandbox or protection
from code running inside this process. Caller must authenticate its catalog.
"""
from contextlib import contextmanager
import ctypes
import importlib.util
from pathlib import Path
import sys
import threading


class SessionKeyError(RuntimeError):pass


class RetainedSessionKey:
    """Policy with explicit backend injection for isolated experiments only."""
    def __init__(self, backend, key):
        self._backend=backend;self._guard=threading.RLock();self._state='INITIALIZING'
        try:
            if type(key) is not bytes or len(key)!=32:raise SessionKeyError('exact32-byte input required')
            backend.store(key)
            backend.assert_locked()
            backend.protect()
            backend.assert_locked()
            backend.readonly()
            self._state='PARKED_ENCRYPTED'
        except BaseException:
            self._fail();raise

    @property
    def state(self):return self._state

    def _fail(self):
        self._state='FAILED'
        self._backend.wipe_release()

    @contextmanager
    def use(self):
        with self._guard:
            if self._state!='PARKED_ENCRYPTED':raise SessionKeyError('key closed, failed or already active')
            view=None
            try:
                self._state='OPENING'
                self._backend.assert_locked()
                self._backend.writable()
                self._backend.unprotect()
                self._backend.assert_locked()
                self._backend.readonly()
                view=self._backend.view()
                self._state='ACTIVE_READONLY'
            except BaseException:
                self._fail();raise
            try:
                yield view
            finally:
                try:
                    if view is not None:view.release()
                    self._state='SEALING'
                    self._backend.writable()
                    self._backend.protect()
                    self._backend.assert_locked()
                    self._backend.readonly()
                    self._state='PARKED_ENCRYPTED'
                except BaseException:
                    self._fail();raise

    def close(self):
        with self._guard:
            if self._state=='ACTIVE_READONLY':raise SessionKeyError('cannot close an active borrowed view')
            if self._state in ('CLOSED','FAILED'):return
            self._state='CLOSING'
            try:self._backend.wipe_release()
            except BaseException:self._state='FAILED';raise
            self._state='CLOSED'

    def __repr__(self):return 'RetainedSessionKey(state='+self._state+')'
    def __copy__(self):raise TypeError('session key cannot be copied')
    def __deepcopy__(self,memo):raise TypeError('session key cannot be copied')
    def __reduce__(self):raise TypeError('session key cannot be pickled')


class WindowsMemoryBackend:
    """Dedicated page, process-local DPAPI, no runtime/library fallback."""
    SAME_PROCESS=0
    def __init__(self,case='session_key'):
        if sys.platform!='win32':raise SessionKeyError('native Windows backend unavailable; no fallback')
        spec=importlib.util.spec_from_file_location('session_memory_page',Path(__file__).with_name('probe.py'))
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        self._page=module.Page(case=case);self._crypto=None
        try:
            self._crypto=ctypes.WinDLL('crypt32',use_last_error=True,winmode=0x00000800) # SYSTEM32 only
            for name in ('CryptProtectMemory','CryptUnprotectMemory'):
                f=getattr(self._crypto,name);f.argtypes=[ctypes.c_void_p,ctypes.c_ulong,ctypes.c_ulong];f.restype=ctypes.c_int
            if self._page.size%16:raise SessionKeyError('whole allocation must be16-byte aligned in length')
        except BaseException:
            self._page.close();raise

    def store(self,key):
        self.assert_locked()
        ctypes.memset(self._page.address,0,self._page.size)
        ctypes.memmove(self._page.address,key,32)
        if ctypes.string_at(self._page.address,32)!=key:raise SessionKeyError('initial readback')

    def assert_locked(self):
        s=self._page.snapshot('session_lock_guard')
        if s['valid'] is not True or s['locked'] is not True:raise SessionKeyError('page lock not observed')

    def _crypt(self,name):
        ctypes.set_last_error(0)
        ok=getattr(self._crypto,name)(self._page.address,self._page.size,self.SAME_PROCESS)
        error=ctypes.get_last_error() if not ok else 0
        # All values below are non-secret protocol metadata.
        print(__import__('json').dumps(dict(event='MEMORY_CRYPT',mode=self._page.case,operation=name,
            scope='SAME_PROCESS',bytes=self._page.size,succeeded=bool(ok),win32_error=error)),flush=True)
        if not ok:raise SessionKeyError(name+' failed:'+str(error))

    def protect(self):self._crypt('CryptProtectMemory')
    def unprotect(self):self._crypt('CryptUnprotectMemory')
    def writable(self):self._page.protect('rw')
    def readonly(self):self._page.protect('ro')
    def view(self):
        array=(ctypes.c_ubyte*32).from_address(self._page.address)
        return memoryview(array).cast('B').toreadonly()
    def wipe_release(self):self._page.close()
