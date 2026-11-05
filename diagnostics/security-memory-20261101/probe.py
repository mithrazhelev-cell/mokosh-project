"""Own-process memory API prerequisite; never imports or starts MOKOSH.

Only public synthetic bytes. Some child processes deliberately fault after
READY. Parent records exact termination, bounds time, and reaps only its child.
This does NOT implement a product sandbox, a secret store or kernel protection.
"""
import argparse
import ctypes
import datetime
import hashlib
import json
import mmap
import os
from pathlib import Path
import platform
import subprocess
import sys
import time

VALUE = b'MOKOSH-SYNTHETIC-MEMORY-ONLY-00001'
MODES = ('roundtrip', 'readonly_write', 'noaccess_read',
         'control_write', 'control_read', 'timeout')
TRACE_EVENTS = {'API_CALL', 'PAGE_STATE', 'MEMORY_ZEROED', 'CLEANUP_ERROR'}


class NativeCallError(OSError):
    def __init__(self, operation, phase, code):
        self.operation, self.phase, self.win32_code = operation, phase, code
        super().__init__(code, operation + ' failed at ' + phase)


def decode_working_set(flags):
    """Windows PSAPI_WORKING_SET_EX_BLOCK; invalid entries have no Locked bit."""
    if type(flags) is not int or flags < 0:
        raise ValueError('invalid working-set flags')
    valid = bool(flags & 1)
    return {'valid': valid, 'locked': bool(flags & (1 << 22)) if valid else None,
            'protection': (flags >> 4) & 0x7ff if valid else None}


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields), sort_keys=True), flush=True)


class Page:
    """One dedicated anonymous page; never alter a Python heap page."""
    def __init__(self, case=None):
        self.case = case
        self.size = mmap.PAGESIZE
        self.address = None
        self.locked = False
        self.windows = sys.platform == 'win32'
        if self.windows:
            self.api = ctypes.WinDLL('kernel32', use_last_error=True)
            specs = {
                'VirtualAlloc': ([ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.c_ulong], ctypes.c_void_p),
                'VirtualFree': ([ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong], ctypes.c_int),
                'VirtualLock': ([ctypes.c_void_p, ctypes.c_size_t], ctypes.c_int),
                'VirtualUnlock': ([ctypes.c_void_p, ctypes.c_size_t], ctypes.c_int),
                'VirtualProtect': ([ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)], ctypes.c_int),
                'GetCurrentProcess': ([], ctypes.c_void_p),
                'K32QueryWorkingSetEx': ([ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong], ctypes.c_int),
            }
            for name, (args, result) in specs.items():
                getattr(self.api, name).argtypes = args
                getattr(self.api, name).restype = result
            self.address = self._win_call('VirtualAlloc', None, self.size, 0x3000, 4, phase='allocate')
        else:
            if sys.platform not in ('linux', 'darwin'):
                raise RuntimeError('unsupported platform; no fallback')
            self.api = ctypes.CDLL(None, use_errno=True)
            self.mapping = mmap.mmap(-1, self.size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                                     prot=mmap.PROT_READ | mmap.PROT_WRITE)
            self.address = ctypes.addressof(ctypes.c_char.from_buffer(self.mapping))
            for name in ('mlock', 'munlock'):
                getattr(self.api, name).argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                getattr(self.api, name).restype = ctypes.c_int
            self.api.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
            self.api.mprotect.restype = ctypes.c_int
        try:
            if self.windows:
                self._win_call('VirtualLock', self.address, self.size, phase='initial_lock')
            elif self.api.mlock(self.address, self.size) != 0:
                raise OSError('page locking unavailable')
            self.locked = True
            ctypes.memmove(self.address, VALUE, len(VALUE))
            if ctypes.string_at(self.address, len(VALUE)) != VALUE:
                raise RuntimeError('initial readback mismatch')
            self.snapshot('initial_readback')
        except BaseException:
            self.close()
            raise

    def _win_call(self, operation, *args, phase):
        # Capture before emit, formatting, snapshot, cleanup or any subsequent API.
        ctypes.set_last_error(0)
        result = getattr(self.api, operation)(*args)
        code = ctypes.get_last_error() if not result else 0
        emit('API_CALL', mode=self.case, operation=operation, phase=phase,
             succeeded=bool(result), win32_error=code)
        if not result:
            raise NativeCallError(operation, phase, code)
        return result

    def snapshot(self, phase):
        if not self.windows:
            return
        class WorkingSetInformation(ctypes.Structure):
            _fields_ = [('VirtualAddress', ctypes.c_void_p), ('VirtualAttributes', ctypes.c_size_t)]
        entry = WorkingSetInformation(self.address, 0)
        process = self.api.GetCurrentProcess()
        self._win_call('K32QueryWorkingSetEx', process, ctypes.byref(entry), ctypes.sizeof(entry),
                       phase='query:' + phase)
        state = decode_working_set(entry.VirtualAttributes)
        emit('PAGE_STATE', mode=self.case, phase=phase, **state)
        return state

    def protect(self, mode):
        if mode not in ('rw', 'ro', 'none'):
            raise ValueError('invalid protection')
        if self.windows:
            self.snapshot('before_protect:' + mode)
            old = ctypes.c_ulong()
            self._win_call('VirtualProtect', self.address, self.size,
                           {'rw': 4, 'ro': 2, 'none': 1}[mode], ctypes.byref(old), phase='protect:' + mode)
            self.snapshot('after_protect:' + mode)
        elif self.api.mprotect(self.address, self.size, {'rw': 3, 'ro': 1, 'none': 0}[mode]) != 0:
            raise OSError(ctypes.get_errno(), 'mprotect failed')

    def close(self):
        if self.address is None:
            return
        try:
            self.protect('rw')
            ctypes.memset(self.address, 0, self.size)
            if ctypes.string_at(self.address, self.size) != bytes(self.size):
                raise RuntimeError('own-page zero readback failed')
            if self.windows:
                emit('MEMORY_ZEROED', mode=self.case, bytes=self.size, readback_bytes=self.size)
            if self.locked:
                if self.windows:
                    self.snapshot('before_unlock')
                    self._win_call('VirtualUnlock', self.address, self.size, phase='cleanup_unlock')
                    self.snapshot('after_unlock')
                elif self.api.munlock(self.address, self.size) != 0:
                    raise OSError('page unlock failed')
                self.locked = False
        finally:
            try:
                if self.windows:
                    self._win_call('VirtualFree', self.address, 0, 0x8000, phase='cleanup_free')
                else:
                    self.mapping.close()
            finally:
                self.address = None


def configure_child():
    if sys.platform == 'win32':
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.SetErrorMode.argtypes = [ctypes.c_uint]
        api.SetErrorMode.restype = ctypes.c_uint
        api.SetErrorMode(0x0001 | 0x0002 | 0x8000)
    else:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def child(mode):
    configure_child()
    if mode == 'timeout':
        emit('READY', mode=mode)
        while True:
            time.sleep(1)
    page = Page(case=mode)
    try:
        if mode == 'roundtrip':
            page.protect('ro')
            if ctypes.string_at(page.address, len(VALUE)) != VALUE:
                raise RuntimeError('readonly read mismatch')
            page.protect('none')
            page.protect('rw')
            if ctypes.string_at(page.address, len(VALUE)) != VALUE:
                raise RuntimeError('reopened read mismatch')
            page.close()
            emit('ROUNDTRIP_OK', locked=True, reopened=True, own_page_zeroed=True, released=True)
            return 0
        if mode == 'readonly_write':
            page.protect('ro')
        elif mode == 'noaccess_read':
            page.protect('none')
        emit('READY', mode=mode, lock_api_succeeded=True, initial_readback=True)
        try:
            if mode in ('readonly_write', 'control_write'):
                ctypes.memset(page.address, 0x5A, 1)
                if ctypes.string_at(page.address, 1) != b'Z':
                    raise RuntimeError('control write did not take effect')
            else:
                if ctypes.string_at(page.address, len(VALUE)) != VALUE:
                    raise RuntimeError('control read mismatch')
        except OSError as exc:
            # Windows ctypes may translate SEH access violation into OSError.
            # Any other error is a tool failure, not evidence of protection.
            if sys.platform == 'win32' and 'access violation' in str(exc).lower():
                emit('ACCESS_VIOLATION', mode=mode, origin='ctypes_SEH')
                return 31
            raise
        emit('ACCESS_SUCCEEDED', mode=mode)
        return 0
    finally:
        page.close()


def run_child(mode):
    started = time.monotonic()
    environment = {k: os.environ[k] for k in ('SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'PATH', 'LANG') if k in os.environ}
    command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), '--child', mode]
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment, close_fds=True)
    timed_out = False
    try:
        try:
            stdout, stderr = process.communicate(timeout=5 if mode == 'timeout' else 30)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()  # Only this Popen-owned process. It creates no children.
            stdout, stderr = process.communicate(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    if len(stdout) > 65536 or len(stderr) > 8192:
        raise RuntimeError('unexpected diagnostic output size')
    emitted = [json.loads(line) for line in stdout.decode('utf-8').splitlines()]
    trace = [e for e in emitted if e.get('event') in TRACE_EVENTS]
    events = [e for e in emitted if e.get('event') not in TRACE_EVENTS]
    return {'mode': mode, 'exit': process.returncode, 'timed_out': timed_out,
            'reaped': process.poll() is not None, 'elapsed_seconds': round(time.monotonic() - started, 3),
            'trace': trace,
            'events': events, 'stderr': stderr.decode('utf-8', 'replace')}


def event_seen(result, name):
    return any(e.get('event') == name for e in result.get('events', []))


def denial_observed(result, system):
    ready = any(e.get('event') == 'READY' and e.get('mode') == result['mode'] and e.get('lock_api_succeeded') is True
                and e.get('initial_readback') is True for e in result.get('events', []))
    if not ready or not result['reaped'] or result['timed_out'] or event_seen(result, 'ACCESS_SUCCEEDED'):
        return False
    if system == 'Windows':
        return (result['exit'] & 0xffffffff) == 0xc0000005 or (
            result['exit'] == 31 and event_seen(result, 'ACCESS_VIOLATION'))
    # Target-specific POSIX signal values, including in cross-platform oracle tests.
    return result['exit'] in ((-11, -7) if system == 'Linux' else (-11, -10))


def assess(results, system):
    if system not in ('Linux', 'Darwin', 'Windows'):
        raise ValueError('unsupported system')
    by_mode = {r['mode']: r for r in results}
    if set(by_mode) != set(MODES) or len(results) != len(MODES):
        raise ValueError('missing, duplicate or unexpected case')
    checks = {}
    r = by_mode['roundtrip']
    roundtrip = any(e.get('event') == 'ROUNDTRIP_OK' and all(e.get(k) is True for k in
                    ('locked', 'reopened', 'own_page_zeroed', 'released')) for e in r['events'])
    checks['lock_protect_reopen_zero_release'] = r['exit'] == 0 and r['reaped'] and not r['timed_out'] and roundtrip
    for mode in ('readonly_write', 'noaccess_read'):
        checks[mode + '_denied'] = denial_observed(by_mode[mode], system)
    for mode in ('control_write', 'control_read'):
        r = by_mode[mode]
        checks[mode + '_succeeds'] = r['exit'] == 0 and r['reaped'] and not r['timed_out'] and event_seen(r, 'ACCESS_SUCCEEDED')
        checks[mode + '_cannot_fake_denial'] = not denial_observed(r, system)
    r = by_mode['timeout']
    checks['own_child_deadline_kill_reap'] = r['timed_out'] and r['reaped'] and r['exit'] != 0 and event_seen(r, 'READY')
    return checks


def privilege():
    if sys.platform != 'win32':
        return {'euid': os.geteuid(), 'elevated': os.geteuid() == 0,
                'sudo_capability': 'NOT_TESTED_NO_ESCALATION_ATTEMPT'}
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    token, elevated, size = wintypes.HANDLE(), wintypes.DWORD(), wintypes.DWORD()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.GetTokenInformation(token, 20, ctypes.byref(elevated), ctypes.sizeof(elevated), ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return {'elevated': bool(elevated.value), 'source': 'TokenElevation'}
    finally:
        kernel.CloseHandle(token)


def run(destination):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=False)
    report = {'schema': 1, 'scope': 'OWN_PROCESS_SYNTHETIC_MEMORY_PREREQUISITE_ONLY',
              'status': 'STOP', 'product_backend_implemented': False, 'product_executed': False,
              'product_accepted': False, 'physical_GUI_tested': False,
              'controller_worker_isolation_tested': False, 'compromised_kernel_protected': False,
              'dump_swap_hibernation_exclusion_tested': False,
              'recorded_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'results': []}
    try:
        system = platform.system()
        if system not in ('Linux', 'Darwin', 'Windows'):
            raise RuntimeError('unsupported native platform')
        report['environment'] = {'system': system, 'release': platform.release(),
             'version': platform.version(), 'machine': platform.machine(), 'python': platform.python_version(),
             'page_size': mmap.PAGESIZE, 'privilege': privilege()}
        report['ci'] = {k: os.environ.get(k) for k in ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'ImageOS', 'ImageVersion')}
        for mode in MODES:
            report['results'].append(run_child(mode))
        report['checks'] = assess(report['results'], system)
        report['status'] = 'SCOPED_API_PASS_PRODUCT_NOT_ACCEPTED' if all(report['checks'].values()) else 'FAIL'
    except Exception as exc:
        report['error'] = {'type': type(exc).__name__, 'message': str(exc)[:500]}
    report['probe_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    (destination / 'RESULT.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(json.dumps({'status': report['status'], 'checks': report.get('checks'), 'product_accepted': False}))
    return 0 if report['status'] == 'SCOPED_API_PASS_PRODUCT_NOT_ACCEPTED' else 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--child', choices=MODES, help=argparse.SUPPRESS)
    group.add_argument('--output', help='new empty evidence directory; refuses reuse')
    args = parser.parse_args()
    os.umask(0o077)
    raise SystemExit(child(args.child) if args.child else run(args.output))
