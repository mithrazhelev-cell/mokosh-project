import errno
import inspect
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import mokosh_v2_operation_lease as lease_module
from mokosh_v2_operation_lease import (
    HeldOperationLease,
    LeaseProbeStatus,
    OperationLeaseBackend,
    OperationLeaseBusy,
    OperationLeaseError,
    OperationLeaseProbe,
    OperationLeaseUnsupported,
    acquire_writer_operation_lease,
    probe_operation_lease,
)


class RealPosixLeaseTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix":
            self.skipTest("POSIX flock integration test")
        self._temporary = tempfile.TemporaryDirectory()
        self.path = Path(self._temporary.name) / "journal"
        self.path.write_bytes(b"journal")
        os.chmod(self.path, 0o600)

    def tearDown(self):
        self._temporary.cleanup()

    def open_descriptor(self):
        return os.open(self.path, os.O_RDWR)

    def test_writer_holds_exclusive_lease_until_handle_close(self):
        writer = acquire_writer_operation_lease(self.open_descriptor())
        self.assertEqual(writer.backend, OperationLeaseBackend.POSIX_FLOCK)
        probe = probe_operation_lease(self.open_descriptor())
        self.assertEqual(probe.status, LeaseProbeStatus.HELD_BY_OTHER)
        self.assertIsNone(probe.lease)
        self.assertFalse(probe.mutation_permitted)
        writer.close()
        released = probe_operation_lease(self.open_descriptor())
        self.assertEqual(released.status, LeaseProbeStatus.ACQUIRED)
        self.assertIsNotNone(released.lease)
        released.lease.close()

    def test_lease_close_is_idempotent_and_descriptor_is_invalidated(self):
        lease = acquire_writer_operation_lease(self.open_descriptor())
        descriptor = lease.fileno()
        lease.close()
        lease.close()
        self.assertTrue(lease.closed)
        with self.assertRaises(OperationLeaseError):
            lease.fileno()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_context_manager_releases_lease(self):
        with acquire_writer_operation_lease(self.open_descriptor()) as lease:
            self.assertFalse(lease.closed)
            busy = probe_operation_lease(self.open_descriptor())
            self.assertEqual(busy.status, LeaseProbeStatus.HELD_BY_OTHER)
        acquired = probe_operation_lease(self.open_descriptor())
        self.assertEqual(acquired.status, LeaseProbeStatus.ACQUIRED)
        acquired.lease.close()

    def test_process_exit_releases_kernel_lease(self):
        script = """
import os, sys
from mokosh_v2_operation_lease import acquire_writer_operation_lease
fd = os.open(sys.argv[1], os.O_RDWR)
acquire_writer_operation_lease(fd)
os._exit(0)
"""
        subprocess.run(
            [sys.executable, "-c", script, str(self.path)],
            cwd=Path(__file__).resolve().parents[1],
            check=True,
            timeout=10,
        )
        result = probe_operation_lease(self.open_descriptor())
        self.assertEqual(result.status, LeaseProbeStatus.ACQUIRED)
        result.lease.close()

    def test_competing_process_is_observed_as_active(self):
        script = """
import os, sys
from mokosh_v2_operation_lease import acquire_writer_operation_lease
fd = os.open(sys.argv[1], os.O_RDWR)
lease = acquire_writer_operation_lease(fd)
print('READY', flush=True)
sys.stdin.readline()
lease.close()
"""
        process = subprocess.Popen(
            [sys.executable, "-c", script, str(self.path)],
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(process.stdout.readline().strip(), "READY")
            result = probe_operation_lease(self.open_descriptor())
            self.assertEqual(result.status, LeaseProbeStatus.HELD_BY_OTHER)
            process.stdin.write("release\n")
            process.stdin.flush()
            self.assertEqual(process.wait(timeout=10), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()


class LeaseErrorPolicyTests(unittest.TestCase):
    def descriptor(self):
        descriptor, path = tempfile.mkstemp()
        os.write(descriptor, b"x")
        os.unlink(path)
        return descriptor

    def assert_consumed(self, descriptor):
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_invalid_descriptors_are_rejected_without_boolean_confusion(self):
        for value in (-1, True, 1.5, "3", None):
            with self.subTest(value=value):
                with self.assertRaises(OperationLeaseError):
                    probe_operation_lease(value)

    def test_unsupported_backend_consumes_descriptor_and_fails_closed(self):
        descriptor = self.descriptor()
        with patch.object(
            lease_module,
            "_load_backend",
            side_effect=OperationLeaseUnsupported("forced"),
        ):
            result = probe_operation_lease(descriptor)
        self.assertEqual(result.status, LeaseProbeStatus.UNSUPPORTED)
        self.assertIsNone(result.backend)
        self.assert_consumed(descriptor)

    def test_busy_unsupported_and_other_os_errors_are_distinct(self):
        class Backend:
            name = OperationLeaseBackend.POSIX_FLOCK

            def __init__(self, error):
                self.error = error

            def acquire(self, descriptor):
                raise self.error

        cases = (
            (OSError(errno.EAGAIN, "busy"), LeaseProbeStatus.HELD_BY_OTHER),
            (OSError(errno.ENOLCK, "unsupported"), LeaseProbeStatus.UNSUPPORTED),
            (OSError(errno.EIO, "error"), LeaseProbeStatus.ERROR),
        )
        for error, expected in cases:
            with self.subTest(expected=expected):
                descriptor = self.descriptor()
                with patch.object(
                    lease_module,
                    "_load_backend",
                    return_value=Backend(error),
                ):
                    result = probe_operation_lease(descriptor)
                self.assertEqual(result.status, expected)
                self.assert_consumed(descriptor)

    def test_unexpected_backend_exception_is_error_and_consumes_descriptor(self):
        class Backend:
            name = OperationLeaseBackend.POSIX_FLOCK

            def acquire(self, descriptor):
                raise RuntimeError("forced")

        descriptor = self.descriptor()
        with patch.object(lease_module, "_load_backend", return_value=Backend()):
            result = probe_operation_lease(descriptor)
        self.assertEqual(result.status, LeaseProbeStatus.ERROR)
        self.assert_consumed(descriptor)

    def test_writer_maps_probe_outcomes_to_strict_errors(self):
        cases = (
            (LeaseProbeStatus.HELD_BY_OTHER, OperationLeaseBusy),
            (LeaseProbeStatus.UNSUPPORTED, OperationLeaseUnsupported),
            (LeaseProbeStatus.ERROR, OperationLeaseError),
        )
        for status, exception in cases:
            with self.subTest(status=status):
                descriptor = self.descriptor()
                probe = OperationLeaseProbe(
                    status,
                    OperationLeaseBackend.POSIX_FLOCK,
                    None,
                )
                with patch.object(
                    lease_module,
                    "probe_operation_lease",
                    return_value=probe,
                ):
                    with self.assertRaises(exception):
                        acquire_writer_operation_lease(descriptor)
                os.close(descriptor)

    def test_probe_result_invariants_reject_mutation_or_missing_handle(self):
        with self.assertRaises(OperationLeaseError):
            OperationLeaseProbe(
                LeaseProbeStatus.ACQUIRED,
                OperationLeaseBackend.POSIX_FLOCK,
                None,
            )
        with self.assertRaises(OperationLeaseError):
            OperationLeaseProbe(
                LeaseProbeStatus.ERROR,
                None,
                None,
                mutation_permitted=True,
            )


class BackendContractTests(unittest.TestCase):
    def test_windows_backend_locks_one_byte_from_offset_zero(self):
        calls = []

        class FakeMsvcrt:
            LK_NBLCK = 7

            @staticmethod
            def locking(descriptor, mode, count):
                calls.append((descriptor, mode, count, os.lseek(descriptor, 0, os.SEEK_CUR)))

        descriptor, path = tempfile.mkstemp()
        try:
            os.write(descriptor, b"journal")
            os.lseek(descriptor, 4, os.SEEK_SET)
            backend = lease_module._WindowsMsvcrtBackend(FakeMsvcrt)
            backend.acquire(descriptor)
            self.assertEqual(calls, [(descriptor, 7, 1, 0)])
        finally:
            os.close(descriptor)
            os.unlink(path)

    def test_posix_backend_uses_exclusive_nonblocking_flags(self):
        calls = []

        class FakeFcntl:
            LOCK_EX = 2
            LOCK_NB = 4

            @staticmethod
            def flock(descriptor, flags):
                calls.append((descriptor, flags))

        backend = lease_module._PosixFlockBackend(FakeFcntl)
        backend.acquire(9)
        self.assertEqual(calls, [(9, 6)])

    def test_unknown_platform_is_explicitly_unsupported(self):
        with patch.object(lease_module.os, "name", "unknown"):
            with self.assertRaises(OperationLeaseUnsupported):
                lease_module._load_backend()

    def test_module_has_no_paths_content_crypto_network_gui_or_cleanup(self):
        source = inspect.getsource(lease_module)
        for forbidden in (
            "pathlib",
            "journal_name",
            "temporary_name",
            "password",
            "private_key",
            "AESGCM",
            "socket",
            "requests",
            "tkinter",
            "os.unlink",
            "os.remove",
            "os.rename",
            "os.replace",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
