"""Bounded observations of owned synthetic files, never product acceptance.

Product imports occur only inside run_probes, after the worker binds its copy.
There is no command line, environment override, user path, or application run.
"""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile

PAYLOAD = b'MOKOSH native prerequisite payload\n'
COLLISION = b'MOKOSH existing collision sentinel\n'
SIBLING = b'MOKOSH sibling sentinel\n'
IDENTITY_FIELDS = ('device', 'inode', 'mode', 'size', 'mtime_ns', 'ctime_ns', 'uid', 'gid')
PROBE_IDS = ('file_identity_path_fd', 'permission_semantics',
    'file_and_directory_fsync', 'filesystem_capabilities', 'explicit_product_linux_gates')


def _require(condition, detail):
    if not condition:
        raise ValueError(detail)


def _stat(value):
    return {'device': value.st_dev, 'inode': value.st_ino, 'st_mode': value.st_mode,
        'mode': stat.S_IMODE(value.st_mode), 'size': value.st_size,
        'mtime_ns': value.st_mtime_ns, 'ctime_ns': value.st_ctime_ns,
        'uid': getattr(value, 'st_uid', 0), 'gid': getattr(value, 'st_gid', 0),
        'uid_present': hasattr(value, 'st_uid'), 'gid_present': hasattr(value, 'st_gid'),
        'birthtime_ns': getattr(value, 'st_birthtime_ns', None), 'links': value.st_nlink}


def _create(path, payload):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, 'O_BINARY', 0), 0o600)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            _require(type(written) is int and 0 < written <= len(payload) - offset,
                'Owned fixture write made invalid progress')
            offset += written
    finally:
        os.close(descriptor)


def _integrity(root, identities=None):
    expected = {'payload.bin': PAYLOAD, 'collision.bin': COLLISION, 'sibling.bin': SIBLING}
    result = {}
    for name, payload in expected.items():
        path = root / name
        before = path.lstat()
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
            'Owned fixture is no longer a single regular file')
        if identities is not None:
            observed, original = _stat(before), identities[name]
            fields = set(original) - ({'mode', 'st_mode', 'ctime_ns'}
                if name == 'payload.bin' else set())
            _require(all(observed[key] == original[key] for key in fields),
                'Owned fixture or sentinel was replaced between observations')
        with path.open('rb') as stream:
            opened = os.fstat(stream.fileno())
            _require((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
                'Owned fixture identity changed')
            raw = stream.read(len(payload) + 1)
            after = os.fstat(stream.fileno())
            current = path.lstat()
            _require(_stat(before) == _stat(current) and _stat(opened) == _stat(after),
                'Owned fixture changed while verifying its bytes')
        _require(raw == payload, 'Owned fixture payload or sentinel changed')
        result[name.split('.')[0] + '_sha256'] = hashlib.sha256(raw).hexdigest()
    return result


def _identity_probe(root, filesystem):
    path = root / 'payload.bin'
    before = path.lstat()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    try:
        opened = os.fstat(descriptor)
        _require(stat.S_ISREG(opened.st_mode), 'Identity fixture must be regular')
        _require(os.read(descriptor, len(PAYLOAD) + 1) == PAYLOAD,
            'Read-only descriptor returned different payload')
        after = os.fstat(descriptor)
        current = path.lstat()
    finally:
        os.close(descriptor)
    records = tuple(_stat(item) for item in (before, opened, after, current))
    _require(records[0] == records[3] and records[1] == records[2],
        'Same-API identity changed on an owned stable source')
    path_identity = filesystem.FileIdentity.from_stat(before)
    fd_identity = filesystem.FileIdentity.from_stat(opened)
    deltas = [name for name in IDENTITY_FIELDS
        if getattr(path_identity, name) != getattr(fd_identity, name)]
    source = None
    outcome, exception, count = 'READ_AND_VERIFIED', None, 0
    try:
        source = filesystem.VerifiedFileSource(path, max_read_size=len(PAYLOAD))
        raw = source.read(len(PAYLOAD))
        _require(raw == PAYLOAD and source.read(1) == b'', 'Product source payload differs')
        source.verify_and_close()
        count = len(raw)
    except filesystem.SourceChangedError:
        _require(source is None, 'Product source changed after its constructor returned')
        outcome, exception = 'CONSTRUCTOR_IDENTITY_REFUSAL', 'SourceChangedError'
    finally:
        if source is not None and not source.closed:
            source.close()
    return {'path_before': records[0], 'fd_before': records[1], 'fd_after': records[2],
        'path_after': records[3], 'same_api_path_unchanged': True,
        'same_api_fd_unchanged': True, 'cross_api_identity_deltas': deltas,
        'evidence_scope': 'INDEPENDENT_CALL_NOT_INTERNAL_STAT_TRACE',
        'verified_source_outcome': outcome, 'verified_source_exception': exception,
        'bytes_read': count}, []


def _permission_probe(root):
    path = root / 'payload.bin'
    before, directory_before = _stat(path.lstat()), _stat(root.lstat())
    os.chmod(path, 0o600)
    os.chmod(root, 0o700)
    available = hasattr(os, 'fchmod')
    if available:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
        try:
            _require(stat.S_ISREG(os.fstat(descriptor).st_mode), 'Permission fixture must be regular')
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    after, directory_after = _stat(path.lstat()), _stat(root.lstat())
    preserved = ('device', 'inode', 'size', 'mtime_ns', 'uid', 'gid', 'uid_present',
        'gid_present', 'birthtime_ns', 'links')
    for left, right in ((before, after), (directory_before, directory_after)):
        _require(all(left[name] == right[name] for name in preserved),
            'Permission observation changed unrelated fixture identity')
    return {'file_before': before, 'file_after': after, 'directory_before': directory_before,
        'directory_after': directory_after, 'chmod_file_returned': True,
        'chmod_directory_returned': True, 'fchmod_available': available,
        'fchmod_returned': True if available else None,
        'permission_model': 'WINDOWS_READONLY_FLAG_ONLY_NO_ACL_ACCEPTANCE' if os.name == 'nt'
            else 'POSIX_MODE_OBSERVATION_ONLY'}, []


def _os_error(operation, error, target):
    """Only explicit unsupported native outcomes; never stringify an OS path."""
    unsupported = {errno.EINVAL, getattr(errno, 'ENOTSUP', errno.EINVAL),
        getattr(errno, 'EOPNOTSUPP', errno.EINVAL)}
    winerror = getattr(error, 'winerror', None)
    windows = target == 'windows-x64'
    if type(error.errno) is not int or (winerror is not None and type(winerror) is not int):
        raise error
    if operation == 'open_directory':
        allowed = windows and ((type(error) is PermissionError and error.errno == errno.EACCES)
            or (type(error) is IsADirectoryError and error.errno == errno.EISDIR)) \
            and winerror in (None, 5)
    else:
        codes = unsupported | ({errno.EBADF} if operation == 'fsync_directory' else set())
        allowed = operation in ('fsync_file', 'fsync_directory') and type(error) is OSError \
            and type(error.errno) is int and error.errno in codes \
            and winerror in ((None, 1, 6, 50) if windows else (None,))
    if not allowed:
        raise error
    return {'operation': operation, 'exception': type(error).__name__, 'errno': error.errno,
        'winerror': winerror, 'expected': True}


def _fsync_probe(root, target):
    errors = []
    descriptor = os.open(root / 'payload.bin', os.O_RDWR | getattr(os, 'O_BINARY', 0))
    try:
        _require(stat.S_ISREG(os.fstat(descriptor).st_mode), 'fsync file descriptor must be regular')
        file_result = 'RETURNED'
        try:
            os.fsync(descriptor)
        except OSError as error:
            errors.append(_os_error('fsync_file', error, target))
            file_result = 'OS_ERROR'
    finally:
        os.close(descriptor)
    directory_open, directory_result, verified = 'OPENED', 'NOT_ATTEMPTED', False
    try:
        directory = os.open(root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0)
            | getattr(os, 'O_CLOEXEC', 0))
    except OSError as error:
        errors.append(_os_error('open_directory', error, target))
        directory_open = 'OS_ERROR'
    else:
        try:
            _require(stat.S_ISDIR(os.fstat(directory).st_mode), 'fsync descriptor must be a held directory')
            verified = True
            directory_result = 'RETURNED'
            try:
                os.fsync(directory)
            except OSError as error:
                errors.append(_os_error('fsync_directory', error, target))
                directory_result = 'OS_ERROR'
        finally:
            os.close(directory)
    return {'file_result': file_result, 'directory_open_result': directory_open,
        'directory_fsync_result': directory_result, 'file_descriptor_regular': True,
        'directory_descriptor_verified': verified, 'crash_durability': 'NOT_TESTED'}, errors


def _capabilities_probe():
    return {'declared_dir_fd': {name: getattr(os, name) in os.supports_dir_fd
            for name in ('open', 'stat', 'unlink', 'link')},
        'declared_follow_symlinks': {name: getattr(os, name) in os.supports_follow_symlinks
            for name in ('stat', 'link')},
        'declared_fd': {'listdir': os.listdir in os.supports_fd},
        'flags': {name: bool(getattr(os, name, 0))
            for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC')},
        'fchmod_available': hasattr(os, 'fchmod'), 'getuid_available': hasattr(os, 'getuid'),
        'getgid_available': hasattr(os, 'getgid'),
        'capability_scope': 'DECLARED_API_MEMBERSHIP_NOT_NATIVE_GUARANTEE',
        'tested_operations': []}, []


def _tree_signature(root):
    result = {}
    for path in (root, *sorted(root.rglob('*'))):
        value = path.lstat()
        _require(not stat.S_ISLNK(value.st_mode), 'Unexpected symlink in owned gate tree')
        key = path.relative_to(root).as_posix()
        result[key] = {'stat': _stat(value),
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None}
    return result


def _gates_probe(root, profile, phrase, local):
    legacy = root / 'empty_legacy'
    legacy.mkdir(mode=0o700)
    absent = root / 'absent_profile'
    before = _tree_signature(root)
    linux = os.name == 'posix' and sys.platform == 'linux'
    try:
        profile.require_supported_platform()
    except profile.ProfileUnsupportedPlatformError as error:
        _require(not linux and str(error) == 'the Stage 2.46 protected-profile backend is unavailable',
            'Unexpected profile platform refusal')
        require_result = 'EXPECTED_UNSUPPORTED'
    else:
        _require(linux, 'Profile platform gate returned on an unsupported platform')
        require_result = 'RETURNED'
    inspection = profile.inspect_profile(root=absent, legacy_directory=legacy)
    expected_state = profile.ProfileState.ABSENT if linux else profile.ProfileState.UNSUPPORTED
    _require(inspection.state is expected_state and inspection.reason == ('' if linux else 'platform')
        and inspection.legacy_login_records_present is False, 'Unexpected explicit private profile inspection')
    try:
        profile.create_profile(nickname='', password='public synthetic probe text', root=absent)
    except profile.ProfileValidationError as error:
        _require(linux and str(error) == 'nickname length is outside policy', 'Unexpected validation refusal')
        create_result = 'EXPECTED_VALIDATION_REFUSAL'
    except profile.ProfileUnsupportedPlatformError as error:
        _require(not linux and str(error) == 'the Stage 2.46 protected-profile backend is unavailable',
            'Unexpected profile creation gate refusal')
        create_result = 'EXPECTED_UNSUPPORTED'
    else:
        raise ValueError('Invalid nickname did not stop before profile creation')
    if linux:
        descriptor = os.open(root, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            _require(stat.S_ISDIR(os.fstat(descriptor).st_mode), 'Filesystem magic requires an owned directory')
            magic = phrase._filesystem_magic(descriptor)
            _require(type(magic) is int, 'Linux filesystem magic must be an integer')
        finally:
            os.close(descriptor)
        magic_result = {'result': 'LINUX_MAGIC', 'value': magic}
    else:
        try:
            phrase._filesystem_magic(-1)
        except phrase.RecoveryPhraseExportUnsupportedError as error:
            _require(str(error) == 'recovery phrase storage requires Linux filesystem checks',
                'Unexpected non-Linux filesystem refusal')
        else:
            raise ValueError('Filesystem platform gate did not refuse before descriptor use')
        magic_result = {'result': 'EXPECTED_UNSUPPORTED', 'value': None}
    try:
        local._require_linux()
    except local._LocalRefusal as error:
        _require(not linux and error.code is local.LocalV2ErrorCode.UNSUPPORTED_PLATFORM,
            'Unexpected local V2 gate refusal')
        local_result = 'EXPECTED_UNSUPPORTED'
    else:
        _require(linux, 'Local V2 gate returned on an unsupported platform')
        local_result = 'RETURNED'
    _require(not absent.exists() and list(legacy.iterdir()) == [] and before == _tree_signature(root),
        'Profile gate observations changed the private tree')
    return {'profile_require': require_result,
        'profile_inspect': {'state': inspection.state.name, 'reason': inspection.reason,
            'legacy_login_records_present': inspection.legacy_login_records_present},
        'profile_create_invalid_nickname': create_result, 'phrase_filesystem_magic': magic_result,
        'local_v2_gate': local_result, 'private_tree_unchanged': True}, []


def run_probes(data_root: Path, *, target: str) -> list[dict]:
    systems = {'linux-x64': ('linux', 'posix'), 'windows-x64': ('win32', 'nt'),
        'macos-arm64': ('darwin', 'posix')}
    _require(type(target) is str and target in systems
        and systems[target] == (sys.platform, os.name), 'Actual probe platform differs from target')
    root = Path(data_root)
    _require(root.is_absolute() and root.parent.resolve(strict=True) == root.parent
        and not root.exists() and not root.is_symlink(), 'A fresh canonical owned probe leaf is required')
    # These imports are intentionally delayed until the owning worker has bound
    # its immutable project copy and qualified its interpreter/package runtime.
    import mokosh_v2_filesystem as filesystem
    import mokosh_profile_storage as profile
    import mokosh_recovery_phrase_storage as phrase
    import mokosh_v2_local_service as local

    root.mkdir(mode=0o700)
    rows = []
    try:
        with tempfile.TemporaryDirectory(prefix='owned-native-', dir=root) as directory:
            owned = Path(directory).resolve(strict=True)
            _require(owned.parent == root, 'Owned probe directory escaped its allocated leaf')
            for name, payload in (('payload.bin', PAYLOAD), ('collision.bin', COLLISION), ('sibling.bin', SIBLING)):
                _create(owned / name, payload)
            identities = {name: _stat((owned / name).lstat())
                for name in ('payload.bin', 'collision.bin', 'sibling.bin')}
            operations = (lambda: _identity_probe(owned, filesystem), lambda: _permission_probe(owned),
                lambda: _fsync_probe(owned, target), _capabilities_probe,
                lambda: _gates_probe(owned, profile, phrase, local))
            for probe_id, operation in zip(PROBE_IDS, operations):
                _integrity(owned, identities)
                observations, errors = operation()
                observations['integrity'] = _integrity(owned, identities)
                rows.append({'id': probe_id, 'execution': 'COMPLETE_OBSERVATION',
                    'observations': observations, 'os_errors': errors, 'product_support': 'NOT_ACCEPTED'})
        _require(not owned.exists(), 'Owned native temporary directory remains')
    finally:
        root.rmdir()  # Only our known empty leaf; failure cannot yield observations.
    for row in rows:
        row['observations']['integrity']['owned_temporary_removed'] = True
    return rows
