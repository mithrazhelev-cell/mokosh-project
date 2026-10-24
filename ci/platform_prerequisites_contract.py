"""Pinned selected cases and native observations; no product acceptance authority."""
from __future__ import annotations

import hashlib
import errno
import json
import math
from pathlib import Path
import re
import stat

import functional_cohort_contract as runtime_contract
from functional_cohort_contract import strict_json, same_typed, _source_binding
from run_preliminary import read_file, require

CONTRACT_PATH = Path(__file__).with_name('platform_prerequisites.json')
CONTRACT_SHA256 = '696c21bbc20c639947dfc658a0bcfa3d78b3f4bb7dad4f51205d6150fe679a37'
SCOPE = 'PLATFORM_PREREQUISITES_DIAGNOSTICS_AND_SELECTED_UNCHANGED_TESTS_ONLY_NO_PRODUCT_PLATFORM_ACCEPTANCE'
CI_PASS = 'PASS_PLATFORM_PREREQUISITES_OBSERVATIONS'
LAB_PASS = 'PASS_LOCAL_LAB_PLATFORM_PREREQUISITES_OBSERVATIONS'
PROBE_PREFIX = 'MOKOSH_PLATFORM_OBSERVATION='
PROBE_IDS = ('file_identity_path_fd', 'permission_semantics', 'file_and_directory_fsync',
    'filesystem_capabilities', 'explicit_product_linux_gates')
COUNTS = {'linux-x64': 35, 'windows-x64': 21, 'macos-arm64': 35}
MAX_PROBE_ROW_BYTES = 64 * 1024
MAX_PROBE_STDOUT_BYTES = 512 * 1024
MAX_TEST_LOG_BYTES = 20 * 1024 * 1024
PAYLOAD_BYTES = 35
INTEGRITY_HASHES = {
    'payload_sha256': 'e11ee1598502b9e680644b6142a22c9bef7acd89677190520065d58aac628c4a',
    'collision_sha256': 'b5258be67c0432694f71ebb04cd4701153f319d022ba4a061722707995c3e4e9',
    'sibling_sha256': '8e0d0d2c4231b06f7d2aeb264d39e6fb1d462fbcf663c7b9aa2bc1abd43da498'}


def _unique_ids(value, count, message):
    require(type(value) is list and len(value) == count
        and all(type(item) is str and re.fullmatch(r'tests\.test_[a-z0-9_]+\.[A-Za-z0-9_]+\.[A-Za-z0-9_]+', item)
            for item in value) and len(set(value)) == count, message)


def load_contract(path=CONTRACT_PATH):
    raw = read_file(path)
    require(len(raw) <= 256 * 1024 and hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256,
        'Pinned platform prerequisites manifest bytes differ')
    value = strict_json(raw)
    require(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
        and value.get('scope') == SCOPE, 'Platform prerequisites schema/scope differs')
    require(same_typed(value.get('source_snapshot'), {'files': 263, 'bytes': 5223645,
        'canonical_sha256': runtime_contract.SOURCE_SHA256}), 'Platform source binding differs')
    require(same_typed(value.get('expected_counts'), COUNTS)
        and type(value.get('tests_by_target')) is dict
        and set(value['tests_by_target']) == set(COUNTS), 'Platform selected counts differ')
    for target, count in COUNTS.items():
        _unique_ids(value['tests_by_target'][target], count, 'Platform selected IDs differ')
        require(value['tests_by_target'][target] == sorted(value['tests_by_target'][target]),
            'Platform selected IDs are not canonical')
    require(same_typed(value.get('probe_ids'), list(PROBE_IDS))
        and type(value.get('probe_count')) is int and value['probe_count'] == 5
        and value.get('raw_probe_prefix') == PROBE_PREFIX, 'Platform probe inventory differs')
    require(value.get('CI_python') == '3.12.3'
        and same_typed(value.get('dependency_pins'), runtime_contract.DEPENDENCIES),
        'Platform runtime pins differ')
    return value


def _pinned(contract):
    pinned = load_contract()
    require(contract is None or same_typed(contract, pinned), 'Supplied platform contract differs')
    return pinned


def expected_ids(target, contract=None):
    value = _pinned(contract)
    require(type(target) is str and target in COUNTS, 'Unknown platform prerequisites target')
    return value['tests_by_target'][target][:]


def qualify_runtime(target, local_lab=False):
    # The unchanged helper reads its own old manifest solely for the same five
    # pins and platform/runtime boundaries. It never receives this new manifest.
    load_contract()
    return runtime_contract.qualify_runtime(target, local_lab=local_lab)


def _bounded_json(value, depth=0):
    require(depth <= 8, 'Probe observation nesting exceeds bound')
    if type(value) is dict:
        require(len(value) <= 128 and all(type(k) is str and 0 < len(k) <= 128 for k in value),
            'Probe observation object exceeds bound')
        for item in value.values():
            _bounded_json(item, depth + 1)
    elif type(value) is list:
        require(len(value) <= 128, 'Probe observation array exceeds bound')
        for item in value:
            _bounded_json(item, depth + 1)
    elif type(value) is str:
        require(len(value) <= 1024, 'Probe observation text exceeds bound')
    elif type(value) is int:
        require(abs(value) < 2 ** 128, 'Probe observation integer exceeds bound')
    elif type(value) is float:
        require(math.isfinite(value), 'Probe observation number is non-finite')
    else:
        require(value is None or type(value) is bool, 'Probe observation is not JSON data')


IDENTITY_FIELDS = ('device', 'inode', 'mode', 'size', 'mtime_ns', 'ctime_ns', 'uid', 'gid')
STAT_FIELDS = {*IDENTITY_FIELDS, 'st_mode', 'uid_present', 'gid_present', 'birthtime_ns', 'links'}


def _keys(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def _stat_record(value):
    _keys(value, STAT_FIELDS, 'Native stat observation field set differs')
    for name in STAT_FIELDS - {'uid_present', 'gid_present', 'birthtime_ns'}:
        require(type(value[name]) is int and abs(value[name]) < 2 ** 128,
            'Native stat field must be a bounded integer')
    require(all(type(value[k]) is bool for k in ('uid_present', 'gid_present')),
        'Native uid/gid availability must be boolean')
    require(value['birthtime_ns'] is None or type(value['birthtime_ns']) is int
        and abs(value['birthtime_ns']) < 2 ** 128, 'Invalid native birthtime observation')
    require(value['mode'] == stat.S_IMODE(value['st_mode']) and value['links'] >= 1
        and value['size'] >= 0 and value['device'] >= 0 and value['inode'] >= 0,
        'Inconsistent native stat observation')
    require((value['uid_present'] or value['uid'] == 0)
        and (value['gid_present'] or value['gid'] == 0), 'Absent uid/gid observation differs from product identity')


def _integrity(value):
    _keys(value, ('payload_sha256', 'collision_sha256', 'sibling_sha256', 'owned_temporary_removed'),
        'Native probe integrity evidence incomplete')
    require(value['owned_temporary_removed'] is True
        and all(value[k] == expected for k, expected in INTEGRITY_HASHES.items()),
        'Native probe integrity or cleanup failed')


def _os_errors(errors, target):
    require(len(errors) <= 2, 'Too many native fsync errors')
    seen = set()
    allowed = {
        'fsync_file': ({errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}, {'OSError'}),
        'fsync_directory': ({errno.EBADF, errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}, {'OSError'}),
        'open_directory': ({errno.EACCES, errno.EISDIR}, {'PermissionError', 'IsADirectoryError'})}
    for error in errors:
        _keys(error, ('operation', 'exception', 'errno', 'winerror', 'expected'),
            'Native OS-error observation field set differs')
        operation = error['operation']
        require(type(operation) is str and operation in allowed and operation not in seen
            and error['expected'] is True and type(error['errno']) is int,
            'Unexpected or duplicate native OS error')
        seen.add(operation)
        codes, exceptions = allowed[operation]
        require(error['errno'] in codes and type(error['exception']) is str and error['exception'] in exceptions,
            'Native OS error is not in the explicit observation allowlist')
        winerror = error['winerror']
        require(winerror is None or type(winerror) is int, 'Native winerror must be an integer or null')
        if operation == 'open_directory':
            require(target == 'windows-x64' and winerror in (None, 5)
                and ((error['errno'] == errno.EACCES and error['exception'] == 'PermissionError')
                    or (error['errno'] == errno.EISDIR and error['exception'] == 'IsADirectoryError')),
                'Directory-open error is not an expected Windows observation')
        else:
            require(winerror in ((None, 1, 6, 50) if target == 'windows-x64' else (None,)),
                'Native fsync winerror differs from allowlist')
    return seen


def _boolean_mapping(value, keys):
    _keys(value, keys, 'Declared API capability field set differs')
    require(all(type(flag) is bool for flag in value.values()), 'API capability observations must be booleans')


def _observations(row, target):
    name, value, errors = row['id'], row['observations'], row['os_errors']
    require(not errors or name == 'file_and_directory_fsync', 'Unexpected OS error outside fsync observation')
    if name == 'file_identity_path_fd':
        _keys(value, ('path_before', 'fd_before', 'fd_after', 'path_after', 'same_api_path_unchanged',
            'same_api_fd_unchanged', 'cross_api_identity_deltas', 'verified_source_outcome',
            'verified_source_exception', 'bytes_read', 'evidence_scope', 'integrity'),
            'Native identity observation incomplete')
        for key in ('path_before', 'fd_before', 'fd_after', 'path_after'):
            _stat_record(value[key])
            require(stat.S_ISREG(value[key]['st_mode']) and value[key]['size'] == PAYLOAD_BYTES,
                'Native identity source is not the bounded regular fixture')
        require(value['same_api_path_unchanged'] is True and value['same_api_fd_unchanged'] is True
            and same_typed(value['path_before'], value['path_after'])
            and same_typed(value['fd_before'], value['fd_after']), 'Native same-API identity changed')
        delta = [key for key in IDENTITY_FIELDS if value['path_before'][key] != value['fd_before'][key]]
        require(same_typed(value['cross_api_identity_deltas'], delta), 'Native cross-API identity delta is masked or invented')
        # The external lstat/fstat sequence and the product constructor are
        # distinct actual calls. Neither is presented as the other's trace.
        require(value['evidence_scope'] == 'INDEPENDENT_CALL_NOT_INTERNAL_STAT_TRACE'
            and type(value['bytes_read']) is int and ((value['verified_source_outcome'] == 'READ_AND_VERIFIED'
            and value['verified_source_exception'] is None
            and value['bytes_read'] == PAYLOAD_BYTES)
            or (value['verified_source_outcome'] == 'CONSTRUCTOR_IDENTITY_REFUSAL'
                and value['verified_source_exception'] == 'SourceChangedError' and value['bytes_read'] == 0)),
            'Native product source call observation is incomplete or overclaimed')
    elif name == 'permission_semantics':
        _keys(value, ('file_before', 'file_after', 'directory_before', 'directory_after',
            'chmod_file_returned', 'chmod_directory_returned', 'fchmod_available', 'fchmod_returned',
            'permission_model', 'integrity'), 'Native permission observation incomplete')
        for key in ('file_before', 'file_after', 'directory_before', 'directory_after'):
            _stat_record(value[key])
            require((stat.S_ISDIR if key.startswith('directory') else stat.S_ISREG)(value[key]['st_mode']),
                'Native permission object type differs')
        invariant = STAT_FIELDS - {'mode', 'st_mode', 'ctime_ns'}
        for kind in ('file', 'directory'):
            require(all(same_typed(value[kind + '_before'][key], value[kind + '_after'][key])
                for key in invariant), 'Native permission fixture identity/content changed')
        require(value['file_after']['size'] == PAYLOAD_BYTES, 'Native permission payload size changed')
        require(value['chmod_file_returned'] is True and value['chmod_directory_returned'] is True
            and type(value['fchmod_available']) is bool
            and value['fchmod_returned'] is (True if value['fchmod_available'] else None),
            'Native chmod/fchmod did not complete')
        model = ('WINDOWS_READONLY_FLAG_ONLY_NO_ACL_ACCEPTANCE' if target == 'windows-x64'
            else 'POSIX_MODE_OBSERVATION_ONLY')
        require(value['permission_model'] == model, 'Permission observation overclaims platform semantics')
        if target != 'windows-x64':
            require(value['file_after']['mode'] == 0o600 and value['directory_after']['mode'] == 0o700,
                'POSIX private fixture mode differs')
    elif name == 'file_and_directory_fsync':
        _keys(value, ('file_result', 'directory_open_result', 'directory_fsync_result',
            'file_descriptor_regular', 'directory_descriptor_verified', 'crash_durability',
            'integrity'), 'Native fsync observation incomplete')
        seen = _os_errors(errors, target)
        require(value['file_result'] == ('OS_ERROR' if 'fsync_file' in seen else 'RETURNED')
            and value['directory_open_result'] == ('OS_ERROR' if 'open_directory' in seen else 'OPENED')
            and value['directory_fsync_result'] == ('NOT_ATTEMPTED' if 'open_directory' in seen
                else 'OS_ERROR' if 'fsync_directory' in seen else 'RETURNED')
            and not {'open_directory', 'fsync_directory'} <= seen
            and value['file_descriptor_regular'] is True
            and value['directory_descriptor_verified'] is ('open_directory' not in seen)
            and value['crash_durability'] == 'NOT_TESTED', 'Native fsync outcome/error contradiction or durability overclaim')
    elif name == 'filesystem_capabilities':
        _keys(value, ('declared_dir_fd', 'declared_follow_symlinks', 'declared_fd', 'flags',
            'fchmod_available', 'getuid_available', 'getgid_available', 'capability_scope',
            'tested_operations', 'integrity'), 'Native capability observation incomplete')
        _boolean_mapping(value['declared_dir_fd'], ('open', 'stat', 'unlink', 'link'))
        _boolean_mapping(value['declared_follow_symlinks'], ('stat', 'link'))
        _boolean_mapping(value['declared_fd'], ('listdir',))
        _boolean_mapping(value['flags'], ('O_DIRECTORY', 'O_NOFOLLOW', 'O_NONBLOCK', 'O_CLOEXEC'))
        require(all(type(value[k]) is bool for k in ('fchmod_available', 'getuid_available', 'getgid_available'))
            and value['capability_scope'] == 'DECLARED_API_MEMBERSHIP_NOT_NATIVE_GUARANTEE'
            and type(value['tested_operations']) is list and value['tested_operations'] == [],
            'Native capability observation overclaims exercised support')
    else:
        _keys(value, ('profile_require', 'profile_inspect', 'profile_create_invalid_nickname',
            'phrase_filesystem_magic', 'local_v2_gate', 'private_tree_unchanged', 'integrity'),
            'Explicit product-gate observation incomplete')
        linux = target == 'linux-x64'
        require(value['private_tree_unchanged'] is True
            and value['profile_require'] == ('RETURNED' if linux else 'EXPECTED_UNSUPPORTED')
            and value['local_v2_gate'] == ('RETURNED' if linux else 'EXPECTED_UNSUPPORTED')
            and value['profile_create_invalid_nickname'] == ('EXPECTED_VALIDATION_REFUSAL' if linux else 'EXPECTED_UNSUPPORTED')
            and same_typed(value['profile_inspect'], {'state': 'ABSENT' if linux else 'UNSUPPORTED',
                'reason': '' if linux else 'platform', 'legacy_login_records_present': False}),
            'Explicit product Linux gate or private-tree observation differs')
        magic = value['phrase_filesystem_magic']
        _keys(magic, ('result', 'value'), 'Phrase filesystem gate observation incomplete')
        require(magic['result'] == ('LINUX_MAGIC' if linux else 'EXPECTED_UNSUPPORTED')
            and (type(magic['value']) is int if linux else magic['value'] is None),
            'Phrase filesystem gate contradicts actual target')
    _integrity(value['integrity'])


def validate_probe_rows(rows, target):
    require(type(target) is str and target in COUNTS, 'Unknown native probe target')
    require(type(rows) is list and len(rows) == 5, 'Exactly five native probe rows required')
    for expected, row in zip(PROBE_IDS, rows):
        require(type(row) is dict and set(row) == {'id', 'execution', 'observations', 'os_errors', 'product_support'}
            and row['id'] == expected and row['execution'] == 'COMPLETE_OBSERVATION'
            and row['product_support'] == 'NOT_ACCEPTED' and type(row['observations']) is dict
            and type(row['os_errors']) is list, 'Incomplete, duplicate or overclaimed probe row')
        _bounded_json(row)
        require(len(json.dumps(row, allow_nan=False, ensure_ascii=True).encode('ascii')) <= MAX_PROBE_ROW_BYTES,
            'Probe row exceeds bound')
        _observations(row, target)
    return rows


def validate_raw_probe_stdout(raw, rows, target):
    require(type(raw) is bytes and len(raw) <= MAX_PROBE_STDOUT_BYTES and raw.endswith(b'\n'),
        'Raw native probe stdout incomplete or outside bound')
    text = raw.decode('ascii').replace('\r\n', '\n')
    require('\r' not in text, 'Raw probe stdout has invalid line endings')
    lines = text.split('\n')
    require(len(lines) == 6 and lines[-1] == '' and all(line.startswith(PROBE_PREFIX) for line in lines[:-1]),
        'Raw stdout must contain only the exact five probe rows')
    observed = [strict_json(line[len(PROBE_PREFIX):]) for line in lines[:-1]]
    validate_probe_rows(observed, target)
    require(same_typed(observed, rows), 'Raw native probe rows differ from worker receipt')


def validate_raw_test_log(raw, ids):
    # The protected prior parser is deliberately 248-specific; these selected
    # 35/21 cases use their own equally strict variable-count raw-log contract.
    count = len(ids)
    _unique_ids(ids, count, 'Expected selected test IDs incomplete')
    require(type(raw) is bytes and len(raw) <= MAX_TEST_LOG_BYTES and raw.endswith(b'\n'),
        'Selected raw test log incomplete or outside bound')
    text = raw.decode('ascii').replace('\r\n', '\n')
    require('\r' not in text, 'Selected raw test log has invalid line endings')
    lines = [line for line in text.split('\n') if line]
    require(len(lines) == count + 3 and lines[-3] == '-' * 70
        and re.fullmatch(r'Ran ' + str(count) + r' tests in [0-9]+(?:\.[0-9]+)?s', lines[-2])
        and lines[-1] == 'OK', 'Selected raw test footer incomplete or out of order')
    successes = []
    for line in lines[:-3]:
        match = re.fullmatch(r'([A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok', line)
        require(match is not None and match[1] == match[2].rsplit('.', 1)[-1],
            'Unexpected or non-success selected raw test result')
        successes.append(match[2])
    require(len(successes) == len(set(successes)) == count and set(successes) == set(ids),
        'Raw selected test ID set differs')
    return successes


def validate_worker_result(record, raw_test_log, contract=None, *, expected_runtime,
        expected_source, expected_worker_sha256, expected_probes_sha256, raw_probe_stdout):
    pinned = _pinned(contract)
    runtime_contract.validate_runtime(expected_runtime)
    target = expected_runtime['target']
    ids = expected_ids(target, pinned)
    count = len(ids)
    modules = sorted({'.'.join(name.split('.')[:2]) for name in ids})
    require(type(record) is dict and type(record.get('schema')) is int and record['schema'] == 1
        and record.get('scope') == SCOPE and record.get('contract_sha256') == CONTRACT_SHA256,
        'Platform worker receipt schema/scope differs')
    for key, expected in (('worker_sha256', expected_worker_sha256), ('probes_sha256', expected_probes_sha256)):
        require(type(expected) is str and re.fullmatch('[0-9a-f]{64}', expected)
            and record.get(key) == expected, 'Platform worker code binding differs: ' + key)
    require(same_typed(record.get('runtime'), expected_runtime), 'Platform worker runtime differs')
    lab = expected_runtime['qualification'] == runtime_contract.LAB_QUALIFICATION
    require(record.get('local_lab') is lab and record.get('target') == target
        and record.get('result') == (LAB_PASS if lab else CI_PASS), 'Platform worker qualification differs')
    for key, expected in (('test_modules', len(modules)), ('discovered', count), ('tests_run', count),
            ('successful_test_count', count), ('unique_successful_test_count', count), ('probe_count', 5)):
        require(type(record.get(key)) is int and record[key] == expected, 'Platform worker inventory incomplete: ' + key)
    require(same_typed(record.get('test_module_names'), modules), 'Selected loaded module names differ')
    for key in ('discovered_test_ids', 'successful_test_ids'):
        _unique_ids(record.get(key), count, 'Selected worker test ID inventory incomplete')
        require(set(record[key]) == set(ids), 'Selected worker test ID set differs')
    require(all(type(record.get(k)) is list and record[k] == [] for k in ('failures', 'errors',
        'skipped', 'expected_failures', 'unexpected_successes', 'discovery_errors')),
        'Unresolved selected test/discovery outcome')
    require(not any(k in record for k in ('runner_error', 'final_source_error', 'module_binding_error',
        'acceptance_error', 'final_tool_error')), 'Platform worker failed outside selected tests')
    require(record.get('source_files_unchanged') is True and record.get('tool_files_unchanged') is True
        and record.get('source_overlay_applied') is False and record.get('R3_candidate_tested') is False
        and record.get('live_apply') is False, 'Platform worker source/tool/scope invariant failed')
    _source_binding(expected_source)
    for key in ('source_before', 'source_after'):
        _source_binding(record.get(key))
        require(same_typed(record[key], expected_source), 'Platform worker source pair differs from parent copy')
    tests, product = record.get('loaded_test_module_bindings'), record.get('loaded_product_module_bindings')
    require(type(tests) is dict and set(tests) == set(modules) and type(product) is dict
        and set(tests) <= set(product), 'Selected loaded module inventory incomplete')
    for name, binding in product.items():
        require(type(name) is str and type(binding) is dict and set(binding) == {'path', 'sha256'}
            and type(binding['path']) is str and binding['path'] == name.replace('.', '/') + '.py'
            and binding['path'] in expected_source['per_file_sha256']
            and binding['sha256'] == expected_source['per_file_sha256'][binding['path']],
            'Loaded prerequisite product origin/bytes differ')
    require(all(same_typed(binding, product[name]) for name, binding in tests.items()),
        'Selected test module origin differs')
    require(record.get('product_support') == 'NOT_ACCEPTED'
        and all(record.get(k) == 'NOT_TESTED' for k in ('native_GUI_acceptance', 'physical_GUI', 'product_storage_acceptance'))
        and all(record.get(k) == 'NOT_EXECUTED_BY_THIS_SUITE' for k in ('full2509', 'prior248')),
        'Platform prerequisites overclaims product acceptance')
    validate_probe_rows(record.get('probe_rows'), target)
    validate_raw_probe_stdout(raw_probe_stdout, record['probe_rows'], target)
    validate_raw_test_log(raw_test_log, ids)
    return count
