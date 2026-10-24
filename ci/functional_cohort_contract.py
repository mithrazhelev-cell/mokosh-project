"""Pinned 248-case selection and fail-closed receipt contracts; no product imports.

Qualification here means the recorded interpreter/platform/package versions.
The GitHub run/job identity must still be established from the hosted run evidence.
The explicit local-lab mode cannot establish CI/native platform acceptance.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import ssl
import sys

from run_preliminary import read_file, require

CONTRACT_PATH = Path(__file__).with_name('functional_cohort_248.json')
CONTRACT_SHA256 = 'd79223e4321cb84c1c54f19048d885a5c350bcef0e3502f5567d28c4cab78d85'
SOURCE_SHA256 = '92e159ed818bc6fbf858549452ad78fd0b238f9d8193ac9842147555afb3dcca'
TEST_COUNT, MODULE_COUNT = 248, 12
MAX_CONTRACT_BYTES = 256 * 1024
MAX_TEST_LOG_BYTES = 20 * 1024 * 1024
SCOPE = 'FUNCTIONAL_COHORT_248_PRELIMINARY_ONLY_NO_PRODUCT_PLATFORM_ACCEPTANCE'
CI_QUALIFICATION = 'CI_EXACT_PY3123'
LAB_QUALIFICATION = 'LOCAL_LAB_NOT_CI_QUALIFIED'
CI_PASS = 'PASS_FUNCTIONAL_COHORT_248'
LAB_PASS = 'PASS_LOCAL_LAB_FUNCTIONAL_COHORT_248'
DEPENDENCIES = {'cryptography': '49.0.0', 'argon2-cffi': '25.1.0',
    'argon2-cffi-bindings': '25.1.0', 'cffi': '2.1.0', 'pycparser': '3.0'}
TARGETS = {'linux-x64': ('linux', 'posix', {'x86_64', 'amd64'}),
    'windows-x64': ('win32', 'nt', {'amd64', 'x86_64'}),
    'macos-arm64': ('darwin', 'posix', {'arm64', 'aarch64'})}
CI_MARKERS = ('CI', 'GITHUB_ACTIONS', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT',
    'GITHUB_SHA', 'RUNNER_OS')


def strict_json(raw):
    """JSON with no duplicate members or non-standard numeric constants."""
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, 'Duplicate JSON member')
            result[key] = value
        return result

    def bad_constant(value):
        raise ValueError('Non-standard JSON constant')

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad_constant)


def _unique_strings(value, count, detail):
    require(type(value) is list and len(value) == count
        and all(type(item) is str and item for item in value)
        and len(set(value)) == count, detail)


def same_typed(left, right):
    """JSON-shaped equality that never equates bool with an integer."""
    if type(left) is not type(right):
        return False
    if type(left) is dict:
        return (all(type(key) is str for key in left)
            and all(type(key) is str for key in right)
            and set(left) == set(right)
            and all(same_typed(left[key], right[key]) for key in left))
    if type(left) is list:
        return len(left) == len(right) and all(same_typed(a, b) for a, b in zip(left, right))
    return left == right


def validate_contract(value):
    require(type(value) is dict and type(value.get('schema')) is int
        and value['schema'] == 1 and value.get('scope') == SCOPE, 'Cohort schema/scope differs')
    require(same_typed(value.get('source_snapshot'), {'files': 263, 'bytes': 5223645,
        'canonical_sha256': SOURCE_SHA256}), 'Cohort source binding differs')
    require(type(value.get('expected_test_count')) is int
        and value['expected_test_count'] == TEST_COUNT, 'Cohort count differs')
    modules, ids, mandatory = (value.get(key) for key in
        ('test_modules', 'expected_successful_test_ids', 'mandatory_real_mlkem_test_ids'))
    _unique_strings(modules, MODULE_COUNT, 'Missing/duplicate cohort module')
    require(all(re.fullmatch(r'tests\.test_[a-z0-9_]+', name) for name in modules),
        'Unsafe cohort module name')
    _unique_strings(ids, TEST_COUNT, 'Missing/duplicate cohort test ID')
    require(ids == sorted(ids) and all(re.fullmatch(r'[A-Za-z0-9_.]+', name)
        and sum(name.startswith(module + '.') for module in modules) == 1 for name in ids),
        'Cohort test IDs are not exact module-qualified names')
    require(all(any(name.startswith(module + '.') for name in ids) for module in modules),
        'Empty cohort module')
    _unique_strings(mandatory, 6, 'Missing/duplicate mandatory real ML-KEM ID')
    require(set(mandatory) <= set(ids), 'Mandatory real ML-KEM ID not selected')
    require(same_typed(value.get('dependency_pins'), DEPENDENCIES)
        and value.get('CI_python') == '3.12.3', 'Cohort runtime pins differ')
    targets = value.get('CI_targets')
    require(type(targets) is dict and set(targets) == set(TARGETS), 'Cohort target platform set differs')
    for key, row in TARGETS.items():
        target = targets[key]
        require(type(target) is dict and set(target) == {'sys_platform', 'machines'}
            and target['sys_platform'] == row[0] and type(target['machines']) is list
            and len(target['machines']) == len(row[2])
            and all(type(machine) is str for machine in target['machines'])
            and set(target['machines']) == row[2], 'Cohort target platform set differs')
    require(same_typed(value.get('acceptance_rules'), {'failures': 0, 'errors': 0, 'skips': 0,
        'expected_failures': 0, 'unexpected_successes': 0, 'unique_successes': 248,
        'all_six_real_mlkem_ids_must_succeed': True, 'source_overlay_allowed': False,
        'R3_execution_allowed': False, 'native_GUI_acceptance': 'NOT_TESTED',
        'physical_GUI': 'NOT_TESTED', 'product_storage_acceptance': 'NOT_TESTED'}),
        'Cohort acceptance policy differs')
    return value


def load_contract(path=CONTRACT_PATH):
    raw = read_file(path)
    require(len(raw) <= MAX_CONTRACT_BYTES and hashlib.sha256(raw).hexdigest() == CONTRACT_SHA256,
        'Pinned cohort manifest bytes differ')
    return validate_contract(strict_json(raw))


def _pinned_contract(contract):
    pinned = load_contract()
    require(contract is None or same_typed(contract, pinned), 'Supplied cohort contract differs from pinned manifest')
    return pinned


def dependency_versions():
    return {name: importlib.metadata.version(name) for name in DEPENDENCIES}


def crypto_openssl_version():
    # This import is reached only after exact interpreter/platform and package pins.
    from cryptography.hazmat.backends.openssl.backend import backend
    return backend.openssl_version_text()


def validate_runtime(runtime):
    expected_keys = {'python', 'sys_platform', 'os_name', 'machine', 'target', 'dependencies',
        'isolated', 'dont_write_bytecode', 'qualification', 'CI_runtime_qualified',
        'python_ssl_openssl', 'cryptography_openssl'}
    require(type(runtime) is dict and set(runtime) == expected_keys, 'Runtime receipt field set differs')
    require(type(runtime.get('target')) is str and runtime['target'] in TARGETS, 'Unknown qualified target')
    system, family, machines = TARGETS[runtime['target']]
    require(runtime.get('sys_platform') == system and runtime.get('os_name') == family
        and type(runtime.get('machine')) is str and runtime['machine'] in machines,
        'Qualified runtime platform/architecture differs')
    require(runtime.get('isolated') is True and runtime.get('dont_write_bytecode') is True
        and same_typed(runtime.get('dependencies'), DEPENDENCIES), 'Runtime flags or package pins differ')
    lab = runtime.get('qualification') == LAB_QUALIFICATION
    require(runtime.get('qualification') in (CI_QUALIFICATION, LAB_QUALIFICATION)
        and runtime.get('CI_runtime_qualified') is (not lab)
        and runtime.get('python') == ('3.12.14' if lab else '3.12.3')
        and (not lab or runtime['target'] == 'linux-x64'), 'Runtime qualification/version differs')
    for key in ('python_ssl_openssl', 'cryptography_openssl'):
        text = runtime.get(key)
        require(type(text) is str and 0 < len(text) <= 240 and '\n' not in text and '\r' not in text,
            'Runtime crypto identity unavailable')
    return runtime


def qualify_runtime(target, local_lab=False, contract=None):
    _pinned_contract(contract)
    require(type(local_lab) is bool and type(target) is str and target in TARGETS,
        'Explicit known target and boolean lab mode required')
    require(sys.flags.isolated and sys.dont_write_bytecode, 'Explicit -I and -B required')
    system, family, machines = TARGETS[target]
    machine = platform.machine().lower()
    require(sys.platform == system and os.name == family and machine in machines,
        'Actual platform/architecture differs from requested target')
    version = platform.python_version()
    if local_lab:
        require(target == 'linux-x64' and version == '3.12.14'
            and not any(os.environ.get(key) for key in CI_MARKERS),
            'Local lab mode requires isolated local Linux/Python3.12.14 without runner identity')
    else:
        require(version == '3.12.3', 'Pinned CI Python3.12.3 required')
    dependencies = dependency_versions()
    require(same_typed(dependencies, DEPENDENCIES), 'The exact five dependency pins are required')
    crypto_ssl = crypto_openssl_version()
    require(type(crypto_ssl) is str and 0 < len(crypto_ssl) <= 240
        and '\n' not in crypto_ssl and '\r' not in crypto_ssl, 'Crypto runtime identity unavailable')
    return validate_runtime({'python': version, 'sys_platform': sys.platform, 'os_name': os.name,
        'machine': machine, 'target': target, 'dependencies': dependencies,
        'isolated': True, 'dont_write_bytecode': True,
        'qualification': LAB_QUALIFICATION if local_lab else CI_QUALIFICATION,
        'CI_runtime_qualified': not local_lab, 'python_ssl_openssl': ssl.OPENSSL_VERSION,
        'cryptography_openssl': crypto_ssl})


def _source_binding(value):
    require(type(value) is dict and type(value.get('files')) is int
        and type(value.get('bytes')) is int
        and (value['files'], value['bytes'], value.get('canonical_sha256'))
        == (263, 5223645, SOURCE_SHA256), 'Worker source identity differs')
    hashes, modes, metadata = (value.get(key) for key in
        ('per_file_sha256', 'observed_file_modes', 'non_atime_metadata'))
    require(type(hashes) is dict and len(hashes) == 263
        and all(type(name) is str and type(sha) is str and re.fullmatch('[0-9a-f]{64}', sha)
            for name, sha in hashes.items()), 'Worker per-file source binding incomplete')
    require(type(modes) is dict and set(modes) == set(hashes)
        and all(type(mode) is int for mode in modes.values()), 'Worker source mode inventory incomplete')
    require(type(metadata) is dict and len(metadata) == 268,
        'Worker complete non-atime source inventory incomplete')


def validate_raw_test_log(raw, expected_ids):
    _unique_strings(expected_ids, TEST_COUNT, 'Expected raw-log test ID set is incomplete')
    if type(raw) is bytes:
        require(len(raw) <= MAX_TEST_LOG_BYTES, 'Cohort raw test log exceeds bound')
        raw = raw.decode('ascii')
    require(type(raw) is str and raw.isascii() and len(raw.encode('ascii')) <= MAX_TEST_LOG_BYTES
        and raw.endswith('\n'), 'Cohort raw test log is incomplete or outside its bound')
    text = raw.replace('\r\n', '\n')
    require('\r' not in text, 'Cohort test log has invalid line endings')
    successes, runs, okay, separators = [], 0, 0, 0
    lines = [line for line in text.split('\n') if line]
    require(len(lines) == TEST_COUNT + 3 and lines[-3] == '-' * 70
        and re.fullmatch(r'Ran 248 tests in [0-9]+(?:\.[0-9]+)?s', lines[-2])
        and lines[-1] == 'OK', 'Raw unittest success footer is incomplete or out of order')
    for line in lines:
        match = re.fullmatch(r'([A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\) \.\.\. ok', line)
        if match:
            require(match[1] == match[2].rsplit('.', 1)[-1], 'Raw test method/ID differs')
            successes.append(match[2])
        elif line == '-' * 70:
            separators += 1
        elif re.fullmatch(r'Ran 248 tests in [0-9]+(?:\.[0-9]+)?s', line):
            runs += 1
        elif line == 'OK':
            okay += 1
        else:
            raise ValueError('Unexpected/non-success raw test result line')
    require(len(successes) == len(set(successes)) == TEST_COUNT
        and set(successes) == set(expected_ids)
        and runs == okay == separators == 1 and lines[-1] == 'OK',
        'Raw test log does not prove the exact complete cohort')
    return successes


def validate_worker_result(record, raw_test_log, contract=None, *, expected_runtime,
        expected_source, expected_worker_sha256):
    contract = _pinned_contract(contract)
    require(type(record) is dict and type(record.get('schema')) is int and record['schema'] == 1,
        'Worker receipt schema differs')
    require(record.get('scope') == SCOPE and record.get('contract_sha256') == CONTRACT_SHA256,
        'Worker cohort scope/binding differs')
    require(type(expected_worker_sha256) is str and re.fullmatch('[0-9a-f]{64}', expected_worker_sha256)
        and record.get('worker_sha256') == expected_worker_sha256, 'Worker code binding differs')
    validate_runtime(expected_runtime)
    require(same_typed(record.get('runtime'), expected_runtime),
        'Worker runtime differs from qualified parent runtime')
    local_lab = expected_runtime.get('qualification') == LAB_QUALIFICATION
    require(expected_runtime.get('qualification') in (LAB_QUALIFICATION, CI_QUALIFICATION)
        and expected_runtime.get('CI_runtime_qualified') is (not local_lab)
        and record.get('local_lab') is local_lab and record.get('target') == expected_runtime.get('target')
        and record.get('result') == (LAB_PASS if local_lab else CI_PASS), 'Worker qualification claim differs')
    for key, expected in (('test_modules', MODULE_COUNT), ('discovered', TEST_COUNT),
            ('tests_run', TEST_COUNT), ('successful_test_count', TEST_COUNT),
            ('unique_successful_test_count', TEST_COUNT)):
        require(type(record.get(key)) is int and record[key] == expected, 'Incomplete worker inventory: ' + key)
    require(same_typed(record.get('test_module_names'), contract['test_modules']),
        'Worker selected module names differ')
    for key in ('discovered_test_ids', 'successful_test_ids'):
        ids = record.get(key)
        _unique_strings(ids, TEST_COUNT, 'Missing/duplicate worker test IDs: ' + key)
        require(set(ids) == set(contract['expected_successful_test_ids']), 'Worker test ID set differs: ' + key)
    require(record.get('mandatory_real_mlkem_success_ids') == sorted(contract['mandatory_real_mlkem_test_ids']),
        'Mandatory real ML-KEM success evidence incomplete')
    require(all(record.get(key) == [] for key in ('failures', 'errors', 'skipped',
        'expected_failures', 'unexpected_successes', 'discovery_errors')),
        'Unresolved test/discovery result in worker receipt')
    require(all(key not in record for key in ('runner_error', 'final_source_error',
        'module_binding_error', 'acceptance_error')), 'Worker failed outside unittest results')
    require(record.get('source_files_unchanged') is True and record.get('source_overlay_applied') is False
        and record.get('R3_candidate_tested') is False and record.get('live_apply') is False,
        'Worker source/scope invariant failed')
    _source_binding(expected_source)
    for key in ('source_before', 'source_after'):
        _source_binding(record.get(key))
        require(same_typed(record[key], expected_source), 'Worker source snapshot differs from held parent copy')
    tests, product = record.get('loaded_test_module_bindings'), record.get('loaded_product_module_bindings')
    require(type(tests) is dict and set(tests) == set(contract['test_modules'])
        and type(product) is dict and set(tests) <= set(product), 'Loaded module binding inventory incomplete')
    for name, binding in product.items():
        require(type(name) is str and type(binding) is dict and set(binding) == {'path', 'sha256'}
            and type(binding['path']) is str and binding['path'] == name.replace('.', '/') + '.py'
            and binding['path'] in expected_source['per_file_sha256']
            and binding['sha256'] == expected_source['per_file_sha256'][binding['path']],
            'Loaded product module bytes differ from frozen source')
    for name, binding in tests.items():
        require(same_typed(binding, product[name]) and binding['path'] == name.replace('.', '/') + '.py',
            'Selected test module origin differs')
    require(all(record.get(key) == 'NOT_TESTED' for key in
        ('native_GUI_acceptance', 'physical_GUI', 'product_storage_acceptance'))
        and record.get('full2509') == 'NOT_EXECUTED_BY_COHORT', 'Worker overclaims product/platform acceptance')
    validate_raw_test_log(raw_test_log, contract['expected_successful_test_ids'])
