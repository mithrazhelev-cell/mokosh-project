"""Owned real-metadata fixtures for the CI reader; no product GUI/crypto operation.

The fstat hook schedules a real chmod/read-only toggle after the first actual
kernel observation. It never fabricates a stat result. Fixture waits separate
real timestamp events; the production reader has no retry, tolerance or wait.
"""
from pathlib import Path
import argparse
import json
import os
import platform
import stat
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_preliminary as controller

FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
CONTENT = b'MOKOSH owned non-secret immutable fixture\n'
PREFIX = 'MOKOSH_NATIVE_STAT_READER='


class Unexercised(ValueError):
    pass


def qualified_runtime():
    return (os.name == 'nt' and sys.platform == 'win32' and sys.version_info[:3] == (3, 12, 3)
        and platform.machine().lower() in ('amd64', 'x86_64')
        and sys.flags.isolated and sys.dont_write_bytecode)


def fields(value):
    return {key: getattr(value, key) for key in FIELDS}


def capture_read(path, *, mutate=False, reader=None):
    """Single-process scheduler around the real kernel fstat, never fake metadata."""
    reader = controller.read_file if reader is None else reader
    original_fstat = os.fstat
    original_mode = stat.S_IMODE(path.stat().st_mode)
    samples, raw, refused = [], None, False

    def observe(fd):
        value = original_fstat(fd)
        samples.append(fields(value))
        if mutate and len(samples) == 1:
            # The held read descriptor stays open. Restore the original mode
            # before the second observation, leaving ChangeTime as the delta.
            time.sleep(0.04)
            path.chmod(original_mode & ~stat.S_IWRITE)
            path.chmod(original_mode)
        return value

    before = fields(path.lstat())
    try:
        os.fstat = observe
        try:
            raw = reader(path)
        except ValueError as error:
            if str(error) != 'Source changed while reading':
                raise
            refused = True
    finally:
        os.fstat = original_fstat
        if mutate and stat.S_IMODE(path.stat().st_mode) != original_mode:
            path.chmod(original_mode)
    after = fields(path.lstat())
    if len(samples) != 2:
        raise Unexercised('TWO_REAL_DESCRIPTOR_OBSERVATIONS_NOT_EXERCISED')
    return {'fixture_lstat_before': before, 'fixture_lstat_after': after,
        'fstat_opened': samples[0], 'fstat_after_read': samples[1],
        'refused': refused, 'returned_expected_bytes': raw == CONTENT,
        'path_observation_scope': 'OUTER_FIXTURE_SAMPLES_NOT_READER_GUARD_POST_LSTAT'}


def exercise_reader(directory, *, require_windows=True, reader=None, report=None):
    report = {} if report is None else report
    report.update(result='INCOMPLETE_OWNED_STAT_READER_FIXTURES',
        native_fixture_execution='ATTEMPTED_OWNED_FIXTURES' if require_windows else 'LOCAL_ONLY_FIXTURES',
        native_GUI_acceptance='NOT_TESTED', physical_GUI='NOT_TESTED',
        product_crypto_or_storage_acceptance='NOT_TESTED',
        scope='CI_READ_FILE_OWNED_FIXTURES_ONLY')
    path = directory / 'owned-fixture.bin'
    with path.open('xb') as stream:
        stream.write(CONTENT)
    path.chmod(0o600)
    # Distinguish creation and later write on filesystems with coarser clocks.
    time.sleep(0.04)
    with path.open('r+b') as stream:
        stream.write(CONTENT)
        stream.flush()
        os.fsync(stream.fileno())
    positive = capture_read(path, reader=reader)
    report['positive_control'] = positive
    controller.require(positive['fixture_lstat_before'] == positive['fixture_lstat_after']
        and positive['fstat_opened'] == positive['fstat_after_read'], 'Stable fixture metadata changed')
    differs = positive['fixture_lstat_before']['st_ctime_ns'] != positive['fstat_opened']['st_ctime_ns']
    report['stable_cross_api_ctime_difference_observed'] = differs
    if require_windows and not differs:
        raise Unexercised('WINDOWS_STABLE_CROSS_API_CTIME_DIFFERENCE_NOT_EXERCISED')
    controller.require(not positive['refused'] and positive['returned_expected_bytes'],
        'Stable real fixture was not accepted')
    negative = capture_read(path, mutate=True, reader=reader)
    report['negative_control'] = negative
    descriptor_changes = [key for key in FIELDS
        if negative['fstat_opened'][key] != negative['fstat_after_read'][key]]
    report['negative_descriptor_changed_fields'] = descriptor_changes
    if descriptor_changes != ['st_ctime_ns']:
        raise Unexercised('REAL_SAME_HANDLE_CTIME_ONLY_CHANGE_NOT_EXERCISED')
    if require_windows:
        comparable = FIELDS[:-1]
        path_before, path_after = negative['fixture_lstat_before'], negative['fixture_lstat_after']
        if path_before != path_after or any(path_before[key] != negative['fstat_opened'][key]
                or path_after[key] != negative['fstat_after_read'][key] for key in comparable):
            raise Unexercised('WINDOWS_NEGATIVE_NOT_ISOLATED_TO_DESCRIPTOR_CTIME_ONLY')
    controller.require(negative['refused'] and not negative['returned_expected_bytes'],
        'Real same-handle ctime-only change was not rejected')
    controller.require(path.read_bytes() == CONTENT, 'Owned fixture content changed')
    report.update(result='PASS_NATIVE_WINDOWS_STAT_READER_FIXTURES' if require_windows
            else 'PASS_OWNED_STAT_FIXTURES_LOCAL_ONLY',
        native_fixture_execution='COMPLETED_OWNED_FIXTURES' if require_windows else 'LOCAL_ONLY_FIXTURES',
        metadata_values='REAL_KERNEL_RESULTS_NOT_FABRICATED',
        injection='OWNED_READ_ONLY_FLAG_TOGGLE_AND_RESTORE_AFTER_FIRST_REAL_FSTAT')
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument('--project', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    project, output = map(controller.safe_path, (args.project, args.output))
    controller.require(output != project and project not in output.parents,
        'Reader reports must be outside frozen project')
    result = {'result': 'FAIL_RUNTIME_QUALIFICATION', 'native_fixture_execution': 'NOT_EXECUTED',
        'required_runtime': 'WINDOWS_X64_PYTHON_3_12_3', 'native_GUI_acceptance': 'NOT_TESTED'}
    status = 2
    try:
        if qualified_runtime():
            result['native_fixture_execution'] = 'PREPARATION_STARTED'
            with tempfile.TemporaryDirectory(prefix='mokosh-native-reader-',
                    dir=controller.private_temp_base(project)) as temporary:
                result = exercise_reader(Path(temporary), report=result)
            controller.require(result.get('result') == 'PASS_NATIVE_WINDOWS_STAT_READER_FIXTURES'
                and result.get('native_fixture_execution') == 'COMPLETED_OWNED_FIXTURES',
                'Native fixture completion contract differs')
            result['owned_fixture_directory_removed'] = not Path(temporary).exists()
            controller.require(result['owned_fixture_directory_removed'], 'Owned fixture cleanup failed')
            status = 0
    except Unexercised as error:
        result.update(result='UNEXERCISED_NATIVE_STAT_READER_FIXTURE', reason=str(error),
            native_GUI_acceptance='NOT_TESTED')
    except Exception:
        result.update(result='FAIL_NATIVE_STAT_READER_FIXTURES', native_GUI_acceptance='NOT_TESTED')
        status = 1
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
    controller.require(len(raw.encode('ascii')) <= 16384, 'Reader fixture report exceeds bound')
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = controller.safe_path(output)
    with output.open('x', encoding='ascii') as stream:
        controller.require(stream.write(raw) == len(raw), 'Incomplete reader fixture report')
        stream.flush()
    print(PREFIX + raw, end='', flush=True)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
