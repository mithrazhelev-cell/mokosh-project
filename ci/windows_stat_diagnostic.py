"""One bounded Windows observation job; never product compatibility acceptance."""
from pathlib import Path
import argparse
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bootstrap_venv
import run_preliminary
import stage_report_artifacts
from stat_diagnostics import Collector


def qualified_runtime():
    return (sys.flags.isolated and sys.dont_write_bytecode and sys.platform == 'win32'
        and sys.version_info[:3] == (3, 12, 3) and platform.machine().lower() in ('amd64', 'x86_64'))


def main(argv=None):
    parser = argparse.ArgumentParser(allow_abbrev=False)
    commands = parser.add_subparsers(dest='phase', required=True)
    bootstrap = commands.add_parser('bootstrap', allow_abbrev=False)
    for name in ('project', 'manifest', 'destination', 'requirements', 'output'):
        bootstrap.add_argument('--' + name, type=Path, required=True)
    audit = commands.add_parser('audit', allow_abbrev=False)
    for name in ('project', 'manifest', 'output'):
        audit.add_argument('--' + name, type=Path, required=True)
    stage = commands.add_parser('stage', allow_abbrev=False)
    for name in ('root', 'output'):
        stage.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args(argv)
    observer = Collector(args.phase.upper())
    status = 1
    try:
        if not qualified_runtime():
            observer.event('QUALIFICATION_FAILED')
            observer.mark_incomplete('COLLECTOR_ERROR')
            return 2
        observer.event('DIAGNOSTIC_STARTED')
        if args.phase == 'bootstrap':
            status = bootstrap_venv.bootstrap(args.project, args.manifest, args.destination,
                args.requirements, args.output, diagnostic=observer)
        elif args.phase == 'audit':
            status = run_preliminary.run_audit(args.project, args.manifest, args.output,
                'portability-probe', Path(__file__).with_name('run_baseline_tests.py'),
                diagnostic=observer, diagnostic_only=True)
        else:
            result = stage_report_artifacts.stage(args.root, args.output, diagnostic=observer)
            if result['safe_subset_sealed']:
                # Same fixed output contract used by the normal artifact stager.
                import os
                if os.environ.get('GITHUB_OUTPUT'):
                    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as stream:
                        stream.write('sealed=true\n')
            status = 0 if result['result'].startswith('PASS_') else 1
    except BaseException:
        # No arbitrary exception body, path or file content enters diagnostic
        # stdout. Source/bootstrap handlers already retain their approved logs.
        observer.mark_incomplete('COLLECTOR_ERROR')
        status = 1
    finally:
        observer.finish()
    # Distinguish incomplete collection from an original guard refusal or
    # diagnostic non-reproduction (both retain exit 1). A final receipt can
    # reach the log before its flush fails, so review must also check this exit.
    return 2 if observer.incomplete else status


if __name__ == '__main__':
    raise SystemExit(main())
