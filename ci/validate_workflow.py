"""Limited workflow contract/lint check; does not claim a GitHub-hosted run."""
from pathlib import Path
import argparse
import json
import re

PINS = {'actions/checkout': '3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/setup-python': '5fda3b95a4ea91299a34e894583c3862153e4b97',
    'actions/upload-artifact': 'bbbca2ddaa5d8feaa63e36b76fdaad77386f024f'}


def check(path):
    import yaml
    raw = Path(path).read_text()
    value = yaml.safe_load(raw)
    assert set(value['on']) == {'workflow_dispatch'}, 'Manual trigger only'
    assert value['permissions'] == {'contents': 'read'}, 'Read-only contents permission required'
    assert value['concurrency']['cancel-in-progress'] is False
    assert set(value['jobs']) == {'compatibility', 'security'}
    compatibility = value['jobs']['compatibility']
    assert compatibility['strategy']['fail-fast'] is False and compatibility['strategy']['max-parallel'] == 1
    assert compatibility['strategy']['matrix']['include'] == [
        {'os': 'ubuntu-24.04', 'mode': 'linux-baseline', 'architecture': 'x64'},
        {'os': 'windows-2022', 'mode': 'portability-probe', 'architecture': 'x64'},
        {'os': 'macos-15', 'mode': 'portability-probe', 'architecture': 'arm64'}]
    actions = []
    for job in value['jobs'].values():
        assert type(job['timeout-minutes']) is int and 1 <= job['timeout-minutes'] <= 20
        assert 'permissions' not in job and 'secrets' not in job and 'environment' not in job
        for step in job['steps']:
            assert not step.get('continue-on-error'), 'Failures must stay failures'
            if 'uses' not in step:
                continue
            name, revision = step['uses'].split('@')
            assert name in PINS and revision == PINS[name] and re.fullmatch('[0-9a-f]{40}', revision)
            actions.append(step['uses'])
            if name == 'actions/checkout':
                assert step['with']['persist-credentials'] is False
                assert step['with']['ref'] == '${{ github.sha }}'
            if name == 'actions/upload-artifact':
                assert step['with']['path'] == 'artifact_upload/'
                assert step['with']['retention-days'] == 7 and step['with']['include-hidden-files'] is False
                assert "steps.stage.outputs.sealed == 'true'" in step['if'], 'Only sealed reports may upload'
    assert not any(word in raw for word in ('pull_request:', 'pull_request_target:', 'self-hosted',
        'git push', 'gh pr', '--autofix', '--fix', 'secrets.')), 'Unexpected automatic mutation/secret scope'
    return {'result': 'PASS_PRELIMINARY_WORKFLOW_CONTRACTS', 'yaml_parser_version': yaml.__version__,
        'actions': actions, 'GitHub_execution': 'NOT_RUN_NO_ACCOUNT',
        'scope': 'YAML_PARSE_AND_EXPLICIT_POLICY_CONTRACTS; NOT_GENERAL_ACTION_CODE_AUDIT'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--workflow', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        report = check(args.workflow)
        status = 0
    except Exception as error:
        report = {'result': 'FAIL_WORKFLOW_CONTRACT', 'error': type(error).__name__ + ': ' + str(error)}
        status = 1
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    raise SystemExit(status)
