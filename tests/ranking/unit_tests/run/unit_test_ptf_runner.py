import base64
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest


def _request(tmp_path):
    run = tmp_path / 'run'
    run.mkdir()
    collector = tmp_path / 'collector' / 'sairoute_Case.json'
    collector.parent.mkdir()
    return {
        'argv': [sys.executable, '-c', 'print("OK")'],
        'env': {}, 'cwd': str(tmp_path), 'run_dir': str(run),
        'timeout_s': 5, 'container_id': 'a' * 64,
        'collector_source': str(collector),
    }


def test_runner_executes_and_records_one_process_group(tmp_path):
    from tests.ranking.run import ptf_runner

    request = _request(tmp_path)
    outcome = ptf_runner.run_ptf(
        request['argv'], env=dict(os.environ), cwd=request['cwd'],
        run_dir=request['run_dir'], timeout_s=5,
        container_id=request['container_id'])

    assert outcome['rc'] == 0
    assert outcome['process_exited'] is True
    assert 'OK' in (Path(request['run_dir']) / 'run.log').read_text()
    assert not {'pid', 'group', 'birth'}.intersection(outcome)


def test_runner_accepts_only_base64_request(tmp_path):
    from tests.ranking.run import ptf_runner

    request = _request(tmp_path)
    payload = base64.b64encode(json.dumps(request).encode()).decode()
    assert ptf_runner._load_request(['--request-base64', payload]) == request
    with pytest.raises(ValueError, match='usage'):
        ptf_runner._load_request(['--request', '-'])


def test_runner_moves_collector_into_case_directory(tmp_path):
    from tests.ranking.run import ptf_runner

    request = _request(tmp_path)
    Path(request['collector_source']).write_text('{}')
    ptf_runner._move_collector(
        request['collector_source'], Path(request['run_dir']))
    assert not Path(request['collector_source']).exists()
    assert (Path(request['run_dir']) / 'sairoute_Case.json').is_file()


def test_runner_has_no_proc_scan_or_historical_identity():
    from tests.ranking.run import ptf_runner

    source = Path(ptf_runner.__file__).read_text()
    assert '/proc' not in source
    assert 'process_birth' not in source
    assert 'artifact_ownership' not in source


def test_injected_runner_executes_without_the_ranking_python_package(tmp_path):
    from tests.ranking.run import ptf_container, ptf_runner

    request = _request(tmp_path)
    payload = base64.b64encode(json.dumps(request).encode()).decode()
    source = ptf_container._runner_source(Path(ptf_runner.__file__))
    result = subprocess.run(
        [sys.executable, '-c', source.decode(), '--request-base64', payload],
        cwd=tmp_path, env=dict(os.environ, PYTHONPATH=''), text=True,
        capture_output=True, check=False)

    assert result.returncode == 0, result.stderr
    outcome = json.loads(
        (Path(request['run_dir']) / 'outcome.json').read_text())
    assert outcome['process_exited'] is True


def test_classifier_does_not_treat_failed_summary_as_pass_on_zero_rc():
    from tests.ranking.run import ptf_protocol

    value = {
        'phase': 'ptf', 'argv': ['ptf'], 'timeout_s': 1, 'rc': 0,
        'timed_out': False, 'process_exited': True,
    }
    log = ('===== PTF console output =====\nFAILED (failures=1)\n'
           '\n===== PTF internal log =====\n')
    assert ptf_protocol.classify(value, log) == 'failed'
