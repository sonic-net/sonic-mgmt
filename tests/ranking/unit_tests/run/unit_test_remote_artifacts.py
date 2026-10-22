import base64
import hashlib
import json
import os
import subprocess
import sys

import pytest


def test_one_shot_helper_creates_polls_hashes_and_deletes_one_run(tmp_path):
    from tests.ranking.run import remote_artifacts

    root = tmp_path / 'remote'
    run_id = 'a' * 32
    assert remote_artifacts.operate('create', root, run_id) == {'created': True}
    run = root / 'runs' / run_id
    (run / 'run.log').write_text('hello')
    (run / 'outcome.json').write_text(json.dumps({'process_exited': False}))

    polled = remote_artifacts.operate(
        'poll', root, run_id, {'offset': 1, 'limit': 3})
    assert base64.b64decode(polled['data']) == b'ell'
    assert polled['outcome'] == {'process_exited': False}
    assert remote_artifacts.operate('inspect', root, run_id) == {
        'outcome.json': hashlib.sha256((run / 'outcome.json').read_bytes()).hexdigest(),
        'run.log': hashlib.sha256(b'hello').hexdigest(),
    }
    assert remote_artifacts.operate('delete', root, run_id) == {'deleted': True}
    assert not run.exists()


def test_helper_refuses_duplicate_or_non_uuid_run(tmp_path):
    from tests.ranking.run import remote_artifacts

    with pytest.raises(ValueError, match='run id'):
        remote_artifacts.operate('create', tmp_path / 'remote', 'case-name')
    remote_artifacts.operate('create', tmp_path / 'remote', 'b' * 32)
    with pytest.raises(FileExistsError):
        remote_artifacts.operate('create', tmp_path / 'remote', 'b' * 32)
def test_dispatched_helper_runs_without_the_ranking_python_package(tmp_path):
    from tests.ranking.run import artifact_collection

    root = tmp_path / 'remote'
    result = subprocess.run(
        [sys.executable, '-c', artifact_collection.SCRIPT, 'create', str(root),
         'c' * 32, 'null'],
        cwd=tmp_path,
        env=dict(os.environ, PYTHONPATH=''), text=True, capture_output=True,
        check=False)

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {'created': True}
    assert (root / 'runs' / ('c' * 32)).is_dir()
