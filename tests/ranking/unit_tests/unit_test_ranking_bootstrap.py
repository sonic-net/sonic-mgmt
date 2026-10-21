import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tests.ranking.environment_ownership import OwnershipError, ResourceStore
from tests.ranking.state_store import StateStore

ROOT = Path(__file__).resolve().parents[3]
TASKS = ROOT / 'ansible' / 'roles' / 'ranking' / 'tasks'


def test_clean_host_bootstrap_precedes_ownership():
    tasks = yaml.safe_load((TASKS / 'main.yml').read_text())
    includes = [task.get('ansible.builtin.include_tasks') for task in tasks]
    assert includes[0] == 'bootstrap.yml'
    bootstrap = yaml.safe_load((TASKS / 'bootstrap.yml').read_text())
    assert any('ansible.builtin.command' in task for task in bootstrap)
    assert any('ansible.builtin.copy' in task for task in bootstrap)


def test_agent_runs_from_a_deployed_package_without_pythonpath(tmp_path):
    package = tmp_path / 'deployed' / 'ranking'
    package.mkdir(parents=True)
    for name in ('__init__.py', 'remote_agent.py', 'environment_ownership.py',
                 'state_store.py', 'snapshot_contract.py'):
        shutil.copyfile(ROOT / 'tests' / 'ranking' / name, package / name)
    request = tmp_path / 'request.json'
    request.write_text(json.dumps({'action': 'unknown'}))
    request.chmod(0o600)
    env = dict(os.environ)
    env.pop('PYTHONPATH', None)
    result = subprocess.run([sys.executable, str(package / 'remote_agent.py'),
                             '--request', str(request.resolve())],
                            cwd=tmp_path, env=env, capture_output=True, text=True)
    assert result.returncode == 1
    assert 'Unknown action or invalid request fields' in result.stderr
    assert 'ImportError' not in result.stderr


def test_operation_request_paths_do_not_collide():
    from tests.ranking.ranking_infra import _request_path

    def request(operation):
        return {'action': 'claim', 'resource': 'dut:' + 'a' * 32,
                'environment_id': 'env-a', 'operation_id': operation}
    assert _request_path(request('op-a')) != _request_path(request('op-b'))


def test_attempt_marker_makes_a_claim_ineligible_for_abort(tmp_path):
    root = tmp_path.resolve()
    store = ResourceStore(str(root / 'owners'))
    handle = store.claim('ptf:' + 'b' * 32 + ':' + 'c' * 64, 'env-a', 'op-a')
    state = StateStore(str(root / 'state'), store, handle['resource'])
    state.write(handle, 'snapshot.json', {
        'schema_version': 1, 'environment_id': 'env-a', 'resource': handle['resource'],
        'peer_resource': 'dut:' + 'a' * 32, 'container_id': 'c' * 64,
        'running': True, 'interfaces': [], 'staging_path': '/tmp/env-a',
        'staging_state': 'absent'})
    state.write(handle, 'ledger.json', {
        'schema_version': 1, 'environment_id': 'env-a', 'resource': handle['resource'],
        'attempted': [], 'completed': []})
    state.mark_attempt(handle, 'stage:ptf')
    with pytest.raises(OwnershipError, match='unmodified'):
        store.abort_unmodified(handle)


def test_teardown_can_abort_a_snapshotless_unmodified_setup():
    tasks = yaml.safe_load((TASKS / 'teardown.yml').read_text())
    text = (TASKS / 'teardown.yml').read_text()
    assert 'abort' in text

    def flatten(tasks):
        for task in tasks:
            yield task
            for key in ('block', 'always', 'rescue'):
                yield from flatten(task.get(key, []))
    actions = [task.get('ansible.builtin.set_fact', {}) for task in flatten(tasks)]
    assert any('ranking_teardown_unmodified' in action for action in actions)


def test_recovery_transport_bootstraps_once_before_dispatch():
    from tests.ranking.ranking_infra import HostReservationClient
    calls = []

    def invoke(argv):
        params = json.loads(argv[argv.index('-a') + 1])
        module = argv[argv.index('-m') + 1]
        calls.append((module, params))
        if module == 'ansible.builtin.command':
            return {'schema_version': 1, 'action': 'claim', 'result': {
                'resource': 'dut:' + 'a' * 32, 'environment_id': 'env-a',
                'operation_id': 'op-a', 'created': True}}
        return {}
    resource = 'dut:' + 'a' * 32
    route = {'host': 'dut-a', 'inventory': 'hosts', 'agent': 'ranking.remote_agent'}
    client = HostReservationClient({resource: route}, invoke)
    client.claim(resource, 'env-a', 'op-a')
    assert calls[0][0] == 'ansible.builtin.command'
    assert calls[0][1]['argv'][1] == '-c'
    assert any(module == 'ansible.builtin.copy' and 'src' in params
               for module, params in calls)
    command = calls[-1][1]['argv']
    assert command[1].endswith('/agent/ranking/remote_agent.py')
    assert '/env-a/op-a/' in command[1]


def test_ansible_transport_accepts_successful_file_module_output():
    from unittest.mock import patch
    from tests.ranking.ranking_infra import ansible_agent_invoke
    completed = subprocess.CompletedProcess([], 0, b'dut-a | CHANGED => {}', b'')
    with patch('tests.ranking.ranking_infra.subprocess.run', return_value=completed):
        assert ansible_agent_invoke(['ansible', 'dut-a', '-m', 'ansible.builtin.copy']) == {}


@pytest.mark.parametrize('name, action', [
    ('Claim the DUT reservation', 'setup'), ('Claim the PTF reservation', 'setup'),
    ('Resume the retained DUT reservation', 'status'), ('Resume the retained PTF reservation', 'status'),
])
def test_status_never_creates_a_new_environment(name, action):
    tasks = yaml.safe_load((TASKS / 'ownership.yml').read_text())
    task = next(task for task in tasks if task['name'] == name)
    assert task.get('when') == "ranking_action == '{}'".format(action)


@pytest.mark.parametrize('unsafe', ['symlink', 'writable'])
def test_transport_refuses_untrusted_ancestors_before_copy(tmp_path, monkeypatch, unsafe):
    from tests.ranking import host_transport
    from tests.ranking.ranking_infra import AgentDispatchError
    base = tmp_path.resolve() / 'requests'
    outside = tmp_path.resolve() / 'outside'
    outside.mkdir()
    if unsafe == 'symlink':
        base.symlink_to(outside, target_is_directory=True)
    else:
        base.mkdir(mode=0o700)
        base.chmod(0o777)
    monkeypatch.setattr(host_transport, 'REQUEST_ROOT', str(base))
    copies = []

    def invoke(argv):
        module = argv[argv.index('-m') + 1]
        params = json.loads(argv[argv.index('-a') + 1])
        if module == 'ansible.builtin.file':
            Path(params['path']).mkdir(parents=True, exist_ok=True)
        elif module == 'ansible.builtin.copy':
            copies.append(params)
        elif module == 'ansible.builtin.command' and '-c' in params['argv']:
            result = subprocess.run([sys.executable] + params['argv'][1:], capture_output=True, text=True)
            if result.returncode:
                raise AgentDispatchError(result.stderr)
        return {}
    route = {'host': 'dut-a', 'inventory': 'hosts', 'agent': 'ranking.remote_agent'}
    request = {'action': 'claim', 'resource': 'dut:' + 'a' * 32,
               'environment_id': 'env-a', 'operation_id': 'op-a'}
    try:
        with pytest.raises(AgentDispatchError):
            host_transport.HostTransport(invoke).invoke_agent(route, request)
        assert copies == []
        assert list(outside.iterdir()) == []
    finally:
        if unsafe == 'writable':
            base.chmod(0o700)


@pytest.mark.parametrize('environment, operation', [('../escape', 'op-a'), ('env-a', '../escape')])
def test_role_rejects_path_components_before_creating_controller_files(environment, operation):
    from tests.ranking.ranking_infra import _validate_invocation
    execution = {'runtime': {'inventory': 'hosts'},
                 'execution': {'dut_host': 'dut-a', 'ptf_host': 'ptf-a'},
                 'source_hash': 'a' * 64, 'mapping_hash': 'b' * 64, 'profile_hash': 'c' * 64,
                 'source_identity': {'commit': 'abc'}, 'port_mapping': [],
                 'pipeline_dir': '/source/pipeline', 'runner_path': '/source/runner.py'}
    with pytest.raises(ValueError):
        _validate_invocation('setup', execution, environment, operation, None, None)
