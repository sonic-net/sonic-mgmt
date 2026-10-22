import copy
import json
import os
import re
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from tests.ranking.execution_config import build_ptf_request
from tests.ranking.ranking_infra import (
    AGENT_MODULE, RECEIPT_FILE, AgentDispatchError, AgentResponseError,
    HostReservationClient, PLAYBOOKS, ReceiptError, Infra, RoleInvocationError,
    RoleResult, ansible_agent_invoke, build_playbook_argv, create_receipt,
    invoke_role, main, read_receipt, update_receipt,
)


ROOT = Path(__file__).resolve().parents[3]
REQUIRED_PAYLOAD_KEYS = {
    'ranking_action', 'ranking_environment_id', 'ranking_operation_id',
    'ranking_case', 'ranking_run_id', 'ranking_dut_host', 'ranking_ptf_host',
    'ranking_execution',
}
RUN_ARGS = ('env-a', 'op-a', 'sairoute.RouteA', 'run-a')


def completed(rc, stdout=b'', stderr=b''):
    return subprocess.CompletedProcess([], rc, stdout=stdout, stderr=stderr)


def test_infra_literal_argv_and_rc(execution_spec, tmp_path):
    literal = '$(touch unsafe);echo bad'
    execution_spec['execution']['ptf_argv'].append(literal)
    artifacts = tmp_path / 'call'
    with patch('tests.ranking.ranking_infra.subprocess.run',
               return_value=subprocess.CompletedProcess([], 13)) as run:
        result = invoke_role('run', execution_spec, 'env-a', 'op-a',
                             'sairoute.RouteA', 'run-a', str(artifacts))
    argv = run.call_args.args[0]
    assert isinstance(argv, list)
    assert run.call_args.kwargs['shell'] is False
    assert Path(run.call_args.kwargs['cwd']).name == 'ansible'
    assert argv[argv.index('--limit') + 1] == 'dut-a'
    payload = json.loads((artifacts / 'role-vars.json').read_text())
    assert payload['ranking_execution']['ptf_argv'][-1] == literal
    assert (artifacts / 'role-vars.json').stat().st_mode & 0o777 == 0o600
    assert result.rc == 13


def test_build_playbook_argv_maps_actions_to_absolute_playbooks(execution_spec, tmp_path):
    expected_playbooks = {
        'setup': 'setup_ranking.yml', 'status': 'setup_ranking.yml',
        'run': 'run_ranking.yml', 'teardown': 'teardown_ranking.yml',
        'keep': 'teardown_ranking.yml',
    }
    assert PLAYBOOKS == expected_playbooks
    artifacts = tmp_path / 'call'
    for action, playbook in sorted(expected_playbooks.items()):
        argv = build_playbook_argv(action, execution_spec, 'env-a', 'op-a',
                                   None, None, str(artifacts))
        assert argv == ['ansible-playbook', '-i', execution_spec['runtime']['inventory'],
                        str(ROOT / 'ansible' / playbook), '--limit', 'dut-a',
                        '-e', '@' + str(artifacts / 'role-vars.json')]


def test_build_playbook_argv_rejects_unknown_action(execution_spec, tmp_path):
    for action in ('explode', 'setup ', '', None, 1):
        with pytest.raises(ValueError):
            build_playbook_argv(action, execution_spec, 'env-a', 'op-a',
                                None, None, str(tmp_path / 'call'))


def test_invoke_role_returns_parsed_outcome_and_logs(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    outcome = {'ranking_environment_id': 'env-a', 'status': 'prepared'}

    def fake_run(argv, **kwargs):
        (artifacts / 'role-outcome.json').write_text(json.dumps(outcome))
        return completed(0, b'play stdout', b'play stderr')

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=fake_run):
        result = invoke_role('run', execution_spec, *RUN_ARGS, str(artifacts))
    assert isinstance(result, RoleResult)
    assert RoleResult.__slots__ == ('rc', 'outcome')
    assert result.rc == 0
    assert result.outcome == outcome
    assert (artifacts / 'role-stdout.log').read_bytes() == b'play stdout'
    assert (artifacts / 'role-stderr.log').read_bytes() == b'play stderr'


def test_invoke_role_preserves_rc_when_outcome_missing(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    with patch('tests.ranking.ranking_infra.subprocess.run',
               return_value=completed(7, b'out', b'err')):
        result = invoke_role('run', execution_spec, *RUN_ARGS, str(artifacts))
    assert result.rc == 7
    assert result.outcome is None
    assert (artifacts / 'role-stdout.log').read_bytes() == b'out'
    assert (artifacts / 'role-stderr.log').read_bytes() == b'err'


def test_invoke_role_preserves_rc_when_outcome_unparseable(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'

    def fake_run(argv, **kwargs):
        (artifacts / 'role-outcome.json').write_text('{not json')
        return completed(3, b'out', b'err')

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=fake_run):
        result = invoke_role('run', execution_spec, *RUN_ARGS, str(artifacts))
    assert result.rc == 3
    assert result.outcome is None
    assert (artifacts / 'role-stdout.log').exists()
    assert (artifacts / 'role-stderr.log').exists()


def test_role_vars_payload_minimum_and_detachment(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'

    def fake_run(argv, **kwargs):
        stage_setup_outcome(artifacts)
        return completed(0)

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=fake_run):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(artifacts))
    payload = json.loads((artifacts / 'role-vars.json').read_text())
    assert REQUIRED_PAYLOAD_KEYS <= set(payload)
    assert payload['ranking_action'] == 'setup'
    assert payload['ranking_environment_id'] == 'env-a'
    assert payload['ranking_operation_id'] == 'op-a'
    assert payload['ranking_case'] is None
    assert payload['ranking_run_id'] is None
    assert payload['ranking_dut_host'] == 'dut-a'
    assert payload['ranking_ptf_host'] == 'server-a'
    assert payload['ranking_execution'] == execution_spec['execution']
    execution_spec['execution']['env']['LATE'] = 'changed'
    fresh = json.loads((artifacts / 'role-vars.json').read_text())
    assert fresh['ranking_execution']['env'] == {}
    assert 'ranking_ownership_root' not in payload
    assert 'ranking_ptf_request' not in payload


def test_role_vars_payload_carries_case_identity_for_run(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    with patch('tests.ranking.ranking_infra.subprocess.run',
               return_value=completed(0)):
        invoke_role('run', execution_spec, *RUN_ARGS, str(artifacts))
    payload = json.loads((artifacts / 'role-vars.json').read_text())
    assert payload['ranking_case'] == 'sairoute.RouteA'
    assert payload['ranking_run_id'] == 'run-a'


def test_role_vars_payload_carries_ptf_request_for_run(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    with patch('tests.ranking.ranking_infra.subprocess.run',
               return_value=completed(0)):
        invoke_role('run', execution_spec, *RUN_ARGS, str(artifacts))
    payload = json.loads((artifacts / 'role-vars.json').read_text())
    expected = build_ptf_request(execution_spec, 'env-a', 'sairoute.RouteA',
                                 'run-a')
    assert payload['ranking_ptf_request'] == expected
    assert payload['ranking_ptf_request']['run_dir'] == '/tmp/ranking/env-a/runs/run-a'
    execution_spec['execution']['ptf_argv'].append('mutated')
    fresh = json.loads((artifacts / 'role-vars.json').read_text())
    assert fresh['ranking_ptf_request'] == expected


def test_role_vars_payload_omits_ptf_request_for_non_run(execution_spec, tmp_path):
    for action in ('setup', 'status', 'teardown', 'keep'):
        artifacts = tmp_path / ('call-' + action)
        with patch('tests.ranking.ranking_infra.subprocess.run',
                   side_effect=playbook_router({action: setup_outcome()
                                                if action == 'setup' else {}})):
            invoke_role(action, execution_spec, 'env-a', 'op-a', None, None,
                        str(artifacts))
        payload = json.loads((artifacts / 'role-vars.json').read_text())
        assert 'ranking_ptf_request' not in payload, action


def test_role_vars_file_is_created_exclusively_with_0600(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    real_open = os.open
    seen = []

    def spy_open(path, flags, mode=0o777, *args, **kwargs):
        if str(path).endswith('role-vars.json'):
            seen.append((flags, mode))
        return real_open(path, flags, mode, *args, **kwargs)

    with patch('tests.ranking.ranking_infra.os.open', side_effect=spy_open), \
            patch('tests.ranking.ranking_infra.subprocess.run',
                  return_value=completed(0)):
        invoke_role('run', execution_spec, *RUN_ARGS, str(artifacts))
    assert seen
    for flags, mode in seen:
        assert flags & os.O_EXCL and flags & os.O_CREAT and flags & os.O_WRONLY
        assert mode == 0o600
    assert (artifacts / 'role-vars.json').stat().st_mode & 0o777 == 0o600


def test_role_vars_payload_carries_role_identity_extras(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'

    def fake_run(argv, **kwargs):
        stage_setup_outcome(artifacts)
        return completed(0)

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=fake_run):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(artifacts))
    payload = json.loads((artifacts / 'role-vars.json').read_text())
    assert payload['ranking_profile_hash'] == execution_spec['profile_hash']
    assert payload['ranking_source_identity'] == execution_spec['source_identity']
    assert payload['ranking_source_hash'] == execution_spec['source_hash']
    assert payload['ranking_mapping_hash'] == execution_spec['mapping_hash']
    assert payload['ranking_ptf_interfaces'] == [
        {'id': row['ptf_port_id'], 'name': row['ptf_interface']}
        for row in execution_spec['port_mapping']
    ]


@pytest.mark.parametrize('case', [
    '$(touch unsafe);echo bad', 'sairoute', 'RouteA', '', '.RouteA',
    'sairoute.', None, 123, 'sairoute.RouteA;rm -rf /',
])
def test_invoke_role_rejects_injection_case_names(execution_spec, tmp_path, case):
    with pytest.raises(ValueError):
        invoke_role('run', execution_spec, 'env-a', 'op-a', case, 'run-a',
                    str(tmp_path / 'call'))
    assert not (tmp_path / 'call').exists()


@pytest.mark.parametrize('run_id', ['../x', 'run a', 'run/a', '', None, 12, 'run\\a'])
def test_invoke_role_rejects_path_traversal_run_ids(execution_spec, tmp_path, run_id):
    with pytest.raises(ValueError):
        invoke_role('run', execution_spec, 'env-a', 'op-a', 'sairoute.RouteA',
                    run_id, str(tmp_path / 'call'))
    assert not (tmp_path / 'call').exists()


@pytest.mark.parametrize('action', ['setup', 'status', 'teardown', 'keep'])
@pytest.mark.parametrize('case,run_id', [
    ('sairoute.RouteA', None), (None, 'run-a'), ('sairoute.RouteA', 'run-a'),
])
def test_non_run_actions_reject_case_and_run_id(execution_spec, tmp_path, action,
                                                case, run_id):
    with pytest.raises(ValueError):
        invoke_role(action, execution_spec, 'env-a', 'op-a', case, run_id,
                    str(tmp_path / 'call'))
    assert not (tmp_path / 'call').exists()


@pytest.mark.parametrize('action', ['explode', 'Setup', '', None, 5, 'run!'])
def test_invoke_role_rejects_unknown_actions(execution_spec, tmp_path, action):
    with pytest.raises(ValueError):
        invoke_role(action, execution_spec, 'env-a', 'op-a', None, None,
                    str(tmp_path / 'call'))
    assert not (tmp_path / 'call').exists()


@pytest.mark.parametrize('dut_host', ['dut-a,dut-b', 'dut-a dut-b', ' dut-a', 'dut-a,', ''])
def test_setup_and_teardown_reject_multi_host_limit(execution_spec, tmp_path, dut_host):
    spec = copy.deepcopy(execution_spec)
    spec['execution']['dut_host'] = dut_host
    for action in ('setup', 'teardown'):
        with pytest.raises(ValueError):
            invoke_role(action, spec, 'env-a', 'op-a', None, None,
                        str(tmp_path / 'call'))
    assert not (tmp_path / 'call').exists()


def test_invoke_role_rejects_pre_existing_artifacts(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    artifacts.mkdir()
    (artifacts / 'sentinel').write_text('kept')
    with pytest.raises(ValueError):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(artifacts))
    assert (artifacts / 'sentinel').read_text() == 'kept'
    assert sorted(path.name for path in artifacts.iterdir()) == ['sentinel']


def test_invoke_role_raises_role_invocation_error_and_retains_artifacts(
        execution_spec, tmp_path):
    artifacts = tmp_path / 'call'

    def missing_binary(argv, **kwargs):
        raise FileNotFoundError('No such file or directory: ansible-playbook')

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=missing_binary) as run:
        with pytest.raises(RoleInvocationError):
            invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                        str(artifacts))
    assert run.call_count == 1
    assert (artifacts / 'role-vars.json').exists()
    assert (artifacts / 'role-vars.json').stat().st_mode & 0o777 == 0o600
    assert not (artifacts / 'role-stdout.log').exists()
    assert not (artifacts / 'role-stderr.log').exists()


def test_infra_call_forwards_to_invoke_role(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    outcome = {'status': 'collected'}

    def fake_run(argv, **kwargs):
        (artifacts / 'role-outcome.json').write_text(json.dumps(outcome))
        return completed(0, b'out', b'')

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=fake_run) as run:
        result = Infra().call('run', execution=execution_spec,
                              environment_id='env-a', operation_id='op-a',
                              case='sairoute.RouteA', run_id='run-a',
                              artifacts=str(artifacts))
    assert isinstance(result, RoleResult)
    assert result.rc == 0
    assert result.outcome == outcome
    assert run.call_args.kwargs['shell'] is False
    assert Path(run.call_args.kwargs['cwd']).name == 'ansible'


@pytest.mark.parametrize('action', ['explode', 'deploy', '', None])
def test_infra_call_rejects_unknown_actions(action):
    with pytest.raises(ValueError):
        Infra().call(action, execution={}, environment_id='env-a',
                     operation_id='op-a', case=None, run_id=None,
                     artifacts='/nonexistent-rank')


def test_infra_call_rejects_case_on_non_run_action(execution_spec, tmp_path):
    with pytest.raises(ValueError):
        Infra().call('setup', execution=execution_spec, environment_id='env-a',
                     operation_id='op-a', case='sairoute.RouteA', run_id=None,
                     artifacts=str(tmp_path / 'call'))
    assert not (tmp_path / 'call').exists()


DUT_RESOURCE = 'dut:' + 'a' * 32
PTF_RESOURCE = 'ptf:{}:{}'.format('b' * 32, 'c' * 64)


def resource_entry(resource, host, handle, *, acquired=True, restored=False,
                   released=False, uncertain=False):
    parts = resource.split(':')
    return {
        'resource': resource,
        'host': host,
        'machine_id': parts[1],
        'container_id': parts[2] if len(parts) == 3 else None,
        'handle': handle,
        'snapshot_path': None,
        'environment_path': None,
        'identity_hash': None,
        'acquired': acquired,
        'restored': restored,
        'released': released,
        'uncertain': uncertain,
    }


def reservation_handle(resource, operation_id):
    return {'resource': resource, 'environment_id': 'env-a',
            'operation_id': operation_id, 'created': operation_id is not None}


def setup_outcome():
    return {'schema_version': 1, 'environment_id': 'env-a', 'action': 'setup',
            'restored': False, 'released': [], 'kept': False, 'uncertain': False,
            'resources': [
                {'resource': DUT_RESOURCE, 'host': 'dut-a',
                 'handle': reservation_handle(DUT_RESOURCE, 'op-a')},
                {'resource': PTF_RESOURCE, 'host': 'server-a',
                 'handle': reservation_handle(PTF_RESOURCE, 'op-a')},
            ]}


def stage_setup_outcome(artifacts, outcome=None):
    (Path(artifacts) / 'role-outcome.json').write_text(
        json.dumps(setup_outcome() if outcome is None else outcome))


def keep_outcome():
    return {'schema_version': 1, 'environment_id': 'env-a', 'action': 'keep',
            'restored': False, 'released': [], 'kept': True, 'uncertain': False}


def teardown_outcome():
    return {'schema_version': 1, 'environment_id': 'env-a', 'action': 'teardown',
            'restored': True, 'released': [DUT_RESOURCE, PTF_RESOURCE],
            'kept': False, 'uncertain': False}


def playbook_router(outcomes, rc=0):
    """Fake ansible-playbook that answers each ranking action with an outcome."""
    if not isinstance(rc, dict):
        rc = {action: rc for action in ('setup', 'status', 'run', 'keep', 'teardown')}

    def fake_run(argv, **kwargs):
        directory = Path(argv[argv.index('-e') + 1][1:]).parent
        payload = json.loads((directory / 'role-vars.json').read_text())
        action = payload['ranking_action']
        outcome = outcomes[action]
        if outcome is not None:
            (directory / 'role-outcome.json').write_text(json.dumps(outcome))
        return completed(rc.get(action, 0))
    return fake_run


def agent_envelope(request):
    action = request['action']
    if action in ('claim', 'resume'):
        result = {'resource': request['resource'],
                  'environment_id': request['environment_id'],
                  'operation_id': request['operation_id'],
                  'created': action == 'claim'}
    elif action == 'begin_action':
        result = dict(resource=request['handle']['resource'],
                      environment_id=request['handle']['environment_id'],
                      operation_id=request['action_id'], created=True)
    elif action == 'validate':
        handle = request['handle']
        result = {'schema_version': 1, 'resource': handle['resource'],
                  'environment_id': handle['environment_id'],
                  'operation_id': handle['operation_id'],
                  'mutated': False, 'abortable': False}
    else:
        result = {}
    return {'schema_version': 1, 'action': action, 'result': result}


def agent_boundary(dispatch):
    staged = {}
    calls = []

    def invoke(argv):
        module = argv[argv.index('-m') + 1]
        arguments = json.loads(argv[argv.index('-a') + 1])
        if module == 'ansible.builtin.command' and '-c' in arguments['argv']:
            return {}
        if module == 'ansible.builtin.file':
            assert arguments['state'] == 'directory'
            return {}
        if module == 'ansible.builtin.copy' and 'src' in arguments:
            assert (Path(arguments['src']) / 'remote_agent.py').is_file()
            return {}
        calls.append(list(argv))
        if module == 'ansible.builtin.copy':
            assert set(arguments) == {'content', 'dest', 'mode'}
            assert arguments['mode'] == '0600'
            staged[arguments['dest']] = json.loads(arguments['content'])
            return {'changed': True}
        assert arguments['chdir'].startswith('/var/tmp/ranking-requests/env-a/')
        tokens = arguments['argv']
        return dispatch(staged[tokens[tokens.index('--request') + 1]])

    return invoke, calls


def claim_routes(inventory='inventory/hosts'):
    return {
        DUT_RESOURCE: {'host': 'dut-a', 'inventory': inventory, 'agent': AGENT_MODULE},
        PTF_RESOURCE: {'host': 'server-a', 'inventory': inventory, 'agent': AGENT_MODULE},
    }


def receipt_file(tmp_path):
    return tmp_path / 'artifacts' / 'env-a' / RECEIPT_FILE


def test_create_receipt_is_exclusive_and_strict(execution_spec, tmp_path):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', execution_spec)
    assert path.stat().st_mode & 0o777 == 0o600
    assert receipt == {
        'schema_version': 1, 'environment_id': 'env-a', 'operation_id': 'op-a',
        'action': 'setup', 'execution_contract': execution_spec, 'resources': [],
        'phase': 'created', 'primary_error': None, 'cleanup_errors': []}
    assert read_receipt(path) == receipt
    with pytest.raises(ReceiptError):
        create_receipt(path, 'env-a', 'op-b', 'teardown', execution_spec)
    assert read_receipt(path)['operation_id'] == 'op-a'
    with pytest.raises(ReceiptError):
        create_receipt(receipt_file(tmp_path), 'bad/id', 'op-a', 'setup',
                       execution_spec)
    with pytest.raises(ReceiptError):
        create_receipt(receipt_file(tmp_path), 'env-a', 'op-a', 'explode',
                       execution_spec)
    with pytest.raises(ReceiptError):
        create_receipt(receipt_file(tmp_path), 'env-a', 'op-a', 'setup', {})


def corrupt_receipt(receipt, kind):
    value = copy.deepcopy(receipt)
    if kind == 'extra':
        value['extra'] = 1
    elif kind == 'missing':
        del value['phase']
    elif kind == 'schema':
        value['schema_version'] = 2
    elif kind == 'phase':
        value['phase'] = 'exploded'
    elif kind == 'unordered':
        value['resources'] = [
            resource_entry(PTF_RESOURCE, 'server-a', None, acquired=False),
            resource_entry(DUT_RESOURCE, 'dut-a', None, acquired=False)]
    elif kind == 'duplicate':
        value['resources'] = [
            resource_entry(DUT_RESOURCE, 'dut-a', None, acquired=False)] * 2
    elif kind == 'entry-extra':
        value['resources'] = [
            dict(resource_entry(DUT_RESOURCE, 'dut-a', None, acquired=False), extra=1)]
    elif kind == 'handleless-acquired':
        value['resources'] = [
            resource_entry(DUT_RESOURCE, 'dut-a', None, acquired=True)]
    elif kind == 'dut-container':
        entry = resource_entry(DUT_RESOURCE, 'dut-a', None, acquired=False)
        entry['container_id'] = 'c' * 64
        value['resources'] = [entry]
    elif kind == 'machine-mismatch':
        entry = resource_entry(DUT_RESOURCE, 'dut-a', None, acquired=False)
        entry['machine_id'] = 'd' * 32
        value['resources'] = [entry]
    elif kind == 'handle-resource':
        value['resources'] = [
            resource_entry(DUT_RESOURCE, 'dut-a',
                           reservation_handle(PTF_RESOURCE, 'op-a'))]
    elif kind == 'handle-environment':
        entry = resource_entry(DUT_RESOURCE, 'dut-a', None, acquired=False)
        entry['handle'] = {'resource': DUT_RESOURCE, 'environment_id': 'env-b',
                           'operation_id': 'op-a', 'created': False}
        value['resources'] = [entry]
    elif kind == 'multi-host':
        value['resources'] = [
            resource_entry(DUT_RESOURCE, 'dut-a,dut-b', None, acquired=False)]
    elif kind == 'cleanup':
        value['cleanup_errors'] = 'x'
    elif kind == 'error-type':
        value['primary_error'] = 5
    elif kind == 'contract':
        value['execution_contract'] = {}
    return value


@pytest.mark.parametrize('kind', [
    'extra', 'missing', 'schema', 'phase', 'unordered', 'duplicate', 'entry-extra',
    'handleless-acquired', 'dut-container', 'machine-mismatch', 'handle-resource',
    'handle-environment', 'multi-host', 'cleanup', 'error-type', 'contract',
])
def test_read_receipt_rejects_invalid_records(execution_spec, tmp_path, kind):
    path = receipt_file(tmp_path)
    create_receipt(path, 'env-a', 'op-a', 'setup', execution_spec)
    path.write_text(json.dumps(corrupt_receipt(read_receipt(path), kind),
                               sort_keys=True))
    with pytest.raises(ReceiptError):
        read_receipt(path)


def test_read_receipt_rejects_missing_and_non_strict_json(execution_spec, tmp_path):
    path = receipt_file(tmp_path)
    with pytest.raises(ReceiptError):
        read_receipt(path)
    create_receipt(path, 'env-a', 'op-a', 'setup', execution_spec)
    path.write_text('{"schema_version": 1, "schema_version": 1}')
    with pytest.raises(ReceiptError):
        read_receipt(path)
    path.write_text('{"primary_error": NaN}')
    with pytest.raises(ReceiptError):
        read_receipt(path)
    path.write_text('[]')
    with pytest.raises(ReceiptError):
        read_receipt(path)


def test_update_receipt_validates_before_rewriting(execution_spec, tmp_path):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', execution_spec)
    receipt['phase'] = 'prepared'
    receipt['cleanup_errors'] = ['release failed']
    assert update_receipt(path, receipt)['phase'] == 'prepared'
    assert read_receipt(path)['cleanup_errors'] == ['release failed']
    assert path.stat().st_mode & 0o777 == 0o600
    receipt['phase'] = 'exploded'
    with pytest.raises(ReceiptError):
        update_receipt(path, receipt)
    assert read_receipt(path)['phase'] == 'prepared'
    with pytest.raises(ReceiptError):
        update_receipt(tmp_path / 'missing' / RECEIPT_FILE, receipt)


def test_client_claim_stages_and_dispatches_through_ansible(tmp_path):
    path = receipt_file(tmp_path)
    create_receipt(path, 'env-a', 'op-a', 'setup', {'runtime': {}})
    invoke, calls = agent_boundary(agent_envelope)
    client = HostReservationClient(claim_routes(), invoke, receipt=path)
    handle = client.claim(DUT_RESOURCE, 'env-a', 'op-a')
    assert handle == {'resource': DUT_RESOURCE, 'environment_id': 'env-a',
                      'operation_id': 'op-a', 'created': True}
    assert len(calls) == 2
    staging, command = calls
    for argv in (staging, command):
        assert argv[:5] == ['ansible', 'dut-a', '--inventory', 'inventory/hosts',
                            '--become']
    assert staging[staging.index('-m') + 1] == 'ansible.builtin.copy'
    staged = json.loads(staging[staging.index('-a') + 1])
    assert json.loads(staged['content']) == {
        'action': 'claim', 'resource': DUT_RESOURCE, 'environment_id': 'env-a',
        'operation_id': 'op-a'}
    assert command[command.index('-m') + 1] == 'ansible.builtin.command'
    remote = json.loads(command[command.index('-a') + 1])
    assert remote['argv'] == ['python3', str(Path(staged['dest']).parent /
                                             'agent/ranking/remote_agent.py'), '--request', staged['dest']]
    receipt = read_receipt(path)
    [entry] = receipt['resources']
    assert entry['resource'] == DUT_RESOURCE
    assert entry['host'] == 'dut-a'
    assert entry['machine_id'] == 'a' * 32
    assert entry['container_id'] is None
    assert entry['handle'] == handle
    assert entry['acquired'] is True
    assert entry['restored'] is False
    assert entry['released'] is False
    assert entry['uncertain'] is False


def test_client_pending_marks_the_entry_uncertain_before_dispatch(tmp_path):
    path = receipt_file(tmp_path)
    create_receipt(path, 'env-a', 'op-a', 'setup', {'runtime': {}})
    observed = {}

    def dispatch(request):
        observed['receipt'] = read_receipt(path)
        return agent_envelope(request)

    invoke, _ = agent_boundary(dispatch)
    client = HostReservationClient(claim_routes(), invoke, receipt=path)
    client.claim(PTF_RESOURCE, 'env-a', 'op-a')
    [entry] = observed['receipt']['resources']
    assert entry['resource'] == PTF_RESOURCE
    assert entry['host'] == 'server-a'
    assert entry['machine_id'] == 'b' * 32
    assert entry['container_id'] == 'c' * 64
    assert entry['uncertain'] is True
    assert entry['handle'] is None
    assert entry['acquired'] is False


@pytest.mark.parametrize('mutation', [
    lambda response: response.update(action='resume'),
    lambda response: response.update(schema_version=2),
    lambda response: response.update(result=[]),
    lambda response: response['result'].update(resource='dut:' + 'd' * 32),
    lambda response: response['result'].update(environment_id='env-b'),
    lambda response: response['result'].update(operation_id='op-z'),
    lambda response: response['result'].update(created=False),
    lambda response: response['result'].update(extra=1),
])
def test_client_rejects_mismatching_agent_responses(tmp_path, mutation):
    path = receipt_file(tmp_path)
    create_receipt(path, 'env-a', 'op-a', 'setup', {'runtime': {}})

    def dispatch(request):
        response = agent_envelope(request)
        mutation(response)
        return response

    invoke, _ = agent_boundary(dispatch)
    client = HostReservationClient(claim_routes(), invoke, receipt=path)
    with pytest.raises(AgentResponseError):
        client.claim(DUT_RESOURCE, 'env-a', 'op-a')
    [entry] = read_receipt(path)['resources']
    assert entry['uncertain'] is True
    assert entry['handle'] is None
    assert entry['acquired'] is False


def test_client_resume_keep_and_released_guard(tmp_path):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', {'runtime': {}})
    receipt['resources'] = [resource_entry(DUT_RESOURCE, 'dut-a',
                                           reservation_handle(DUT_RESOURCE, None))]
    update_receipt(path, receipt)
    invoke, calls = agent_boundary(agent_envelope)
    client = HostReservationClient(claim_routes(), invoke, receipt=path)
    handle = client.resume(DUT_RESOURCE, 'env-a', 'op-a')
    assert handle == {'resource': DUT_RESOURCE, 'environment_id': 'env-a',
                      'operation_id': 'op-a', 'created': False}
    [entry] = read_receipt(path)['resources']
    assert entry['handle'] == handle
    assert entry['acquired'] is True
    assert entry['uncertain'] is False
    client.keep(handle)
    [entry] = read_receipt(path)['resources']
    assert entry['handle'] == {'resource': DUT_RESOURCE, 'environment_id': 'env-a',
                               'operation_id': None, 'created': False}
    assert entry['released'] is False
    assert entry['uncertain'] is False
    staged = [json.loads(argv[argv.index('-a') + 1])['content']
              for argv in calls if 'copy' in argv[argv.index('-m') + 1]]
    assert [json.loads(text)['action'] for text in staged] == ['resume', 'keep']


def test_client_released_resources_get_no_further_dispatch(tmp_path):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', {'runtime': {}})
    receipt['resources'] = [resource_entry(DUT_RESOURCE, 'dut-a',
                                           reservation_handle(DUT_RESOURCE, 'op-a'))]
    update_receipt(path, receipt)
    invoke, calls = agent_boundary(agent_envelope)
    client = HostReservationClient(claim_routes(), invoke, receipt=path)
    handle = reservation_handle(DUT_RESOURCE, 'op-a')
    client.release_restored(handle)
    [entry] = read_receipt(path)['resources']
    assert entry['released'] is True
    assert entry['uncertain'] is False
    assert entry['handle'] == handle
    assert len(calls) == 2
    for rejected in (lambda: client.claim(DUT_RESOURCE, 'env-a', 'op-b'),
                     lambda: client.resume(DUT_RESOURCE, 'env-a', 'op-b'),
                     lambda: client.release_restored(handle),
                     lambda: client.keep(handle),
                     lambda: client.validate(handle)):
        with pytest.raises(ValueError):
            rejected()
    assert len(calls) == 2


def test_client_validate_returns_the_record_without_receipt_writes(tmp_path):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', {'runtime': {}})
    receipt['resources'] = [resource_entry(DUT_RESOURCE, 'dut-a',
                                           reservation_handle(DUT_RESOURCE, 'op-a'))]
    update_receipt(path, receipt)
    invoke, calls = agent_boundary(agent_envelope)
    client = HostReservationClient(claim_routes(), invoke, receipt=path)
    before = path.read_bytes()
    record = client.validate(reservation_handle(DUT_RESOURCE, 'op-a'))
    assert record == {'schema_version': 1, 'resource': DUT_RESOURCE,
                      'environment_id': 'env-a', 'operation_id': 'op-a',
                      'mutated': False, 'abortable': False}
    assert path.read_bytes() == before
    assert len(calls) == 2


def test_client_operates_without_a_receipt():
    invoke, calls = agent_boundary(agent_envelope)
    client = HostReservationClient(claim_routes(), invoke)
    assert client.claim(DUT_RESOURCE, 'env-a', 'op-a') == {
        'resource': DUT_RESOURCE, 'environment_id': 'env-a',
        'operation_id': 'op-a', 'created': True}
    with pytest.raises(ValueError):
        client.claim('dut:' + 'e' * 32, 'env-a', 'op-a')
    assert len(calls) == 2


@pytest.mark.parametrize('routes', [
    'route', {DUT_RESOURCE: 'dut-a'},
    {DUT_RESOURCE: {'host': 'dut-a', 'inventory': 'inventory/hosts'}},
    {DUT_RESOURCE: {'host': 'dut-a', 'inventory': 'inventory/hosts',
                    'agent': AGENT_MODULE, 'extra': 1}},
    {DUT_RESOURCE: {'host': 'dut-a,dut-b', 'inventory': 'inventory/hosts',
                    'agent': AGENT_MODULE}},
    {DUT_RESOURCE: {'host': 'dut a', 'inventory': 'inventory/hosts',
                    'agent': AGENT_MODULE}},
    {DUT_RESOURCE: {'host': '', 'inventory': 'inventory/hosts',
                    'agent': AGENT_MODULE}},
    {DUT_RESOURCE: {'host': 'dut-a', 'inventory': '', 'agent': AGENT_MODULE}},
    {DUT_RESOURCE: {'host': 'dut-a', 'inventory': 'inventory/hosts',
                    'agent': 'rank;ing'}},
    {'not-canonical': {'host': 'dut-a', 'inventory': 'inventory/hosts',
                       'agent': AGENT_MODULE}},
])
def test_client_rejects_invalid_routes(routes):
    with pytest.raises(ValueError):
        HostReservationClient(routes, lambda argv: {})


def test_client_rejects_non_callable_invoke():
    with pytest.raises(ValueError):
        HostReservationClient(claim_routes(), 'ansible')


def test_client_requires_an_existing_receipt(tmp_path):
    invoke, _ = agent_boundary(agent_envelope)
    with pytest.raises(ReceiptError):
        HostReservationClient(claim_routes(), invoke,
                              receipt=tmp_path / 'missing.json')


def test_ansible_agent_invoke_parses_the_agent_envelope():
    envelope = {'schema_version': 1, 'action': 'claim',
                'result': {'resource': DUT_RESOURCE, 'environment_id': 'env-a',
                           'operation_id': 'op-a', 'created': True}}
    stdout = 'dut-a | CHANGED | rc=0 >>\n'.encode() + json.dumps(envelope).encode()
    with patch('tests.ranking.ranking_infra.subprocess.run',
               return_value=completed(0, stdout, b'')) as run:
        assert ansible_agent_invoke(['ansible', 'dut-a']) == envelope
    assert run.call_args.kwargs['shell'] is False


@pytest.mark.parametrize('rc, stdout, error', [
    (1, b'dut-a | FAILED | rc=1 >>\n', AgentDispatchError),
    (2, b'', AgentDispatchError),
    (0, b'dut-a | CHANGED | rc=0 >>\nnot json', AgentResponseError),
    (0, b'', AgentResponseError),
    (0, b'dut-a | CHANGED | rc=0 >>\n[]', AgentResponseError),
])
def test_ansible_agent_invoke_rejects_failed_or_garbled_output(rc, stdout, error):
    with patch('tests.ranking.ranking_infra.subprocess.run',
               return_value=completed(rc, stdout, b'err')):
        with pytest.raises(error):
            ansible_agent_invoke(['ansible', 'dut-a'])


def test_ansible_agent_invoke_rejects_unexecutable_boundaries():
    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=FileNotFoundError('ansible')):
        with pytest.raises(AgentDispatchError):
            ansible_agent_invoke(['ansible', 'dut-a'])
    with pytest.raises(AgentDispatchError):
        ansible_agent_invoke('ansible dut-a')


def test_invoke_role_setup_records_the_receipt_lifecycle(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    receipt_path = artifacts / 'env-a' / RECEIPT_FILE
    observed = {}

    def fake_run(argv, **kwargs):
        observed['receipt'] = read_receipt(receipt_path)
        stage_setup_outcome(artifacts)
        return completed(0)

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=fake_run):
        result = invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                             str(artifacts))
    assert result.rc == 0
    assert observed['receipt']['phase'] == 'created'
    assert observed['receipt']['resources'] == []
    assert observed['receipt']['execution_contract'] == execution_spec
    assert observed['receipt']['operation_id'] == 'op-a'
    assert observed['receipt']['action'] == 'setup'
    final = read_receipt(receipt_path)
    assert final['phase'] == 'prepared'
    assert final['primary_error'] is None
    assert receipt_path.stat().st_mode & 0o777 == 0o600


def test_invoke_role_setup_populates_receipt_resources(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    receipt_path = artifacts / 'env-a' / RECEIPT_FILE

    def fake_run(argv, **kwargs):
        stage_setup_outcome(artifacts)
        return completed(0)

    with patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        result = invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                             str(artifacts))
    assert result.rc == 0
    final = read_receipt(receipt_path)
    assert final['phase'] == 'prepared'
    assert final['resources'] == [
        resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
        resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a')),
    ]
    assert all(entry['acquired'] and not entry['uncertain']
               for entry in final['resources'])


@pytest.mark.parametrize('outcome', [
    None, {}, {'resources': []}, {'resources': [{'resource': DUT_RESOURCE}]},
    {'resources': [{'resource': DUT_RESOURCE, 'host': 'dut-a', 'handle': None}]},
    {'resources': [{'resource': DUT_RESOURCE, 'host': 'dut-a',
                    'handle': reservation_handle(DUT_RESOURCE, 'op-a')}]},
])
def test_invoke_role_setup_requires_an_attestable_outcome(execution_spec, tmp_path,
                                                          outcome):
    artifacts = tmp_path / 'call'
    receipt_path = artifacts / 'env-a' / RECEIPT_FILE

    def fake_run(argv, **kwargs):
        if outcome is not None:
            stage_setup_outcome(artifacts, outcome)
        return completed(0)

    with patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        with pytest.raises(ReceiptError):
            invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                        str(artifacts))
    retained = read_receipt(receipt_path)
    assert retained['phase'] == 'created'
    assert retained['resources'] == []


def test_invoke_role_keep_finalizes_the_receipt(execution_spec, tmp_path):
    setup_dir = tmp_path / 'setup'
    keep_dir = tmp_path / 'keep'
    receipt_path = setup_dir / 'env-a' / RECEIPT_FILE

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'setup': setup_outcome(),
                                            'keep': keep_outcome()})):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(setup_dir))
        invoke_role('keep', execution_spec, 'env-a', 'op-a', None, None,
                    str(keep_dir), receipt=str(receipt_path))
    receipt = read_receipt(receipt_path)
    assert receipt['phase'] == 'kept'
    assert receipt['primary_error'] is None
    for entry in receipt['resources']:
        assert entry['handle']['operation_id'] is None
        assert entry['handle']['created'] is False
        assert entry['uncertain'] is False
        assert entry['released'] is False


def test_invoke_role_keep_failure_preserves_handles_and_marks_uncertainty(
        execution_spec, tmp_path):
    setup_dir = tmp_path / 'setup'
    keep_dir = tmp_path / 'keep'
    receipt_path = setup_dir / 'env-a' / RECEIPT_FILE

    def fake_run(argv, **kwargs):
        directory = Path(argv[argv.index('-e') + 1][1:]).parent
        payload = json.loads((directory / 'role-vars.json').read_text())
        if payload['ranking_action'] == 'setup':
            stage_setup_outcome(directory)
            return completed(0)
        return completed(3, b'out', b'err')

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=fake_run):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(setup_dir))
        result = invoke_role('keep', execution_spec, 'env-a', 'op-a', None, None,
                             str(keep_dir), receipt=str(receipt_path))
    assert result.rc == 3
    receipt = read_receipt(receipt_path)
    assert receipt['phase'] == 'failed'
    for entry in receipt['resources']:
        assert entry['handle']['operation_id'] == 'op-a'
        assert entry['handle']['created'] is True
        assert entry['released'] is False
        assert entry['uncertain'] is True


@pytest.mark.parametrize('outcome', [None, {}, {'kept': False}])
def test_invoke_role_keep_requires_an_attested_keep(execution_spec, tmp_path,
                                                    outcome):
    setup_dir = tmp_path / 'setup'
    keep_dir = tmp_path / 'keep'
    receipt_path = setup_dir / 'env-a' / RECEIPT_FILE

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'setup': setup_outcome(),
                                            'keep': outcome})):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(setup_dir))
        with pytest.raises(ReceiptError):
            invoke_role('keep', execution_spec, 'env-a', 'op-a', None, None,
                        str(keep_dir), receipt=str(receipt_path))
    receipt = read_receipt(receipt_path)
    assert receipt['phase'] == 'failed'
    for entry in receipt['resources']:
        assert entry['handle']['operation_id'] == 'op-a'
        assert entry['released'] is False


def test_invoke_role_teardown_finalizes_the_receipt(execution_spec, tmp_path):
    setup_dir = tmp_path / 'setup'
    teardown_dir = tmp_path / 'teardown'
    receipt_path = setup_dir / 'env-a' / RECEIPT_FILE

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'setup': setup_outcome(),
                                            'teardown': teardown_outcome()})):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(setup_dir))
        invoke_role('teardown', execution_spec, 'env-a', 'op-a', None, None,
                    str(teardown_dir), receipt=str(receipt_path))
    receipt = read_receipt(receipt_path)
    assert receipt['phase'] == 'released'
    assert receipt['primary_error'] is None
    for entry in receipt['resources']:
        assert entry['acquired'] and entry['restored'] and entry['released']
        assert entry['uncertain'] is False


def test_invoke_role_teardown_failure_retains_confirmed_release(
        execution_spec, tmp_path):
    setup_dir = tmp_path / 'setup'
    teardown_dir = tmp_path / 'teardown'
    receipt_path = setup_dir / 'env-a' / RECEIPT_FILE

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'setup': setup_outcome(),
                                            'teardown': teardown_outcome()},
                                           rc={'teardown': 5})):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(setup_dir))
        result = invoke_role('teardown', execution_spec, 'env-a', 'op-a', None,
                             None, str(teardown_dir), receipt=str(receipt_path))
    assert result.rc == 5
    receipt = read_receipt(receipt_path)
    assert receipt['phase'] == 'failed'
    for entry in receipt['resources']:
        assert entry['restored'] and entry['released'] and entry['uncertain']
        assert entry['handle']['operation_id'] == 'op-a'


def test_invoke_role_rejects_receipt_for_non_finalizer_actions(
        execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'run': {}})):
        with pytest.raises(ValueError):
            invoke_role('run', execution_spec, 'env-a', 'op-a', 'sairoute.RouteA',
                        'run-a', str(artifacts), receipt=str(tmp_path / 'r.json'))


def test_invoke_role_rejects_a_receipt_from_another_environment(
        execution_spec, tmp_path):
    setup_dir = tmp_path / 'setup'
    keep_dir = tmp_path / 'keep'
    receipt_path = setup_dir / 'env-a' / RECEIPT_FILE

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'setup': setup_outcome(),
                                            'keep': keep_outcome()})):
        invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                    str(setup_dir))
        with pytest.raises(ReceiptError):
            invoke_role('keep', execution_spec, 'env-b', 'op-b', None, None,
                        str(keep_dir), receipt=str(receipt_path))


def test_invoke_role_keep_refuses_an_unprepared_receipt(execution_spec, tmp_path):
    setup_dir = tmp_path / 'setup'
    keep_dir = tmp_path / 'keep'
    receipt_path = setup_dir / 'env-a' / RECEIPT_FILE
    create_receipt(receipt_path, 'env-a', 'op-a', 'setup', execution_spec)

    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'keep': keep_outcome()})):
        with pytest.raises(ReceiptError):
            invoke_role('keep', execution_spec, 'env-a', 'op-a', None, None,
                        str(keep_dir), receipt=str(receipt_path))
    assert read_receipt(receipt_path)['phase'] == 'created'


def test_invoke_role_setup_failure_marks_the_failed_phase(execution_spec, tmp_path):
    artifacts = tmp_path / 'call'
    with patch('tests.ranking.ranking_infra.subprocess.run',
               return_value=completed(7, b'out', b'err')):
        result = invoke_role('setup', execution_spec, 'env-a', 'op-a', None, None,
                             str(artifacts))
    assert result.rc == 7
    final = read_receipt(artifacts / 'env-a' / RECEIPT_FILE)
    assert final['phase'] == 'failed'
    assert isinstance(final['primary_error'], str) and final['primary_error']


@pytest.mark.parametrize('argv', [
    [], ['--action', 'keep', '--receipt', 'x'], ['--action', 'teardown'],
    ['--action', 'teardown', '--receipt', ''], ['--action'],
    ['--action', 'teardown', '--receipt', 'x', 'extra'],
    ['--action', 'teardown', '--action', 'teardown', '--receipt', 'x'],
    ['--receipt', 'x'],
])
def test_cli_rejects_unsupported_usage(tmp_path, argv):
    assert main(argv) == 2


def test_cli_rejects_invalid_receipts_without_recovery(tmp_path):
    missing = tmp_path / 'missing' / RECEIPT_FILE
    assert main(['--action', 'teardown', '--receipt', str(missing)]) == 2
    broken = receipt_file(tmp_path)
    broken.parent.mkdir(parents=True)
    broken.write_text('{not json')
    assert main(['--action', 'teardown', '--receipt', str(broken)]) == 2
    assert [path.name for path in broken.parent.iterdir()] == [RECEIPT_FILE]


def recovery_world(execution_spec, tmp_path, entries, phase):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', execution_spec)
    receipt['resources'] = entries
    receipt['phase'] = phase
    update_receipt(path, receipt)
    events = []
    playbook_vars = []
    outcome = {'schema_version': 1, 'environment_id': 'env-a', 'action': 'teardown',
               'restored': True, 'released': [DUT_RESOURCE, PTF_RESOURCE],
               'kept': False, 'uncertain': False}

    def dispatch(request):
        events.append(('agent', request['action']))
        return agent_envelope(request)

    invoke, _ = agent_boundary(dispatch)

    def fake_run(argv, **kwargs):
        events.append(('playbook',))
        vars_path = Path(argv[argv.index('-e') + 1][1:])
        playbook_vars.append(vars_path)
        (vars_path.parent / 'role-outcome.json').write_text(json.dumps(outcome))
        return completed(0)

    return path, events, playbook_vars, invoke, fake_run


def test_cli_recovers_a_kept_environment_under_a_new_operation(
        execution_spec, tmp_path):
    path, events, playbook_vars, invoke, fake_run = recovery_world(
        execution_spec, tmp_path,
        [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, None)),
         resource_entry(PTF_RESOURCE, 'server-a',
                        reservation_handle(PTF_RESOURCE, None))],
        'kept')
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 0
    assert events == [('agent', 'resume'), ('agent', 'resume'), ('playbook',)]
    payload = json.loads(playbook_vars[0].read_text())
    operation = payload['ranking_operation_id']
    assert operation != 'op-a'
    assert operation.startswith('recover-')
    assert re.fullmatch(r'[A-Za-z0-9_-]+', operation)
    assert payload['ranking_action'] == 'teardown'
    assert payload['ranking_environment_id'] == 'env-a'
    final = read_receipt(path)
    assert final['phase'] == 'released'
    assert final['operation_id'] == operation
    assert final['primary_error'] is None
    assert [entry['released'] for entry in final['resources']] == [True, True]
    assert all(entry['handle']['operation_id'] == operation
               for entry in final['resources'])


def test_cli_verifies_and_recovers_an_active_operation(execution_spec, tmp_path):
    path, events, playbook_vars, invoke, fake_run = recovery_world(
        execution_spec, tmp_path,
        [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
         resource_entry(PTF_RESOURCE, 'server-a',
                        reservation_handle(PTF_RESOURCE, 'op-a'))],
        'prepared')
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 0
    assert events == [('agent', 'validate'), ('agent', 'validate'), ('playbook',)]
    payload = json.loads(playbook_vars[0].read_text())
    assert payload['ranking_operation_id'] == 'op-a'
    final = read_receipt(path)
    assert final['phase'] == 'released'
    assert final['operation_id'] == 'op-a'
    assert [entry['released'] for entry in final['resources']] == [True, True]


def test_cli_tears_down_receipts_without_recorded_resources(
        execution_spec, tmp_path):
    path, events, playbook_vars, invoke, fake_run = recovery_world(
        execution_spec, tmp_path, [], 'prepared')
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke') as agent, \
            patch('tests.ranking.ranking_infra.subprocess.run',
                  side_effect=fake_run):
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 0
    assert agent.call_count == 0
    assert events == [('playbook',)]
    payload = json.loads(playbook_vars[0].read_text())
    assert payload['ranking_operation_id'] == 'op-a'
    assert read_receipt(path)['phase'] == 'released'


@pytest.mark.parametrize('entries, phase', [
    ([resource_entry(DUT_RESOURCE, 'dut-a',
                     reservation_handle(DUT_RESOURCE, 'op-a'), uncertain=True)],
     'prepared'),
    ([resource_entry(DUT_RESOURCE, 'dut-a',
                     reservation_handle(DUT_RESOURCE, 'op-other'))], 'prepared'),
    ([resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, None)),
      resource_entry(PTF_RESOURCE, 'server-a',
                     reservation_handle(PTF_RESOURCE, 'op-a'))], 'kept'),
])
def test_cli_refuses_uncertain_foreign_and_mixed_records(execution_spec, tmp_path,
                                                         entries, phase):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', execution_spec)
    receipt['resources'] = entries
    receipt['phase'] = phase
    update_receipt(path, receipt)
    before = path.read_bytes()
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke') as agent, \
            patch('tests.ranking.ranking_infra.subprocess.run') as run:
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 3
    assert agent.call_count == 0
    assert run.call_count == 0
    assert path.read_bytes() == before


def test_cli_retains_the_environment_after_a_failed_teardown(
        execution_spec, tmp_path):
    path, _, playbook_vars, invoke, _ = recovery_world(
        execution_spec, tmp_path,
        [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
         resource_entry(PTF_RESOURCE, 'server-a',
                        reservation_handle(PTF_RESOURCE, 'op-a'))],
        'prepared')

    def failing_run(argv, **kwargs):
        vars_path = Path(argv[argv.index('-e') + 1][1:])
        playbook_vars.append(vars_path)
        (vars_path.parent / 'role-outcome.json').write_text(json.dumps({
            'schema_version': 1, 'environment_id': 'env-a', 'action': 'teardown',
            'restored': False, 'released': [], 'kept': False, 'uncertain': True}))
        return completed(7, b'out', b'err')

    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run',
                  side_effect=failing_run):
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 1
    final = read_receipt(path)
    assert final['phase'] == 'failed'
    assert final['operation_id'] == 'op-a'
    assert isinstance(final['primary_error'], str) and final['primary_error']
    assert [entry['released'] for entry in final['resources']] == [False, False]
    assert all(entry['uncertain'] for entry in final['resources'])


def test_cli_keeps_the_original_record_when_the_outcome_is_unknown(
        execution_spec, tmp_path):
    path, _, _, invoke, _ = recovery_world(
        execution_spec, tmp_path,
        [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a'))],
        'prepared')
    before = read_receipt(path)
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run',
                  return_value=completed(7, b'out', b'err')):
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 1
    final = read_receipt(path)
    assert final['phase'] == 'failed'
    assert final['primary_error']
    for original, retained in zip(before['resources'], final['resources']):
        assert retained == dict(original, uncertain=True)


def test_cli_retains_uncertainty_when_action_completion_fails_after_release(execution_spec, tmp_path):
    entries = [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
               resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a'))]
    path, _, _, invoke, _ = recovery_world(execution_spec, tmp_path, entries, 'prepared')
    fake_run = playbook_router({'teardown': teardown_outcome()}, rc=7)
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        assert main(['--action', 'teardown', '--receipt', str(path)]) == 1
    receipt = read_receipt(path)
    assert all(entry['released'] and entry['uncertain'] for entry in receipt['resources'])
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke') as agent, \
            patch('tests.ranking.ranking_infra.subprocess.run') as run:
        assert main(['--action', 'teardown', '--receipt', str(path)]) == 3
    agent.assert_not_called()
    run.assert_not_called()


def test_cli_keeps_the_original_record_when_the_playbook_cannot_run(
        execution_spec, tmp_path):
    path, _, _, invoke, _ = recovery_world(
        execution_spec, tmp_path,
        [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a'))],
        'prepared')
    before = path.read_bytes()
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run',
                  side_effect=FileNotFoundError('ansible-playbook')):
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 1
    assert path.read_bytes() == before


@pytest.mark.parametrize('rc, changes, complete', [
    (0, {}, True),
    (7, {}, False),
    (0, {'uncertain': True}, False),
    (0, {'released': [DUT_RESOURCE]}, False),
    (7, {'released': [DUT_RESOURCE]}, False),
    (0, {'restored': False, 'released': []}, False),
    (0, {'restored': False}, False),
    (0, {'environment_id': 'another-environment'}, False),
    (0, {'action': 'keep'}, False),
    (0, {'schema_version': True}, False),
    (0, {'released': [DUT_RESOURCE, DUT_RESOURCE]}, False),
    (0, {'uncertain': 'false'}, False),
    (0, None, False),
    (7, None, False),
])
def test_normal_and_cli_teardown_apply_identical_receipt_rules(
        execution_spec, tmp_path, rc, changes, complete):
    entries = [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
               resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a'))]
    normal, _, _, _, _ = recovery_world(
        execution_spec, tmp_path / 'normal', copy.deepcopy(entries), 'prepared')
    recovery, _, _, invoke, _ = recovery_world(
        execution_spec, tmp_path / 'cli', copy.deepcopy(entries), 'prepared')
    outcome = None if changes is None else dict(teardown_outcome(), **changes)
    fake_run = playbook_router({'teardown': outcome}, rc=rc)
    with patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        if rc == 0 and not complete:
            with pytest.raises(ReceiptError):
                invoke_role('teardown', execution_spec, 'env-a', 'op-a', None,
                            None, str(tmp_path / 'normal-call'), receipt=normal)
        else:
            assert invoke_role('teardown', execution_spec, 'env-a', 'op-a', None,
                               None, str(tmp_path / 'normal-call'), receipt=normal).rc == rc
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        assert main(['--action', 'teardown', '--receipt', str(recovery)]) == (0 if complete else 1)
    assert read_receipt(normal) == read_receipt(recovery)


@pytest.mark.parametrize('malformed', [
    '"restored": false,', '"uncertain": true,',
    '"extra": NaN,', '"extra": Infinity,',
])
def test_both_finalizers_refuse_ambiguous_or_nonfinite_outcome_json(
        execution_spec, tmp_path, malformed):
    entries = [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
               resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a'))]
    normal, _, _, _, _ = recovery_world(
        execution_spec, tmp_path / 'normal', copy.deepcopy(entries), 'prepared')
    recovery, _, _, invoke, _ = recovery_world(
        execution_spec, tmp_path / 'cli', copy.deepcopy(entries), 'prepared')
    raw_outcome = '{' + malformed + json.dumps(teardown_outcome())[1:]

    def fake_run(argv, **kwargs):
        directory = Path(argv[argv.index('-e') + 1][1:]).parent
        (directory / 'role-outcome.json').write_text(raw_outcome)
        return completed(0)

    with patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        with pytest.raises(ReceiptError):
            invoke_role('teardown', execution_spec, 'env-a', 'op-a', None,
                        None, str(tmp_path / 'normal-call'), receipt=normal)
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run', side_effect=fake_run):
        assert main(['--action', 'teardown', '--receipt', str(recovery)]) == 1
    final = read_receipt(normal)
    assert final == read_receipt(recovery)
    assert final['phase'] == 'failed'
    assert all(entry['uncertain'] and not entry['restored'] and not entry['released']
               for entry in final['resources'])


@pytest.mark.parametrize('action, outcome', [
    ('keep', keep_outcome()), ('teardown', teardown_outcome()),
])
def test_normal_cleanup_preserves_the_original_failure(
        execution_spec, tmp_path, action, outcome):
    entries = [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
               resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a'))]
    path, _, _, _, _ = recovery_world(execution_spec, tmp_path, entries, 'prepared')
    receipt = read_receipt(path)
    receipt['primary_error'] = 'original test failure'
    update_receipt(path, receipt)
    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({action: outcome})):
        invoke_role(action, execution_spec, 'env-a', 'op-a', None, None,
                    str(tmp_path / 'cleanup-call'), receipt=path)
    assert read_receipt(path)['primary_error'] == 'original test failure'


def test_normal_keep_records_ended_operations_after_late_failure(execution_spec, tmp_path):
    entries = [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
               resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a'))]
    path, _, _, _, _ = recovery_world(execution_spec, tmp_path, entries, 'prepared')
    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'keep': keep_outcome()}, rc=7)):
        assert invoke_role('keep', execution_spec, 'env-a', 'op-a', None, None,
                           str(tmp_path / 'keep-call'), receipt=path).rc == 7
    final = read_receipt(path)
    assert final['phase'] == 'failed'
    assert all(entry['handle']['operation_id'] is None and entry['uncertain']
               for entry in final['resources'])


def test_cli_finishes_a_normal_partial_release_without_losing_the_primary_error(
        execution_spec, tmp_path):
    entries = [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a')),
               resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a'))]
    path, events, _, invoke, _ = recovery_world(execution_spec, tmp_path, entries, 'prepared')
    receipt = read_receipt(path)
    receipt['primary_error'] = 'original test failure'
    update_receipt(path, receipt)
    partial = dict(teardown_outcome(), released=[DUT_RESOURCE])
    with patch('tests.ranking.ranking_infra.subprocess.run',
               side_effect=playbook_router({'teardown': partial})):
        with pytest.raises(ReceiptError):
            invoke_role('teardown', execution_spec, 'env-a', 'op-a', None, None,
                        str(tmp_path / 'partial-call'), receipt=path)
    partial_receipt = read_receipt(path)
    assert partial_receipt['phase'] == 'failed'
    assert all(entry['restored'] and not entry['uncertain']
               for entry in partial_receipt['resources'])
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run') as run:
        assert main(['--action', 'teardown', '--receipt', str(path)]) == 0
    run.assert_not_called()
    assert events == [('agent', 'validate'), ('agent', 'begin_action'),
                      ('agent', 'release'), ('agent', 'end_action')]
    final = read_receipt(path)
    assert final['phase'] == 'released'
    assert final['primary_error'] == 'original test failure'


def test_cli_releases_attested_remaining_resources_directly(execution_spec,
                                                            tmp_path):
    path, events, playbook_vars, invoke, fake_run = recovery_world(
        execution_spec, tmp_path,
        [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a'),
                        restored=True, released=True),
         resource_entry(PTF_RESOURCE, 'server-a',
                        reservation_handle(PTF_RESOURCE, 'op-a'), restored=True)],
        'failed')
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', invoke), \
            patch('tests.ranking.ranking_infra.subprocess.run',
                  side_effect=fake_run) as run:
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 0
    assert run.call_count == 0
    assert events == [('agent', 'validate'), ('agent', 'begin_action'),
                      ('agent', 'release'), ('agent', 'end_action')]
    assert playbook_vars == []
    final = read_receipt(path)
    assert final['phase'] == 'released'
    assert final['primary_error'] is None
    assert [entry['released'] for entry in final['resources']] == [True, True]


def test_cli_refuses_unattested_remaining_resources(execution_spec, tmp_path):
    path = receipt_file(tmp_path)
    receipt = create_receipt(path, 'env-a', 'op-a', 'setup', execution_spec)
    receipt['resources'] = [
        resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a'),
                       restored=True, released=True),
        resource_entry(PTF_RESOURCE, 'server-a',
                       reservation_handle(PTF_RESOURCE, 'op-a'), restored=False)]
    receipt['phase'] = 'failed'
    update_receipt(path, receipt)
    before = path.read_bytes()
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke') as agent, \
            patch('tests.ranking.ranking_infra.subprocess.run') as run:
        code = main(['--action', 'teardown', '--receipt', str(path)])
    assert code == 3
    assert agent.call_count == 0
    assert run.call_count == 0
    assert path.read_bytes() == before


def test_partial_release_cannot_bypass_an_active_resource_action(execution_spec, tmp_path):
    entries = [resource_entry(DUT_RESOURCE, 'dut-a', reservation_handle(DUT_RESOURCE, 'op-a'),
                              restored=True, released=True),
               resource_entry(PTF_RESOURCE, 'server-a', reservation_handle(PTF_RESOURCE, 'op-a'),
                              restored=True)]
    path, events, _, _, _ = recovery_world(execution_spec, tmp_path, entries, 'kept')

    def dispatch(request):
        events.append(request['action'])
        if request['action'] == 'begin_action':
            raise AgentDispatchError('resource has an unfinished action')
        return agent_envelope(request)
    invoke, _ = agent_boundary(dispatch)
    with patch('tests.ranking.ranking_infra.ansible_agent_invoke', side_effect=invoke):
        result = main(['--action', 'teardown', '--receipt', str(path)])
    assert result == 3
    assert 'release' not in events
