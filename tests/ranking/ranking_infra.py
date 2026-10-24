import json
import os
import re
import subprocess
import sys
import uuid
from copy import deepcopy
from pathlib import Path


from tests.ranking.environment_ownership import (
    _HANDLE_KEYS, _RECORD_KEYS, _invalid_constant, _unique_object,
    _validate_component, _validate_handle, _validate_resource,
)
from tests.ranking.execution_config import build_ptf_request
from tests.ranking.host_transport import HostTransport, request_path
from tests.ranking.receipt_policy import apply_outcome, complete_release, mark_uncertain
from tests.ranking.receipt_store import RECEIPT_FILE, ReceiptError, ReceiptStore, validate_host_alias
from tests.ranking.reservation_coordinator import resume_all


REPO_ROOT = Path(__file__).resolve().parents[2]
ANSIBLE_DIR = REPO_ROOT / 'ansible'
PLAYBOOKS = {
    'setup': 'setup_ranking.yml',
    'status': 'setup_ranking.yml',
    'run': 'run_ranking.yml',
    'teardown': 'teardown_ranking.yml',
    'keep': 'teardown_ranking.yml',
}
ACTIONS = frozenset(PLAYBOOKS)
CASE_NAME_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+')
RUN_ID_PATTERN = re.compile(r'[A-Za-z0-9_-]+')
VARS_FILE = 'role-vars.json'
STDOUT_LOG = 'role-stdout.log'
STDERR_LOG = 'role-stderr.log'
OUTCOME_FILE = 'role-outcome.json'
MACHINE_ID_PATTERN = re.compile(r'[0-9a-f]{32}')
CONTAINER_ID_PATTERN = re.compile(r'[0-9a-f]{64}')
AGENT_MODULE = 'ranking.remote_agent'
REQUEST_ROOT = '/var/tmp/ranking-requests'
ROUTE_KEYS = frozenset({'host', 'inventory', 'agent'})
AGENT_MODULE_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*')
CLI_ACTIONS = frozenset({'teardown'})


class RoleInvocationError(Exception):
    """The playbook runner itself could not be executed; nothing is cleaned up."""


class AgentDispatchError(RuntimeError):
    """The Ansible agent boundary could not run or reported a host failure."""

    def __init__(self, message, *, uncertain=True):
        self.uncertain = uncertain
        super().__init__(message)


class AgentResponseError(RuntimeError):
    """The agent response does not match the dispatched request."""


class RoleResult:
    __slots__ = ('rc', 'outcome')

    def __init__(self, rc, outcome):
        self.rc = rc
        self.outcome = outcome

    def __repr__(self):
        return 'RoleResult(rc={!r}, outcome={!r})'.format(self.rc, self.outcome)


def _ptf_interfaces(port_mapping):
    if not isinstance(port_mapping, list):
        raise ValueError('execution inputs are missing a port mapping')
    interfaces = []
    for row in port_mapping:
        if not isinstance(row, dict) or 'ptf_port_id' not in row or 'ptf_interface' not in row:
            raise ValueError('port mapping rows must declare PTF endpoints')
        interfaces.append({'id': row['ptf_port_id'], 'name': row['ptf_interface']})
    return interfaces


def _execution_fields(execution):
    if not isinstance(execution, dict):
        raise ValueError('execution must be the validated execution inputs')
    try:
        inventory = execution['runtime']['inventory']
        inner = execution['execution']
        dut_host = inner['dut_host']
        ptf_host = inner['ptf_host']
        runtime = execution['runtime']
        source_hash = execution['source_hash']
        mapping_hash = execution['mapping_hash']
        profile_hash = execution['profile_hash']
        source_identity = execution['source_identity']
        port_mapping = execution['port_mapping']
        pipeline_dir = execution['pipeline_dir']
        runner_path = execution['runner_path']
    except (KeyError, TypeError) as error:
        raise ValueError('execution inputs are missing runtime or execution fields') from error
    if not isinstance(inventory, str) or not inventory:
        raise ValueError('runtime inventory must be a path string')
    if not isinstance(dut_host, str) or not isinstance(ptf_host, str):
        raise ValueError('execution hosts must be inventory aliases')
    if not isinstance(profile_hash, str) or not isinstance(source_identity, dict):
        raise ValueError('execution inputs are missing profile or source identity')
    if not isinstance(pipeline_dir, str) or not pipeline_dir:
        raise ValueError('execution inputs are missing the validated pipeline directory')
    if not isinstance(runner_path, str) or not runner_path:
        raise ValueError('execution inputs are missing the validated PTF runner')
    return (inventory, inner, dut_host, ptf_host, runtime, source_hash, mapping_hash,
            profile_hash, source_identity, port_mapping, pipeline_dir, runner_path)


def _identity(value, description):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('{} must be a non-empty identifier'.format(description))
    return _validate_component(value)


def _single_alias(host):
    if not host:
        raise ValueError('dut_host must be a single inventory alias')
    if ',' in host or any(character.isspace() for character in host):
        raise ValueError('dut_host must be a single inventory alias')
    return host


def _validate_invocation(action, execution, environment_id, operation_id, case, run_id):
    if action not in PLAYBOOKS:
        raise ValueError('unknown ranking action: {!r}'.format(action))
    fields = _execution_fields(execution)
    inventory, inner, dut_host, _, _, _, _, _, _, _, _, _ = fields
    _identity(environment_id, 'environment_id')
    _identity(operation_id, 'operation_id')
    if action in ('setup', 'teardown'):
        _single_alias(dut_host)
    if action == 'run':
        if not isinstance(case, str) or CASE_NAME_PATTERN.fullmatch(case) is None:
            raise ValueError("run action requires a case name like 'module.Class'")
        if not isinstance(run_id, str) or RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise ValueError('run action requires a plain run identifier')
    elif case is not None or run_id is not None:
        raise ValueError('{} action must not pass case or run_id'.format(action))
    return fields


def _payload(action, execution, environment_id, operation_id, case, run_id, artifacts,
             fields):
    _, inner, dut_host, ptf_host, runtime, source_hash, mapping_hash, profile_hash, \
        source_identity, port_mapping, pipeline_dir, runner_path = fields
    payload = {
        'ranking_action': action,
        'ranking_environment_id': environment_id,
        'ranking_operation_id': operation_id,
        'ranking_action_id': 'action-' + uuid.uuid4().hex,
        'ranking_case': case,
        'ranking_run_id': run_id,
        'ranking_dut_host': dut_host,
        'ranking_ptf_host': ptf_host,
        'ranking_execution': deepcopy(inner),
        'ranking_runtime': deepcopy(runtime),
        'ranking_source_hash': deepcopy(source_hash),
        'ranking_mapping_hash': deepcopy(mapping_hash),
        'ranking_profile_hash': deepcopy(profile_hash),
        'ranking_source_identity': deepcopy(source_identity),
        'ranking_ptf_interfaces': _ptf_interfaces(port_mapping),
        'ranking_pipeline_dir': pipeline_dir,
        'ranking_runner_path': runner_path,
        'ranking_artifacts_dir': str(artifacts),
    }
    if action == 'run':
        payload['ranking_ptf_request'] = build_ptf_request(
            execution, environment_id, case, run_id)
    return payload


def _artifacts_dir(artifacts):
    try:
        path = Path(artifacts)
    except TypeError as error:
        raise ValueError('artifacts must be a local directory path') from error
    if os.path.lexists(path):
        raise ValueError('artifacts directory must not already exist')
    try:
        path.mkdir(parents=True)
    except OSError as error:
        raise ValueError('artifacts directory cannot be created: {}'.format(error)) from error
    return path


def build_playbook_argv(action, execution, environment_id, operation_id, case, run_id,
                        artifacts) -> list:
    if action not in PLAYBOOKS:
        raise ValueError('unknown ranking action: {!r}'.format(action))
    inventory, _, dut_host, _, _, _, _, _, _, _, _, _ = _execution_fields(execution)
    try:
        vars_path = Path(artifacts) / VARS_FILE
    except TypeError as error:
        raise ValueError('artifacts must be a local directory path') from error
    playbook = ANSIBLE_DIR / PLAYBOOKS[action]
    return ['ansible-playbook', '-i', inventory, str(playbook), '--limit', dut_host,
            '-e', '@' + str(vars_path)]


def _bytes(data):
    if data is None:
        return b''
    if isinstance(data, bytes):
        return data
    return data.encode('utf-8')


def _read_outcome(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'),
                           object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
    except (OSError, ValueError, UnicodeError):
        return None
    return value if isinstance(value, dict) else None


def invoke_role(action, execution, environment_id, operation_id, case, run_id,
                artifacts, receipt=None) -> RoleResult:
    fields = _validate_invocation(action, execution, environment_id, operation_id,
                                  case, run_id)
    receipt_file = _finalizer_receipt(receipt, action, environment_id)
    payload = _payload(action, execution, environment_id, operation_id, case, run_id,
                       artifacts, fields)
    try:
        text = json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=True,
                          allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError('role payload must contain strict JSON values') from error
    directory = _artifacts_dir(artifacts)
    vars_path = directory / VARS_FILE
    descriptor = os.open(
        vars_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write(text)
    setup_receipt = None
    if action == 'setup':
        setup_receipt = directory / environment_id / RECEIPT_FILE
        create_receipt(setup_receipt, environment_id, operation_id, action, execution)
    argv = build_playbook_argv(action, execution, environment_id, operation_id, case,
                               run_id, str(directory))
    try:
        completed = subprocess.run(argv, shell=False, cwd=str(ANSIBLE_DIR),
                                   capture_output=True, check=False)
    except OSError as error:
        raise RoleInvocationError(
            'ansible-playbook could not be executed: {}'.format(error)) from error
    (directory / STDOUT_LOG).write_bytes(_bytes(completed.stdout))
    (directory / STDERR_LOG).write_bytes(_bytes(completed.stderr))
    outcome = _read_outcome(directory / OUTCOME_FILE)
    result = RoleResult(completed.returncode, outcome)
    if setup_receipt is not None:
        _record_setup_outcome(setup_receipt, result)
    if receipt_file is not None:
        _finalize_receipt(receipt_file, action, result)
    return result


def _finalizer_receipt(receipt, action, environment_id):
    if receipt is None:
        return None
    if action not in ('keep', 'teardown'):
        raise ValueError('receipt finalization applies only to keep or teardown')
    path = Path(receipt)
    stored = read_receipt(path)
    if stored['environment_id'] != environment_id:
        raise ReceiptError(
            'receipt does not belong to environment {}'.format(environment_id))
    return path


def _apply_role_outcome(receipt_file, action, result):
    receipt = read_receipt(receipt_file)
    decision = apply_outcome(receipt, action, result.rc, result.outcome)
    if decision.receipt != receipt:
        update_receipt(receipt_file, decision.receipt)
    return decision


def _record_setup_outcome(receipt_file, result):
    decision = _apply_role_outcome(receipt_file, 'setup', result)
    if result.rc == 0 and not decision.complete:
        raise ReceiptError(decision.reason)


def _finalize_receipt(receipt_file, action, result):
    decision = _apply_role_outcome(receipt_file, action, result)
    if result.rc == 0 and not decision.complete:
        raise ReceiptError(decision.reason)


class Infra:
    """Lifecycle call boundary; every action is forwarded to invoke_role unchanged."""

    def call(self, action, **kwargs) -> RoleResult:
        if action not in PLAYBOOKS:
            raise ValueError('unknown ranking action: {!r}'.format(action))
        return invoke_role(action, **kwargs)


def create_receipt(path, environment_id, operation_id, action, execution):
    return ReceiptStore(path).create(environment_id, operation_id, action, execution)


def read_receipt(path):
    return ReceiptStore(path).load()


def update_receipt(path, receipt):
    return ReceiptStore(path).save(receipt)


def _validate_routes(routes):
    if not isinstance(routes, dict):
        raise ValueError('routes must map resources to single-host agent routes')
    validated = {}
    for resource, route in routes.items():
        _validate_resource(resource)
        if not isinstance(route, dict) or set(route) != ROUTE_KEYS:
            raise ValueError('route must declare exactly host, inventory, and agent')
        host = validate_host_alias(route['host'])
        inventory = route['inventory']
        agent = route['agent']
        if not isinstance(inventory, str) or not inventory:
            raise ValueError('route inventory must be a path string')
        if not isinstance(agent, str) or \
                AGENT_MODULE_PATTERN.fullmatch(agent) is None:
            raise ValueError('route agent must be a module name')
        validated[resource] = {'host': host, 'inventory': inventory, 'agent': agent}
    return validated


def _request_path(request):
    return request_path(request)


def _envelope_result(envelope, action):
    if not isinstance(envelope, dict):
        raise AgentResponseError('agent response must be an envelope object')
    if envelope.get('schema_version') != 1:
        raise AgentResponseError('agent response schema is not supported')
    if envelope.get('action') != action:
        raise AgentResponseError(
            'agent response action does not match the dispatch')
    result = envelope.get('result')
    if not isinstance(result, dict):
        raise AgentResponseError('agent response result must be an object')
    return result


def _dispatched_handle(result, resource, environment_id, operation_id, created):
    if set(result) != _HANDLE_KEYS:
        raise AgentResponseError('agent response does not carry a reservation handle')
    if (result['resource'] != resource or
            result['environment_id'] != environment_id or
            result['operation_id'] != operation_id or
            result['created'] is not created):
        raise AgentResponseError('agent handle does not match the dispatched identity')
    return dict(result)


def _dispatched_record(result, handle):
    if set(result) != _RECORD_KEYS:
        raise AgentResponseError('agent response does not carry an ownership record')
    if (result['resource'] != handle['resource'] or
            result['environment_id'] != handle['environment_id'] or
            result['operation_id'] != handle['operation_id']):
        raise AgentResponseError('ownership record does not match the handle')
    return dict(result)


class HostReservationClient:
    """Coordinator protocol client speaking to hosts over the Ansible boundary."""

    def __init__(self, routes, invoke, receipt=None):
        self._routes = _validate_routes(routes)
        if not callable(invoke):
            raise ValueError('invoke must be a callable Ansible boundary')
        self._invoke = invoke
        self._transport = HostTransport(invoke)
        self._receipt = None if receipt is None else Path(receipt)
        if self._receipt is not None:
            read_receipt(self._receipt)

    def invoke_agent(self, route, request):
        return self._transport.invoke_agent(route, request)

    def claim(self, resource, environment_id, operation_id):
        return self._acquire('claim', resource, environment_id, operation_id, True)

    def resume(self, resource, environment_id, operation_id):
        return self._acquire('resume', resource, environment_id, operation_id, False)

    def keep(self, handle):
        return self._transition('keep', handle, ended=True)

    def abort_unmodified(self, handle):
        return self._transition('abort', handle, released=True)

    def release_restored(self, handle):
        return self._transition('release', handle, released=True)

    def validate(self, handle):
        handle = _validate_handle(handle)
        route = self._route(handle['resource'])
        self._guard_released(handle['resource'])
        envelope = self.invoke_agent(route, {'action': 'validate',
                                             'handle': dict(handle)})
        return _dispatched_record(_envelope_result(envelope, 'validate'), handle)

    def begin_action(self, handle, action_id):
        handle = _validate_handle(handle)
        _validate_component(action_id)
        self._guard_released(handle['resource'])
        envelope = self.invoke_agent(self._route(handle['resource']), {
            'action': 'begin_action', 'handle': handle, 'action_id': action_id})
        return _dispatched_handle(_envelope_result(envelope, 'begin_action'),
                                  handle['resource'], handle['environment_id'], action_id, True)

    def end_action(self, guard):
        guard = _validate_handle(guard)
        envelope = self.invoke_agent(self._route(guard['resource']), {
            'action': 'end_action', 'handle': guard})
        if _envelope_result(envelope, 'end_action') != {}:
            raise AgentResponseError('action completion response must be empty')

    def _route(self, resource):
        _validate_resource(resource)
        try:
            return self._routes[resource]
        except KeyError as error:
            raise ValueError('no route is mapped for resource: ' + resource) from error

    def _acquire(self, action, resource, environment_id, operation_id, created):
        _validate_component(environment_id)
        _validate_component(operation_id)
        route = self._route(resource)
        self._guard_released(resource)
        request = {'action': action, 'resource': resource,
                   'environment_id': environment_id, 'operation_id': operation_id}
        self._pending(resource, route)
        envelope = self.invoke_agent(route, request)
        handle = _dispatched_handle(_envelope_result(envelope, action), resource,
                                    environment_id, operation_id, created)
        self._acknowledge(resource, lambda entry: entry.update(
            handle=handle, acquired=True, uncertain=False))
        return handle

    def _transition(self, action, handle, *, ended=False, released=False):
        handle = _validate_handle(handle)
        route = self._route(handle['resource'])
        self._guard_released(handle['resource'])
        self._pending(handle['resource'], route)
        envelope = self.invoke_agent(route, {'action': action, 'handle': dict(handle)})
        if _envelope_result(envelope, action) != {}:
            raise AgentResponseError(
                'agent {} response must be empty'.format(action))
        if ended:
            ended_handle = dict(handle, operation_id=None, created=False)
            self._acknowledge(handle['resource'], lambda entry: entry.update(
                handle=ended_handle, uncertain=False))
        else:
            self._acknowledge(handle['resource'], lambda entry: entry.update(
                released=True, uncertain=False))
        return {}

    def _guard_released(self, resource):
        if self._receipt is None:
            return
        for entry in read_receipt(self._receipt)['resources']:
            if entry['resource'] == resource and entry['released']:
                raise ValueError('resource is already released: ' + resource)

    def _pending(self, resource, route):
        if self._receipt is None:
            return
        receipt = read_receipt(self._receipt)
        if not any(entry['resource'] == resource for entry in receipt['resources']):
            parts = resource.split(':')
            receipt['resources'].append({
                'resource': resource, 'host': route['host'],
                'machine_id': parts[1],
                'container_id': parts[2] if len(parts) == 3 else None,
                'handle': None, 'snapshot_path': None, 'environment_path': None,
                'identity_hash': None, 'acquired': False, 'restored': False,
                'released': False, 'uncertain': True})
            receipt['resources'].sort(key=lambda entry: entry['resource'])
        for entry in receipt['resources']:
            if entry['resource'] == resource:
                entry['uncertain'] = True
        update_receipt(self._receipt, receipt)

    def _acknowledge(self, resource, apply):
        if self._receipt is None:
            return
        receipt = read_receipt(self._receipt)
        for entry in receipt['resources']:
            if entry['resource'] == resource:
                apply(entry)
                update_receipt(self._receipt, receipt)
                return
        raise ReceiptError('receipt entry disappeared during acknowledgement: ' +
                           resource)


def ansible_agent_invoke(argv):
    """Run one adhoc Ansible argv and return the parsed agent response envelope."""
    if not isinstance(argv, list) or not argv or \
            not all(isinstance(token, str) for token in argv):
        raise AgentDispatchError('Ansible boundary requires a literal argv list')
    try:
        completed = subprocess.run(argv, shell=False, capture_output=True,
                                   check=False)
    except OSError as error:
        raise AgentDispatchError(
            'Ansible boundary could not be executed: {}'.format(error)) from error
    if completed.returncode != 0:
        detail = completed.stderr.decode('utf-8', 'replace').strip().splitlines()
        stdout = completed.stdout.decode('utf-8', 'replace')
        confirmed_exit = re.search(r'\| FAILED \| rc=\d+ >>', stdout) is not None
        raise AgentDispatchError('Ansible boundary failed with rc {}: {}'.format(
            completed.returncode, detail[-1] if detail else 'no diagnostics'),
            uncertain=not confirmed_exit)
    if '-m' in argv and argv[argv.index('-m') + 1] in (
            'ansible.builtin.copy', 'ansible.builtin.file'):
        return {}
    return _parse_agent_envelope(completed.stdout)


def _parse_agent_envelope(stdout):
    text = stdout.decode('utf-8', 'replace')
    marker = text.rfind('>>')
    payload = text[marker + 2:].strip() if marker >= 0 else text.strip()
    try:
        envelope = json.loads(payload, object_pairs_hook=_unique_object,
                              parse_constant=_invalid_constant)
    except ValueError as error:
        raise AgentResponseError(
            'agent response could not be parsed from Ansible output') from error
    if not isinstance(envelope, dict):
        raise AgentResponseError('agent response must be an envelope object')
    return envelope


def _cli_arguments(argv):
    if argv is None:
        argv = sys.argv[1:]
    if not isinstance(argv, (list, tuple)):
        raise ValueError('ranking CLI arguments must be a list')
    action = None
    receipt = None
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in ('--action', '--receipt'):
            if index + 1 >= len(argv):
                raise ValueError('{} requires a value'.format(token))
            option, value = token, argv[index + 1]
            index += 2
        elif token.startswith('--action=') or token.startswith('--receipt='):
            option, _, value = token.partition('=')
            index += 1
        else:
            raise ValueError('unknown ranking CLI argument: {!r}'.format(token))
        if option == '--action':
            if action is not None:
                raise ValueError('--action must be given once')
            action = value
        else:
            if receipt is not None:
                raise ValueError('--receipt must be given once')
            receipt = value
    if action not in CLI_ACTIONS:
        raise ValueError('ranking CLI recovery supports only --action teardown')
    if not receipt:
        raise ValueError('ranking CLI recovery requires --receipt <path>')
    return action, receipt


def _report(message):
    sys.stderr.write('ranking-recovery: {}\n'.format(message))


def _announce(message):
    sys.stdout.write('ranking-recovery: {}\n'.format(message))


def _refuse(receipt, receipt_path, reason):
    _report('refused to recover environment {}: {}; receipt retained at {}'.format(
        receipt['environment_id'], reason, receipt_path))
    return 3


def _record_recovery_outcome(receipt_path, result, artifacts):
    decision = _apply_role_outcome(receipt_path, 'teardown', result)
    if decision.complete:
        _announce('environment {} released; artifacts {}'.format(
            decision.receipt['environment_id'], artifacts))
        return 0
    _report('teardown incomplete: {}; receipt retained at {}; artifacts {}'.format(
        decision.reason, receipt_path, artifacts))
    return 1


def _recover_teardown(receipt_path):
    receipt = read_receipt(receipt_path)
    entries = list(receipt['resources'])
    environment_id = receipt['environment_id']
    if any(entry['uncertain'] for entry in entries):
        return _refuse(receipt, receipt_path, 'a recorded reservation is uncertain')
    remaining = [entry for entry in entries
                 if entry['acquired'] and not entry['released']]
    for entry in remaining:
        operation = entry['handle']['operation_id']
        if operation is not None and operation != receipt['operation_id']:
            return _refuse(receipt, receipt_path, 'resource {} is held by another '
                           'operation'.format(entry['resource']))
    ended = {entry['handle']['operation_id'] is None for entry in remaining}
    if len(ended) > 1:
        return _refuse(receipt, receipt_path,
                       'retained reservations mix ended and active operations')
    try:
        inventory = _execution_fields(receipt['execution_contract'])[0]
    except ValueError as error:
        _report(str(error))
        return 2
    routes = {entry['resource']: {'host': entry['host'], 'inventory': inventory,
                                  'agent': AGENT_MODULE}
              for entry in remaining}
    client = HostReservationClient(routes, ansible_agent_invoke, receipt=receipt_path)
    if any(entry['released'] for entry in entries):
        if not all(entry['restored'] for entry in remaining):
            return _refuse(receipt, receipt_path,
                           'a retained reservation was not attested restored')
        guards = []
        action_id = 'action-recovery-' + uuid.uuid4().hex
        try:
            for entry in remaining:
                client.validate(entry['handle'])
            for entry in remaining:
                guards.append(client.begin_action(entry['handle'], action_id))
            for entry in remaining:
                client.release_restored(entry['handle'])
        except Exception as error:
            uncertain = (isinstance(error, AgentResponseError) or
                         isinstance(error, AgentDispatchError) and error.uncertain)
            if not uncertain:
                for guard in reversed(guards):
                    try:
                        client.end_action(guard)
                    except Exception:
                        uncertain = True
                        break
            if uncertain:
                stored = mark_uncertain(
                    read_receipt(receipt_path),
                    {item['resource'] for item in remaining},
                    'action {} has an uncertain result; guards retained'.format(action_id))
                update_receipt(receipt_path, stored)
            return _refuse(receipt, receipt_path,
                           'remaining reservations failed verification: {}'.format(error))
        try:
            for guard in reversed(guards):
                client.end_action(guard)
        except Exception as error:
            stored = mark_uncertain(
                read_receipt(receipt_path), {guard['resource'] for guard in guards},
                'action {} completion is uncertain: {}'.format(action_id, error))
            update_receipt(receipt_path, stored)
            return _refuse(stored, receipt_path, 'action guard completion is uncertain')
        decision = complete_release(read_receipt(receipt_path))
        update_receipt(receipt_path, decision.receipt)
        if not decision.complete:
            return _refuse(decision.receipt, receipt_path, decision.reason)
        _announce('environment {} released'.format(environment_id))
        return 0
    operation = receipt['operation_id']
    if ended == {True}:
        operation = 'recover-' + uuid.uuid4().hex
        try:
            resume_all([entry['resource'] for entry in remaining], environment_id,
                       operation, client)
        except Exception as error:
            return _refuse(receipt, receipt_path,
                           'resume of the retained reservations failed: {}'.format(
                               error))
        fresh = read_receipt(receipt_path)
        fresh['operation_id'] = operation
        update_receipt(receipt_path, fresh)
    elif ended == {False}:
        try:
            for entry in remaining:
                client.validate(entry['handle'])
        except Exception as error:
            return _refuse(receipt, receipt_path,
                           'remaining reservations failed verification: {}'.format(
                               error))
    artifacts = receipt_path.parent / ('recovery-' + uuid.uuid4().hex)
    try:
        result = invoke_role('teardown', receipt['execution_contract'], environment_id,
                             operation, None, None, str(artifacts))
    except RoleInvocationError as error:
        _report('teardown could not be executed; original receipt retained: '
                '{}'.format(error))
        return 1
    except ValueError as error:
        _report(str(error))
        return 2
    return _record_recovery_outcome(receipt_path, result, artifacts)


def main(argv=None) -> int:
    try:
        _, receipt_argument = _cli_arguments(argv)
    except ValueError as error:
        _report(str(error))
        return 2
    try:
        return _recover_teardown(Path(receipt_argument))
    except (ReceiptError, ValueError) as error:
        _report(str(error))
        return 2


if __name__ == '__main__':
    sys.exit(main())
