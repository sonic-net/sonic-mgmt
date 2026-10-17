import json
import os
import re
import subprocess
import sys
import uuid
from copy import deepcopy
from pathlib import Path


from tests.ranking.environment_ownership import (
    OwnershipError, _HANDLE_KEYS, _RECORD_KEYS, _invalid_constant, _unique_object,
    _validate_component, _validate_handle, _validate_resource,
)
from tests.ranking.execution_config import build_ptf_request
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
RECEIPT_FILE = 'environment-receipt.json'
RECEIPT_SCHEMA_VERSION = 1
RECEIPT_KEYS = frozenset({
    'schema_version', 'environment_id', 'operation_id', 'action',
    'execution_contract', 'resources', 'phase', 'primary_error', 'cleanup_errors',
})
RESOURCE_ENTRY_KEYS = frozenset({
    'resource', 'host', 'machine_id', 'container_id', 'handle', 'snapshot_path',
    'environment_path', 'identity_hash', 'acquired', 'restored', 'released',
    'uncertain',
})
RECEIPT_PHASES = frozenset({'created', 'prepared', 'kept', 'released', 'failed'})
MACHINE_ID_PATTERN = re.compile(r'[0-9a-f]{32}')
CONTAINER_ID_PATTERN = re.compile(r'[0-9a-f]{64}')
AGENT_MODULE = 'ranking.remote_agent'
REQUEST_ROOT = '/var/tmp/ranking-requests'
ROUTE_KEYS = frozenset({'host', 'inventory', 'agent'})
AGENT_MODULE_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*')
CLI_ACTIONS = frozenset({'teardown'})


class RoleInvocationError(Exception):
    """The playbook runner itself could not be executed; nothing is cleaned up."""


class ReceiptError(Exception):
    """The environment receipt is missing, invalid, or cannot be rewritten."""


class AgentDispatchError(RuntimeError):
    """The Ansible agent boundary could not run or reported a host failure."""


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
    return value


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
        value = json.loads(path.read_text(encoding='utf-8'))
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


def _attested_resource_entry(item, environment_id, operation_id):
    try:
        if not isinstance(item, dict) or set(item) != {'resource', 'host', 'handle'}:
            raise ReceiptError('setup outcome resource entries must declare '
                               'resource, host, and handle')
        resource = _validate_resource(item['resource'])
        host = _single_inventory_alias(item['host'])
        handle = _validated_receipt_handle(item['handle'], resource, environment_id)
    except (ValueError, OwnershipError) as error:
        raise ReceiptError('invalid setup outcome resource entry: {}'.format(
            error)) from error
    if handle['operation_id'] != operation_id:
        raise ReceiptError('attested handle does not match the setup operation')
    parts = resource.split(':')
    return {
        'resource': resource, 'host': host,
        'machine_id': parts[1],
        'container_id': parts[2] if len(parts) == 3 else None,
        'handle': handle, 'snapshot_path': None, 'environment_path': None,
        'identity_hash': None, 'acquired': True, 'restored': False,
        'released': False, 'uncertain': False,
    }


def _record_setup_outcome(receipt_file, result):
    receipt = read_receipt(receipt_file)
    outcome = result.outcome
    resources = outcome.get('resources') if isinstance(outcome, dict) else None
    entries = None
    attestation_error = None
    if isinstance(resources, list) and resources:
        try:
            entries = [_attested_resource_entry(
                item, receipt['environment_id'], receipt['operation_id'])
                       for item in resources]
            entries.sort(key=lambda entry: entry['resource'])
            kinds = [entry['resource'].split(':', 1)[0] for entry in entries]
            if len(entries) != 2 or set(kinds) != {'dut', 'ptf'}:
                raise ReceiptError(
                    'setup must attest exactly one DUT and one PTF reservation')
        except ReceiptError as error:
            attestation_error = str(error)
            entries = None
    if result.rc == 0 and entries is None:
        raise ReceiptError(attestation_error or
                           'successful setup must attest its acquired resources')
    if entries is not None:
        receipt['resources'] = entries
        receipt['phase'] = 'prepared'
    elif result.rc != 0:
        receipt['phase'] = 'failed'
    if result.rc == 0:
        receipt['primary_error'] = None
    else:
        receipt['primary_error'] = 'setup playbook failed with rc {}'.format(
            result.rc)
        if attestation_error is not None:
            receipt['cleanup_errors'].append(
                'setup resource attestation rejected: ' + attestation_error)
    update_receipt(receipt_file, receipt)


def _finalize_receipt(receipt_file, action, result):
    outcome = result.outcome if isinstance(result.outcome, dict) else None
    if result.rc != 0 or outcome is None:
        return
    receipt = read_receipt(receipt_file)
    if receipt['phase'] != 'prepared':
        return
    if action == 'keep':
        if outcome.get('kept') is not True:
            return
        for entry in receipt['resources']:
            if entry['acquired'] and not entry['released'] and \
                    entry['handle'] is not None:
                entry['handle'] = dict(entry['handle'], operation_id=None,
                                       created=False)
                entry['uncertain'] = False
        receipt['phase'] = 'kept'
        receipt['primary_error'] = None
    else:
        released = outcome.get('released')
        if not isinstance(released, list) or outcome.get('restored') is not True:
            return
        for entry in receipt['resources']:
            if entry['acquired'] and not entry['released']:
                entry['restored'] = True
                if entry['resource'] in released:
                    entry['released'] = True
        if any(entry['acquired'] and not entry['released']
               for entry in receipt['resources']):
            return
        receipt['phase'] = 'released'
    update_receipt(receipt_file, receipt)


class Infra:
    """Lifecycle call boundary; every action is forwarded to invoke_role unchanged."""

    def call(self, action, **kwargs) -> RoleResult:
        if action not in PLAYBOOKS:
            raise ValueError('unknown ranking action: {!r}'.format(action))
        return invoke_role(action, **kwargs)


def _receipt_text(receipt):
    try:
        return json.dumps(receipt, sort_keys=True, indent=2, ensure_ascii=True,
                          allow_nan=False) + '\n'
    except (TypeError, ValueError) as error:
        raise ReceiptError('environment receipt must contain strict JSON values') \
            from error


def _single_inventory_alias(host):
    if not isinstance(host, str) or not host:
        raise ValueError('host must be a single inventory alias')
    if ',' in host or any(character.isspace() for character in host):
        raise ValueError('host must be a single inventory alias')
    return host


def _validated_receipt_handle(handle, resource, environment_id):
    if not isinstance(handle, dict) or set(handle) != _HANDLE_KEYS:
        raise ValueError('handle must declare the ownership handle fields')
    if handle['resource'] != resource or \
            handle['environment_id'] != environment_id:
        raise ValueError('handle identity does not match the receipt entry')
    if handle['operation_id'] is not None:
        _validate_component(handle['operation_id'])
    if type(handle['created']) is not bool:
        raise ValueError('handle created flag must be a boolean')
    return handle


def _validate_resource_entry(entry, environment_id):
    if not isinstance(entry, dict) or set(entry) != RESOURCE_ENTRY_KEYS:
        raise ValueError('resource entry must declare the receipt fields exactly')
    resource = _validate_resource(entry['resource'])
    _single_inventory_alias(entry['host'])
    parts = resource.split(':')
    if entry['machine_id'] != parts[1]:
        raise ValueError('machine identity does not match the resource key')
    if len(parts) == 2:
        if entry['container_id'] is not None:
            raise ValueError('DUT entries do not carry a container identity')
    elif entry['container_id'] != parts[2]:
        raise ValueError('container identity does not match the resource key')
    for key in ('snapshot_path', 'environment_path', 'identity_hash'):
        if entry[key] is not None and (not isinstance(entry[key], str) or
                                       not entry[key]):
            raise ValueError('{} must be a path string or null'.format(key))
    for key in ('acquired', 'restored', 'released', 'uncertain'):
        if type(entry[key]) is not bool:
            raise ValueError('{} must be a boolean'.format(key))
    if entry['handle'] is not None:
        _validated_receipt_handle(entry['handle'], resource, environment_id)
    if entry['handle'] is None and entry['acquired']:
        raise ValueError('acquired entries must record a reservation handle')
    return entry


def _validate_receipt(value):
    try:
        if not isinstance(value, dict) or set(value) != RECEIPT_KEYS:
            raise ValueError('environment receipt must declare its fields exactly')
        if type(value['schema_version']) is not int or \
                value['schema_version'] != RECEIPT_SCHEMA_VERSION:
            raise ValueError('unsupported environment receipt schema version')
        environment_id = _validate_component(value['environment_id'])
        _validate_component(value['operation_id'])
        if value['action'] not in ACTIONS:
            raise ValueError('unknown ranking action: {!r}'.format(value['action']))
        if not isinstance(value['execution_contract'], dict) or \
                not value['execution_contract']:
            raise ValueError('execution contract must be the execution inputs object')
        if value['phase'] not in RECEIPT_PHASES:
            raise ValueError('unknown environment receipt phase')
        if value['primary_error'] is not None and (
                not isinstance(value['primary_error'], str) or
                not value['primary_error']):
            raise ValueError('primary error must be a message or null')
        if not isinstance(value['cleanup_errors'], list):
            raise ValueError('cleanup errors must be a list')
        for error in value['cleanup_errors']:
            if not isinstance(error, str) or not error:
                raise ValueError('cleanup errors must be messages')
        if not isinstance(value['resources'], list):
            raise ValueError('resources must be a list of entries')
        for entry in value['resources']:
            _validate_resource_entry(entry, environment_id)
        keys = [entry['resource'] for entry in value['resources']]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            raise ValueError('resources must be ordered by canonical key')
    except (ValueError, OwnershipError) as error:
        raise ReceiptError(str(error)) from error
    return value


def _receipt_identity(environment_id, operation_id, action, execution):
    try:
        _validate_component(environment_id)
        _validate_component(operation_id)
    except ValueError as error:
        raise ReceiptError(str(error)) from error
    if action not in ACTIONS:
        raise ReceiptError('unknown ranking action: {!r}'.format(action))
    if not isinstance(execution, dict) or not execution:
        raise ReceiptError('execution contract must be the execution inputs object')
    return environment_id, operation_id


def create_receipt(path, environment_id, operation_id, action, execution):
    environment_id, operation_id = _receipt_identity(
        environment_id, operation_id, action, execution)
    receipt = {
        'schema_version': RECEIPT_SCHEMA_VERSION,
        'environment_id': environment_id,
        'operation_id': operation_id,
        'action': action,
        'execution_contract': deepcopy(execution),
        'resources': [],
        'phase': 'created',
        'primary_error': None,
        'cleanup_errors': [],
    }
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, mode=0o700)
    except OSError as error:
        raise ReceiptError(
            'environment receipt directory cannot be created: {}'.format(error)) \
            from error
    try:
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ReceiptError(
            'environment receipt already exists: {}'.format(path)) from error
    except OSError as error:
        raise ReceiptError(
            'environment receipt cannot be written: {}'.format(error)) from error
    with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
        handle.write(_receipt_text(receipt))
    return receipt


def read_receipt(path):
    try:
        text = Path(path).read_text(encoding='utf-8')
    except (OSError, UnicodeError) as error:
        raise ReceiptError(
            'environment receipt cannot be read: {}'.format(path)) from error
    try:
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_invalid_constant)
    except ValueError as error:
        raise ReceiptError('environment receipt is not valid strict JSON') from error
    return _validate_receipt(value)


def update_receipt(path, receipt):
    validated = _validate_receipt(receipt)
    path = Path(path)
    if not path.is_file():
        raise ReceiptError('environment receipt is missing: {}'.format(path))
    temporary = path.parent / ('.' + path.name + '-' + uuid.uuid4().hex)
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(_receipt_text(validated))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise ReceiptError(
            'environment receipt cannot be rewritten: {}'.format(error)) from error
    return validated


def _validate_routes(routes):
    if not isinstance(routes, dict):
        raise ValueError('routes must map resources to single-host agent routes')
    validated = {}
    for resource, route in routes.items():
        _validate_resource(resource)
        if not isinstance(route, dict) or set(route) != ROUTE_KEYS:
            raise ValueError('route must declare exactly host, inventory, and agent')
        host = _single_inventory_alias(route['host'])
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
    identity = request['handle'] if 'handle' in request else request
    return '{}/{}/{}-{}.json'.format(
        REQUEST_ROOT, identity['environment_id'], request['action'],
        identity['resource'].replace(':', '-'))


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
        self._receipt = None if receipt is None else Path(receipt)
        if self._receipt is not None:
            read_receipt(self._receipt)

    def invoke_agent(self, route, request):
        request_path = _request_path(request)
        staging_text = json.dumps(request, sort_keys=True,
                                  separators=(',', ':'), allow_nan=False)
        staging_arguments = json.dumps(
            {'content': staging_text, 'dest': request_path, 'mode': '0600'},
            sort_keys=True, separators=(',', ':'), allow_nan=False)
        command_arguments = json.dumps(
            {'argv': ['python3', '-m', route['agent'], '--request', request_path],
             'chdir': REQUEST_ROOT},
            sort_keys=True, separators=(',', ':'), allow_nan=False)
        staging = ['ansible', route['host'], '--inventory', route['inventory'],
                   '--become', '-m', 'ansible.builtin.copy', '-a', staging_arguments]
        command = ['ansible', route['host'], '--inventory', route['inventory'],
                   '--become', '-m', 'ansible.builtin.command', '-a',
                   command_arguments]
        self._invoke(staging)
        return self._invoke(command)

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
        raise AgentDispatchError('Ansible boundary failed with rc {}: {}'.format(
            completed.returncode, detail[-1] if detail else 'no diagnostics'))
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
    if not isinstance(result.outcome, dict):
        _report('teardown rc {} produced no readable outcome; original receipt '
                'retained; artifacts {}'.format(result.rc, artifacts))
        return 1
    receipt = read_receipt(receipt_path)
    released = result.outcome.get('released')
    if not isinstance(released, list):
        _report('teardown outcome does not report released resources; original '
                'receipt retained; artifacts {}'.format(artifacts))
        return 1
    restored = result.outcome.get('restored') is True
    for entry in receipt['resources']:
        if entry['acquired'] and not entry['released']:
            if restored:
                entry['restored'] = True
            if entry['resource'] in released:
                entry['released'] = True
    outstanding = [entry for entry in receipt['resources']
                   if entry['acquired'] and not entry['released']]
    if result.rc == 0 and not outstanding:
        receipt['phase'] = 'released'
        receipt['primary_error'] = None
        update_receipt(receipt_path, receipt)
        _announce('environment {} released; artifacts {}'.format(
            receipt['environment_id'], artifacts))
        return 0
    receipt['phase'] = 'kept'
    receipt['primary_error'] = (
        'teardown failed with rc {}'.format(result.rc) if result.rc != 0
        else 'teardown outcome reports outstanding reservations')
    update_receipt(receipt_path, receipt)
    _report('environment {} retained after teardown; receipt updated; artifacts '
            '{}'.format(receipt['environment_id'], artifacts))
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
        try:
            for entry in remaining:
                client.validate(entry['handle'])
            for entry in remaining:
                client.release_restored(entry['handle'])
        except Exception as error:
            return _refuse(receipt, receipt_path,
                           'remaining reservations failed verification: {}'.format(
                               error))
        fresh = read_receipt(receipt_path)
        fresh['phase'] = 'released'
        fresh['primary_error'] = None
        update_receipt(receipt_path, fresh)
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
