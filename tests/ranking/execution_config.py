import hashlib
import json
import math
import os
import re
import stat
from copy import deepcopy
from pathlib import PurePosixPath

from tests.ranking.case_selection import (
    _load_json, _validate_source_identity, select_ranking_cases,
)
from tests.ranking.port_mapping import (
    DECIMAL_PATTERN, PHYSICAL_ROW_FIELDS, VIRTUAL_ROW_FIELDS, _lanes,
    _port_table, _validate_mapping, interface_args,
)
from tests.ranking.prepare_inputs import SCHEMA_VERSION, _mapping_hash, _validated_selector
from tests.ranking.ptf_params import serialize_test_params
from tests.ranking.runtime_config import (
    PROTECTED_DESTINATIONS, _argv, _identifier, _reject_credentials, _text,
    validate_runtime_config,
)


BUNDLE_FIELDS = frozenset((
    'schema_version', 'runtime', 'selector', 'selected_cases',
    'interface_args', 'mapping_hash', 'source_identity', 'manifest',
))
ASSEMBLED_FIELDS = BUNDLE_FIELDS | frozenset((
    'input_dir', 'port_mapping', 'ptf_config_db',
))
EXECUTION_FIELDS = frozenset((
    'dut_host', 'ptf_host', 'rpc_host', 'profile_id', 'ptf_argv',
    'test_params', 'env', 'binding_dir', 'prebuilt_dir', 'dut_files',
))
CONTRACT_FIELDS = frozenset((
    'schema_version', 'source_identity', 'rpc_port', 'requires_dut_credentials',
    'switch_owner', 'dataplane_validation',
))
RESERVED_TEST_PARAMS = frozenset((
    'thrift_server', 'rpc_port', 'config_db_json', 'port_config_ini', 'result_output_dir',
    'host_control_container', 'asic_container', 'test_reboot_mode', 'test_reboot_stage',
    'dut_os', 'host_control_user', 'host_control_identity_file', 'host_control_known_hosts',
    'vsonic_dataplane_ready_timeout_s', 'vsonic_connected_port_count',
    'vsonic_saiserver_container',
))
INTERNAL_PTF_CONTAINER_TOKEN = '{ptf_container_id}'
INTERNAL_SAISERVER_CONTAINER_TOKEN = '{saiserver_container_id}'
SSH_SECRET_DIR = 'secrets'
SSH_IDENTITY_NAME = 'dut_identity'
SSH_KNOWN_HOSTS_NAME = 'known_hosts'
LAUNCHER_FIELDS = frozenset((
    'saiserver_container', 'saiserver_image_id', 'saiserver_container_id',
))
ENV_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
RPC_HOST_PATTERN = re.compile(r'[A-Za-z0-9_.:\[\]-]+')
IMAGE_ID_PATTERN = re.compile(r'sha256:[0-9a-f]{64}')
CONTAINER_ID_PATTERN = re.compile(r'[0-9a-f]{64}')


def _exact_object(value, fields, description):
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('{} must have exact fields: {}'.format(
            description, ', '.join(sorted(fields))))


def _canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError('config must contain finite JSON values') from error


def _digest(value):
    return hashlib.sha256(_canonical(value).encode('utf-8')).hexdigest()


def _strict_json(path, description):
    value = _load_json(path, description)
    _canonical(value)
    return value


def _canonical_path(value, description):
    try:
        path = os.fspath(value)
    except TypeError as error:
        raise ValueError('{} must be a local path'.format(description)) from error
    _text(path, description)
    if ('\\' in path or not os.path.isabs(path) or path.startswith('//')
            or os.path.normpath(path) != path):
        raise ValueError('{} must be an absolute canonical path'.format(description))
    return path


def _local_source(value, description, directory=False):
    path = _canonical_path(value, description)
    if os.path.realpath(path) != path:
        raise ValueError('{} must not contain symlinks'.format(description))
    try:
        mode = os.lstat(path).st_mode
    except OSError as error:
        raise ValueError('cannot access {}: {}'.format(description, error)) from error
    expected = stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)
    if not expected:
        raise ValueError('{} must be an existing {}'.format(
            description, 'directory' if directory else 'regular file'))
    return path


def _artifact_path(value):
    path = _canonical_path(value, 'artifact_dir')
    if os.path.lexists(path):
        raise ValueError('artifact_dir must not already exist')
    _local_source(os.path.dirname(path), 'artifact_dir parent', directory=True)
    return path


def _checked_ports(mapping, ptf_config_db):
    _validate_mapping(mapping)
    ports = _port_table(ptf_config_db)
    if list(ports) != [row['dut_port'] for row in mapping]:
        raise ValueError('PORT must match exact mapping selection order')
    for row in mapping:
        if _lanes(ports[row['dut_port']].get('lanes')) != row['lanes']:
            raise ValueError('PORT lanes must match mapping lanes')
    return ports


def _port_integer(value, description, minimum):
    if isinstance(value, str) and DECIMAL_PATTERN.fullmatch(value):
        number = int(value)
    elif type(value) is int:
        number = value
    else:
        raise ValueError('{} must be an integer or numeric string'.format(description))
    if number < minimum:
        raise ValueError('{} must be at least {}'.format(description, minimum))
    return str(value)


def render_port_config(mapping, ptf_config_db) -> str:
    ports = _checked_ports(mapping, ptf_config_db)
    rows = ['# name lanes index speed']
    for row in mapping:
        entry = ports[row['dut_port']]
        index = _port_integer(entry.get('index'), 'PORT index', 0)
        speed = _port_integer(entry.get('speed'), 'PORT speed', 1)
        rows.append('{} {} {} {}'.format(
            row['dut_port'], ','.join(str(lane) for lane in row['lanes']), index, speed))
    return '\n'.join(rows) + '\n'


def _launcher_tokens(argv):
    _argv(argv, 'launcher argv')
    allowed = {'{' + field + '}': field for field in LAUNCHER_FIELDS}
    tokens = {}
    for argument in argv:
        if '{' not in argument and '}' not in argument:
            continue
        if argument not in allowed:
            raise ValueError('unknown or malformed launcher token: {}'.format(argument))
        tokens[argument] = allowed[argument]
    return tokens


def bind_launcher_argv(argv, values) -> list[str]:
    tokens = _launcher_tokens(argv)
    if not isinstance(values, dict):
        raise ValueError('launcher values must be an object')
    _reject_credentials(values)
    if set(values).difference(LAUNCHER_FIELDS):
        raise ValueError('unknown launcher binding fields')
    for field in tokens.values():
        if field not in values:
            raise ValueError('missing launcher binding: {}'.format(field))
        value = values[field]
        if field == 'saiserver_container':
            _identifier(value, field)
        else:
            pattern = IMAGE_ID_PATTERN if field == 'saiserver_image_id' else CONTAINER_ID_PATTERN
            if not isinstance(value, str) or not pattern.fullmatch(value):
                raise ValueError('invalid launcher binding: {}'.format(field))
    return [values[tokens[argument]] if argument in tokens else argument for argument in argv]


def _without_controls(value, description):
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ValueError('{} must not contain control characters'.format(description))


def _scalar_values(value, description, environment=False):
    if not isinstance(value, dict):
        raise ValueError('{} must be an object'.format(description))
    _reject_credentials(value)
    for key, item in value.items():
        _text(key, description + ' key')
        _without_controls(key, description + ' key')
        if environment:
            if not ENV_PATTERN.fullmatch(key) or not isinstance(item, str):
                raise ValueError('env requires environment identifiers and string values')
        elif type(item) not in (str, int, float, bool, type(None)):
            raise ValueError('test_params values must be JSON scalars')
        if isinstance(item, str):
            _without_controls(item, description)
        if type(item) is float and not math.isfinite(item):
            raise ValueError('{} values must be finite'.format(description))
    if not environment:
        serialize_test_params(value)


def _reject_internal_ptf_tokens(values, description):
    for value in values:
        if isinstance(value, str) and (INTERNAL_PTF_CONTAINER_TOKEN in value or
                                       INTERNAL_SAISERVER_CONTAINER_TOKEN in value):
            raise ValueError('{} cannot contain internal container tokens'.format(
                description))


def _docker_exec_argv(argv, ptf_container):
    if len(argv) < 2 or os.path.basename(argv[0]) != 'docker' or argv[1] != 'exec':
        return False
    if len(argv) < 4 or argv[2] != ptf_container:
        raise ValueError(
            'docker exec ptf_argv must be docker exec <runtime.ptf_container> <command>')
    return True


def _validate_execution(runtime):
    execution = runtime['execution']
    _exact_object(execution, EXECUTION_FIELDS, 'execution')
    for field in ('dut_host', 'ptf_host', 'profile_id'):
        _identifier(execution[field], field)
    if execution['dut_host'] != runtime['dut_id'] or execution['dut_host'] != runtime['dut_limit']:
        raise ValueError('execution dut_host must equal dut_id and dut_limit')
    if execution['ptf_host'] != runtime['ptf_host_id']:
        raise ValueError('execution ptf_host must equal ptf_host_id')
    _text(execution['rpc_host'], 'rpc_host')
    if not RPC_HOST_PATTERN.fullmatch(execution['rpc_host']):
        raise ValueError('rpc_host must be a management address without credentials')
    _argv(execution['ptf_argv'], 'ptf_argv')
    _reject_internal_ptf_tokens(execution['ptf_argv'], 'ptf_argv')
    _docker_exec_argv(execution['ptf_argv'], runtime['ptf_container'])
    _scalar_values(execution['test_params'], 'test_params')
    if RESERVED_TEST_PARAMS.intersection(execution['test_params']):
        raise ValueError('reserved test_params cannot be overridden')
    _reject_internal_ptf_tokens(execution['test_params'].values(), 'test_params')
    _scalar_values(execution['env'], 'env', environment=True)
    _reject_internal_ptf_tokens(execution['env'].values(), 'env')
    start_tokens = _launcher_tokens(runtime['start_argv'])
    _launcher_tokens(runtime['stop_argv'])
    if not {'saiserver_image_id', 'saiserver_container'}.issubset(start_tokens.values()):
        raise ValueError('start_argv requires image ID and container name bindings')
    return execution


def _validate_selection(selected, selector, manifest, identity):
    if not isinstance(selected, list) or not selected:
        raise ValueError('selected_cases must be a non-empty list for execution')
    expected = select_ranking_cases(manifest, **_validated_selector(selector))
    if _canonical(manifest['source_identity']) != _canonical(identity):
        raise ValueError('manifest source identity mismatch')
    if selected != expected:
        raise ValueError('selector and selected_cases mismatch')


def _tree_files(root, description):
    files = []

    def fail(error):
        raise ValueError('cannot walk {}: {}'.format(description, error)) from error

    for directory, subdirs, names in os.walk(root, followlinks=False, onerror=fail):
        subdirs.sort()
        for name in subdirs:
            _local_source(os.path.join(directory, name), description, directory=True)
        for name in sorted(names):
            path = _local_source(os.path.join(directory, name), description)
            files.append((description, os.path.relpath(path, root), path))
    return files


def _source_bytes(path, description):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError('{} must remain a regular file'.format(description))
            return source.read()
    except OSError as error:
        raise ValueError('cannot read source {}: {}'.format(path, error)) from error


def _validated_adapter(runtime):
    adapter = _local_source(runtime['adapter_path'], 'adapter_path')
    binding_adapter = _local_source(os.path.join(
        runtime['execution']['binding_dir'], 'sai_thrift', 'sai_adapter.py'),
        'binding sai_adapter.py')
    adapter_content = _source_bytes(adapter, 'adapter_path')
    binding_content = _source_bytes(binding_adapter, 'binding sai_adapter.py')
    if (len(adapter_content), hashlib.sha256(adapter_content).digest()) != (
            len(binding_content), hashlib.sha256(binding_content).digest()) or \
            adapter_content != binding_content:
        raise ValueError('runtime adapter_path must be byte-identical to binding sai_adapter.py')
    return adapter


def _dut_files(runtime):
    files = runtime['execution']['dut_files']
    if not isinstance(files, list):
        raise ValueError('dut_files must be an ordered list')
    declared = {argument for field in ('start_argv', 'stop_argv')
                for argument in runtime[field] if os.path.isabs(argument)}
    roots = runtime['dut_config_roots']
    seen = set()
    sources = []
    for entry in files:
        _exact_object(entry, {'source', 'destination'}, 'dut_files entry')
        source = _local_source(entry['source'], 'dut_files source')
        destination = _canonical_path(entry['destination'], 'dut_files destination')
        configured = any(destination.startswith(root + '/') for root in roots)
        if not configured and (destination == '/' or any(
                destination == root or destination.startswith(root + '/')
                for root in PROTECTED_DESTINATIONS)):
            raise ValueError('dut_files system paths must be under a declared dut_config_roots entry')
        if destination not in declared:
            raise ValueError('dut_files destination must be an explicit launcher file path')
        if destination in seen:
            raise ValueError('duplicate dut_files destination')
        seen.add(destination)
        sources.append(('dut_files', destination, source))
    return sources


def _validate_contract(root, runtime, identity):
    path = _local_source(os.path.join(root, 'ranking-contract.json'), 'prepared case contract')
    contract = _strict_json(path, 'prepared case contract')
    _exact_object(contract, CONTRACT_FIELDS, 'prepared case contract')
    if type(contract['schema_version']) is not int or contract['schema_version'] != 1:
        raise ValueError('prepared case contract schema_version must be 1')
    _validate_source_identity(contract['source_identity'])
    if _canonical(contract['source_identity']) != _canonical(identity):
        raise ValueError('prepared case contract source identity mismatch')
    port = contract['rpc_port']
    if not (port == 'configurable' or (type(port) is int and port == runtime['rpc_port'])):
        raise ValueError('prepared case contract rpc_port mismatch')
    if contract['requires_dut_credentials'] is not False:
        raise ValueError('prepared cases must not require DUT credentials')
    if contract['switch_owner'] != 'case':
        raise ValueError('prepared case switch_owner must be case')
    if contract['dataplane_validation'] != 'after_create_switch':
        raise ValueError('prepared case dataplane_validation must be after_create_switch')


def _source_hash(runtime, selected, identity, pipeline_dir, runner_path):
    files = []
    roots = {}
    for field in ('case_source', 'header_dir', 'experimental_header_dir', 'binding_dir',
                  'prebuilt_dir'):
        owner = runtime['execution'] if field in ('binding_dir', 'prebuilt_dir') else runtime
        root = _local_source(owner[field], field, directory=True)
        roots[field] = root
        files.extend(_tree_files(root, field))
    files.extend(_tree_files(pipeline_dir, 'pipeline'))
    for field in ('adapter_path', 'inventory'):
        path = _local_source(runtime[field], field)
        files.append((field, '', path))
    files.append(('ptf_runner', '', runner_path))
    files.extend(_dut_files(runtime))
    _validate_contract(roots['case_source'], runtime, identity)
    for module in {case.split('.')[0] for case in selected}:
        _local_source(os.path.join(roots['case_source'], module + '.py'), 'selected case module')
    fingerprint = []
    for description, relative, path in sorted(files):
        content = _source_bytes(path, description)
        if description == 'case_source' and b'SONIC_PASSWORD' in content:
            raise ValueError('legacy SONIC_PASSWORD case source requires preparation')
        fingerprint.append([description, relative, len(content), hashlib.sha256(content).hexdigest()])
    return _digest(fingerprint)


def validate_execution_config(assembled, artifact_dir) -> dict:
    if (not isinstance(assembled, dict) or not isinstance(assembled.get('runtime'), dict)
            or 'execution' not in assembled['runtime']):
        raise ValueError('runtime.execution is required for execution')
    runtime = validate_runtime_config(assembled['runtime'])
    _exact_object(assembled, ASSEMBLED_FIELDS, 'assembled execution inputs with sidecars')
    assembled = deepcopy(assembled)
    assembled['input_dir'] = _canonical_path(assembled['input_dir'], 'input_dir')
    _canonical(assembled)
    _reject_credentials(assembled)
    if type(assembled['schema_version']) is not int or assembled['schema_version'] != SCHEMA_VERSION:
        raise ValueError('inputs schema_version must be 1')
    artifact = _artifact_path(artifact_dir)
    input_dir = _local_source(assembled['input_dir'], 'input_dir', directory=True)
    execution = _validate_execution(runtime)
    identity = assembled['source_identity']
    _validate_source_identity(identity)
    _validate_selection(assembled['selected_cases'], assembled['selector'],
                        assembled['manifest'], identity)
    mapping = assembled['port_mapping']
    _validate_mapping(mapping)
    fields = PHYSICAL_ROW_FIELDS if runtime['backend'] == 'physical_fanout' else VIRTUAL_ROW_FIELDS
    if any(set(row) != fields for row in mapping):
        raise ValueError('mapping row shape must match runtime backend')
    if len(mapping) != runtime['expected_connected_ports']:
        raise ValueError('mapping count must match expected_connected_ports')
    if assembled['mapping_hash'] != _mapping_hash(mapping):
        raise ValueError('mapping_hash mismatch')
    if assembled['interface_args'] != interface_args(mapping):
        raise ValueError('interface_args mismatch')
    ini = render_port_config(mapping, assembled['ptf_config_db'])
    _validated_adapter(runtime)
    for field in ('identity_file', 'known_hosts'):
        _local_source(runtime['dut_ssh'][field], 'dut_ssh ' + field)
    module_dir = os.path.abspath(os.path.dirname(__file__))
    pipeline_dir = _local_source(
        os.path.join(module_dir, 'pipeline'), 'pipeline', directory=True)
    runner_path = _local_source(
        os.path.join(module_dir, 'ptf_runner.py'), 'ptf_runner.py')
    source_hash = _source_hash(
        runtime, assembled['selected_cases'], identity, pipeline_dir, runner_path)
    result = {
        'runtime': runtime, 'execution': deepcopy(execution),
        'artifact_dir': artifact, 'input_dir': input_dir,
        'pipeline_dir': pipeline_dir, 'runner_path': runner_path,
        'selected_cases': assembled['selected_cases'], 'selector': assembled['selector'],
        'interface_args': assembled['interface_args'], 'mapping_hash': assembled['mapping_hash'],
        'source_identity': identity, 'port_mapping': mapping,
        'ptf_config_db': assembled['ptf_config_db'], 'port_config_ini': ini,
        'profile_hash': _digest({'runtime': runtime, 'execution': execution}),
        'source_hash': source_hash,
    }
    return deepcopy(result)


def load_execution_inputs(input_dir, artifact_dir) -> dict:
    directory = _local_source(input_dir, 'input_dir', directory=True)
    bundle_path = _local_source(os.path.join(directory, 'inputs.json'), 'inputs.json')
    bundle = _strict_json(bundle_path, 'compiled inputs')
    _exact_object(bundle, BUNDLE_FIELDS, 'compiled inputs')
    assembled = dict(bundle, input_dir=directory)
    for name, field in (('port-mapping.json', 'port_mapping'),
                        ('ptf-config-db.json', 'ptf_config_db')):
        path = _local_source(os.path.join(directory, name), name)
        assembled[field] = _strict_json(path, name)
    return validate_execution_config(assembled, artifact_dir)


PTF_REQUEST_COMPONENT_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*')
PTF_REQUEST_CASE_PATTERN = re.compile(
    r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+')


def _request_component(value, description):
    if not isinstance(value, str) or PTF_REQUEST_COMPONENT_PATTERN.fullmatch(value) is None:
        raise ValueError('invalid {}: {!r}'.format(description, value))


def _request_shape(execution):
    if not isinstance(execution, dict):
        raise ValueError('execution must be the validated execution inputs')
    runtime = execution.get('runtime')
    inner = execution.get('execution')
    if not isinstance(runtime, dict) or not isinstance(inner, dict):
        raise ValueError('execution inputs are missing runtime or execution fields')
    try:
        ptf_root = runtime['ptf_root']
        rpc_port = runtime['rpc_port']
        timeout_s = runtime['timeout_s']
        ptf_argv = inner['ptf_argv']
        test_params = inner['test_params']
        environment = inner['env']
        rpc_host = inner['rpc_host']
        saiserver_container = runtime['saiserver_container']
        ptf_container = runtime['ptf_container']
        interface_args = execution['interface_args']
    except KeyError as error:
        raise ValueError(
            'execution inputs are missing runtime or execution fields') from error
    _text(ptf_root, 'runtime ptf_root')
    if not os.path.isabs(ptf_root):
        raise ValueError('runtime ptf_root must be an absolute path')
    for field, value in (('rpc_port', rpc_port), ('timeout_s', timeout_s)):
        if type(value) is not int or value <= 0:
            raise ValueError('runtime {} must be a positive integer'.format(field))
    _argv(ptf_argv, 'execution ptf_argv')
    _text(rpc_host, 'execution rpc_host')
    _identifier(saiserver_container, 'runtime saiserver_container')
    _identifier(ptf_container, 'runtime ptf_container')
    _docker_exec_argv(ptf_argv, ptf_container)
    _scalar_values(test_params, 'execution test_params')
    if not isinstance(environment, dict):
        raise ValueError('execution env must be an object')
    if not isinstance(interface_args, list):
        raise ValueError('interface_args must be a list')
    for argument in interface_args:
        _text(argument, 'interface_args')
    return (ptf_root, rpc_port, timeout_s, ptf_argv, test_params, environment,
            rpc_host, saiserver_container, ptf_container, interface_args)


def build_ptf_request(execution, environment_id, case, run_id) -> dict:
    _request_component(environment_id, 'environment_id')
    _request_component(run_id, 'run_id')
    if not isinstance(case, str) or PTF_REQUEST_CASE_PATTERN.fullmatch(case) is None:
        raise ValueError("run action requires a case name like 'module.Class'")
    (ptf_root, rpc_port, timeout_s, ptf_argv, test_params, environment, rpc_host,
     saiserver_container, ptf_container, interface_args) = _request_shape(execution)
    root = PurePosixPath(ptf_root) / environment_id
    reserved = {
        'thrift_server': rpc_host,
        'rpc_port': rpc_port,
        'config_db_json': str(root / 'resources' / 'ptf-config-db.json'),
        'port_config_ini': str(root / 'resources' / 'port_config.ini'),
        'result_output_dir': str(root / 'runs' / run_id),
        'host_control_container': INTERNAL_SAISERVER_CONTAINER_TOKEN,
        'asic_container': INTERNAL_SAISERVER_CONTAINER_TOKEN,
    }
    params = dict(test_params)
    params.update(reserved)
    runtime = execution['runtime']
    ssh = runtime['dut_ssh']
    secrets = root / SSH_SECRET_DIR
    params.update({
        'dut_os': runtime['dut_os'],
        'host_control_user': ssh['user'],
        'host_control_identity_file': str(secrets / SSH_IDENTITY_NAME),
        'host_control_known_hosts': str(secrets / SSH_KNOWN_HOSTS_NAME),
    })
    if runtime['backend'] == 'vsonic_ovs':
        params['vsonic_dataplane_ready_timeout_s'] = runtime['vsonic_dataplane_timeout_s']
        params['vsonic_connected_port_count'] = runtime['expected_connected_ports']
        params['vsonic_saiserver_container'] = INTERNAL_SAISERVER_CONTAINER_TOKEN
    env = dict(environment)
    env['PYTHONPATH'] = '{}:{}:{}'.format(
        root / 'binding', root / 'ptf', env.get('PYTHONPATH', ''))
    argv = list(ptf_argv)
    request_env = env
    if _docker_exec_argv(ptf_argv, ptf_container):
        docker_env = []
        for key in sorted(env):
            docker_env.extend(['--env', '{}={}'.format(key, env[key])])
        argv = argv[:2] + docker_env + [INTERNAL_PTF_CONTAINER_TOKEN] + argv[3:]
        request_env = {}
    argv.extend([
        '--test-dir', str(root / 'ptf'), case, '--platform', 'eth'])
    argv.extend(interface_args)
    argv.extend(['--test-params', serialize_test_params(params)])
    return {
        'argv': argv,
        'env': request_env,
        'cwd': str(root),
        'run_dir': str(root / 'runs' / run_id),
        'timeout_s': timeout_s,
    }
