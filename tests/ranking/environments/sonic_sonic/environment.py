"""Strict loader for one Ranking environment without durable credentials."""

import ipaddress
import posixpath
from pathlib import Path
import re

import yaml


ROOT_FIELDS = frozenset(('schema_version', 'type', 'controller', 'hosts',
                         'dut', 'ptf', 'ports'))
CONTROLLER_FIELDS = frozenset(('testbed', 'host_pattern', 'connection'))
HOST_FIELDS = frozenset(('name', 'address', 'user', 'auth'))
AUTH_FIELDS = frozenset(('password',))
DUT_FIELDS = frozenset(('rpc_port',))
PTF_FIELDS = frozenset(('container', 'workdir', 'executable', 'case_dir',
                        'binding_dir', 'collector_dir', 'timeout_s', 'arguments'))
PORT_FIELDS = frozenset(('id', 'interface'))
HOST_NAME = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9])?\Z')
HOST_ADDRESS_LABEL = re.compile(
    r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z')
USER_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*\Z')
PORT_NAME = re.compile(r'[A-Za-z][A-Za-z0-9_.:-]*\Z')
CONTAINER_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*\Z')


class _EnvironmentLoader(yaml.SafeLoader):
    pass


def _yaml_object(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str):
            raise ValueError('environment keys must be strings')
        if key in result:
            raise ValueError('duplicate environment key: {}'.format(key))
        result[key] = loader.construct_object(value_node)
    return result


_EnvironmentLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _yaml_object)


def _object(value, field, allowed, required=None):
    if not isinstance(value, dict):
        raise ValueError('{} must be an object'.format(field))
    if any(not isinstance(key, str) for key in value):
        raise ValueError('{} keys must be strings'.format(field))
    unknown = sorted(set(value).difference(allowed))
    if unknown:
        raise ValueError('unsupported {} fields: {}'.format(field, ', '.join(unknown)))
    missing = sorted(set(required if required is not None else allowed).difference(value))
    if missing:
        raise ValueError('missing {} fields: {}'.format(field, ', '.join(missing)))
    return value


def _text(value, field, pattern=None):
    if (not isinstance(value, str) or not value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or (pattern is not None and pattern.fullmatch(value) is None)):
        raise ValueError('{} must be a valid non-empty string'.format(field))
    return value


def _positive(value, field, maximum=None):
    if type(value) is not int or value <= 0 or (maximum is not None and value > maximum):
        suffix = ' in 1..{}'.format(maximum) if maximum is not None else ''
        raise ValueError('{} must be a positive integer{}'.format(field, suffix))
    return value


def _path(value, field):
    _text(value, field)
    if (not value.startswith('/') or value.startswith('//') or '\\' in value
            or posixpath.normpath(value) != value or value == '/'):
        raise ValueError('{} must be an absolute canonical path'.format(field))
    return value


def _address(value, field):
    _text(value, field)
    try:
        ipaddress.ip_address(value)
    except ValueError:
        labels = value.split('.')
        if (len(value) > 253 or not labels
                or any(not label or len(label) > 63
                       or HOST_ADDRESS_LABEL.fullmatch(label) is None
                       for label in labels)):
            raise ValueError('{} must be an IP address or hostname'.format(field))
    return value


def _ipv4_address(value, field):
    _text(value, field)
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError('{} must be an IPv4 address'.format(field)) from error
    if address.version != 4:
        raise ValueError('{} must be an IPv4 address'.format(field))
    return str(address)


def _host(value, role):
    value = _object(value, 'hosts.{}'.format(role), HOST_FIELDS,
                    required=('name', 'address', 'user'))
    result = {
        'name': _text(value['name'], 'hosts.{}.name'.format(role), HOST_NAME),
        'address': _address(value['address'], 'hosts.{}.address'.format(role)),
        'user': _text(value['user'], 'hosts.{}.user'.format(role), USER_NAME),
    }
    if 'auth' in value:
        auth = _object(value['auth'], 'hosts.{}.auth'.format(role), AUTH_FIELDS)
        result['auth'] = {
            'password': _text(auth['password'], 'hosts.{}.auth.password'.format(role))}
    return result


def _load(path):
    path = Path(path).expanduser().resolve()
    try:
        with path.open(encoding='utf-8') as source:
            value = yaml.load(source, Loader=_EnvironmentLoader)
    except OSError as error:
        raise ValueError('cannot read ranking environment: {}'.format(path)) from error
    except yaml.YAMLError as error:
        raise ValueError('cannot parse ranking environment YAML') from error
    return value


def load_environment(path):
    """Load and validate one complete SONiC-to-SONiC environment."""
    value = _object(_load(path), 'environment', ROOT_FIELDS)
    if value['schema_version'] != 1:
        raise ValueError('schema_version must be 1')
    if value['type'] != 'sonic_sonic':
        raise ValueError('type must be sonic_sonic')

    controller = _object(
        value['controller'], 'controller', CONTROLLER_FIELDS,
        required=('testbed', 'host_pattern'))
    connection = controller.get('connection', 'ssh')
    if connection not in ('ssh', 'paramiko'):
        raise ValueError('controller.connection must be ssh or paramiko')
    controller = {
        'testbed': _text(controller['testbed'], 'controller.testbed', HOST_NAME),
        'host_pattern': _text(
            controller['host_pattern'], 'controller.host_pattern', HOST_NAME),
        'connection': connection,
    }
    hosts = _object(value['hosts'], 'hosts', frozenset(('dut', 'ptf')))
    hosts = {role: _host(hosts[role], role) for role in ('dut', 'ptf')}
    hosts['ptf']['address'] = _ipv4_address(
        hosts['ptf']['address'], 'hosts.ptf.address')
    if hosts['dut']['name'] == hosts['ptf']['name']:
        raise ValueError('DUT and PTF host names must differ')

    dut = _object(value['dut'], 'dut', DUT_FIELDS)
    rpc_port = _positive(dut['rpc_port'], 'dut.rpc_port', 65535)
    if rpc_port != 9092:
        raise ValueError('dut.rpc_port must be exactly 9092')
    dut = {'rpc_port': rpc_port}

    ptf = _object(value['ptf'], 'ptf', PTF_FIELDS)
    arguments = ptf['arguments']
    if arguments != ['--relax']:
        raise ValueError('ptf.arguments must be exactly [--relax]')
    ptf = {
        'container': _text(ptf['container'], 'ptf.container', CONTAINER_NAME),
        'workdir': _path(ptf['workdir'], 'ptf.workdir'),
        'executable': _path(ptf['executable'], 'ptf.executable'),
        'case_dir': _path(ptf['case_dir'], 'ptf.case_dir'),
        'binding_dir': _path(ptf['binding_dir'], 'ptf.binding_dir'),
        'collector_dir': _path(ptf['collector_dir'], 'ptf.collector_dir'),
        'timeout_s': _positive(ptf['timeout_s'], 'ptf.timeout_s'),
        'arguments': list(arguments),
    }

    if not isinstance(value['ports'], dict):
        raise ValueError('ports must be an object')
    ports = _object(value['ports'], 'ports', frozenset(value['ports']))
    normalized = {}
    identifiers = []
    interfaces = set()
    for name, item in ports.items():
        _text(name, 'ports name', PORT_NAME)
        item = _object(item, 'ports.{}'.format(name), PORT_FIELDS)
        identifier = _positive(item['id'], 'ports.{}.id'.format(name))
        interface = _text(
            item['interface'], 'ports.{}.interface'.format(name), PORT_NAME)
        if identifier in identifiers:
            raise ValueError('duplicate PTF port id')
        if interface in interfaces:
            raise ValueError('duplicate PTF interface')
        identifiers.append(identifier)
        interfaces.add(interface)
        normalized[name] = {'id': identifier, 'interface': interface}
    if not identifiers or sorted(identifiers) != list(range(1, len(identifiers) + 1)):
        raise ValueError('PTF port ids must be contiguous starting at 1')
    if identifiers != sorted(identifiers):
        raise ValueError('ports must be ordered by PTF port id')

    return {
        'schema_version': 1,
        'type': 'sonic_sonic',
        'controller': controller,
        'hosts': hosts,
        'dut': dut,
        'ptf': ptf,
        'ports': normalized,
    }


def controller_spec(environment):
    """Translate the SONiC-to-SONiC profile into standard sonic-mgmt adapter inputs."""
    hosts = environment['hosts']
    controller = environment['controller']
    topology = 'ptf{}'.format(len(environment['ports']))

    def inventory_host(host):
        value = {
            'ansible_host': host['address'],
            'ansible_user': host['user'],
            'ansible_connection': controller['connection'],
        }
        auth = host.get('auth')
        if isinstance(auth, dict) and 'password' in auth:
            value['ansible_password'] = auth['password']
        return value

    return {
        'inventory': {
            'all': {'children': {
                'sonic': {'hosts': {hosts['dut']['name']: inventory_host(hosts['dut'])}},
                'ptf': {'hosts': {hosts['ptf']['name']: inventory_host(hosts['ptf'])}},
            }},
        },
        'testbed_entry': {
            'conf-name': controller['testbed'],
            'group-name': controller['testbed'],
            'topo': topology,
            'ptf_image_name': 'docker-ptf',
            'ptf': hosts['ptf']['name'],
            'ptf_ip': '{}/32'.format(hosts['ptf']['address']),
            'ptf_ipv6': None,
            'server': 'server_1',
            'vm_base': None,
            'dut': [hosts['dut']['name']],
            'auto_recover': 'False',
            'comment': 'Ranking generated controller adapter',
        },
        'topology_source': str(
            Path(__file__).resolve().parents[4] / 'ansible' / 'vars' /
            'topo_{}.yml'.format(topology)),
        'testbed_name': controller['testbed'],
        'host_pattern': controller['host_pattern'],
    }


def compile_runtime(environment, config_path):
    """Compile one validated SONiC-to-SONiC environment into the Run contract."""
    if environment.get('dut', {}).get('rpc_port') != 9092:
        raise ValueError('SONiC-to-SONiC rpc_port must be exactly 9092')
    if environment.get('ptf', {}).get('arguments') != ['--relax']:
        raise ValueError('SONiC-to-SONiC PTF arguments must be exactly [--relax]')
    ptf = environment['ptf']
    hosts = environment['hosts']
    interfaces = []
    for endpoint in environment['ports'].values():
        interfaces.extend([
            '--interface',
            '0-{}@{}'.format(endpoint['id'], endpoint['interface']),
        ])
    config = {
        'timeout_s': ptf['timeout_s'],
        'ptf_container': ptf['container'],
        'ptf_workdir': ptf['workdir'],
        'ptf_executable': ptf['executable'],
        'ptf_case_dir': ptf['case_dir'],
        'collector_dir': ptf['collector_dir'],
        'ptf_arguments': list(ptf['arguments']),
        'test_params': {'thrift_server': hosts['dut']['address']},
        'env': {'PYTHONPATH': ptf['binding_dir']},
        'interface_args': interfaces,
    }
    return config


def load_config(path):
    """Load this SONiC-to-SONiC profile and compile a credential-free runtime."""
    resolved = Path(path).expanduser().resolve()
    return compile_runtime(load_environment(resolved), resolved)
