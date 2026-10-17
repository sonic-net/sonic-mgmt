import posixpath
import re
from copy import deepcopy


BACKENDS = ('physical_fanout', 'vsonic_ovs')
DUT_OS_VALUES = ('sonic', 'none')
DEFAULT_SERVICES = (
    'swss', 'syncd', 'radv', 'lldp', 'dhcp_relay', 'teamd', 'bgp',
    'pmon', 'telemetry', 'acms', 'snmp',
)
SONIC_START_PRIORITY = ('syncd', 'swss')
DEFAULT_DUT_IDENTITY_FILE = '/etc/machine-id'
DEFAULT_VSONIC_DATAPLANE_TIMEOUT_S = 180
PORT_BASELINE_FORMATS = ('sonic_interfaces_status', 'json')
PORT_BASELINE_FIELDS = frozenset(('argv', 'format', 'timeout_s'))
DUT_SSH_FIELDS = frozenset(('user', 'identity_file', 'known_hosts'))
PROTECTED_DESTINATIONS = (
    '/etc', '/boot', '/dev', '/proc', '/sys', '/run', '/var',
    '/host', '/mnt', '/media', '/root', '/home', '/lib', '/lib64', '/bin', '/sbin',
    '/usr/bin', '/usr/sbin', '/usr/lib', '/usr/lib64', '/usr/share',
)
PROFILE_FIELDS = ('image_identity_files', 'services_to_stop', 'asic_owner_processes',
                  'port_baseline', 'dut_config_roots')
DUT_OS_DEFAULTS = {
    'sonic': {
        'image_identity_files': ['/etc/sonic/sonic_version.yml'],
        'services_to_stop': list(DEFAULT_SERVICES),
        'asic_owner_processes': ['syncd'],
        'port_baseline': {'argv': ['show', 'interfaces', 'status'],
                          'format': 'sonic_interfaces_status', 'timeout_s': 300},
        'dut_config_roots': ['/etc/sai.d', '/usr/share/sonic/device'],
    },
    'none': {
        'services_to_stop': [],
        'port_baseline': None,
        'dut_config_roots': [],
    },
}
REQUIRED_FIELDS = (
    'schema_version', 'backend', 'dut_id', 'ptf_host_id', 'ptf_container',
    'inventory', 'dut_limit', 'saiserver_container', 'saiserver_image',
    'start_argv', 'stop_argv', 'rpc_port', 'timeout_s', 'expected_connected_ports',
    'ptf_root', 'case_source', 'header_dir', 'experimental_header_dir', 'adapter_path',
    'dut_ssh',
)
OPTIONAL_FIELDS = frozenset(('execution', 'dut_os', 'dut_identity_file', 'service_start_order',
                             'vsonic_dataplane_timeout_s') + PROFILE_FIELDS)
IDENTIFIER_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*')
SERVICE_NAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*')
# pgrep -x matches a regex against the kernel comm, which is truncated to 15 characters.
PROCESS_NAME_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_-]{0,14}')
SSH_USER_PATTERN = re.compile(r'[A-Za-z_][A-Za-z0-9_.-]*')
# The PTF-side key path is derived from ptf_root, and ssh expands %, ~ and whitespace.
SSH_SAFE_PATH_PATTERN = re.compile(r'/[A-Za-z0-9_./-]+')
MAX_RPC_PORT = 65535
SENSITIVE_MARKERS = ('password', 'passwd', 'credential', 'secret', 'token',
                     'privatekey', 'accesskey', 'apikey', 'sshkey')


def _reject_credentials(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError('runtime config keys must be strings')
            normalized = re.sub(r'[^a-z0-9]', '', key.lower())
            parts = key.lower().replace('-', '_').split('_')
            if (any(marker in normalized for marker in SENSITIVE_MARKERS)
                    or any(part in ('pass', 'pwd') for part in parts)):
                raise ValueError('credential fields are not allowed: {}'.format(key))
            _reject_credentials(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_credentials(item)


def _text(value, field):
    if (not isinstance(value, str) or not value.strip()
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError('{} must be a non-empty string without control characters'.format(field))


def _identifier(value, field, pattern=IDENTIFIER_PATTERN):
    _text(value, field)
    if not pattern.fullmatch(value):
        raise ValueError('invalid {}: {!r}'.format(field, value))


def _positive_integer(value, field):
    if type(value) is not int or value <= 0:
        raise ValueError('{} must be a positive integer'.format(field))


def _argv(value, field):
    if not isinstance(value, list) or not value:
        raise ValueError('{} must be a non-empty string array'.format(field))
    for argument in value:
        _text(argument, field)


def _posix_path(value, field):
    _text(value, field)
    if (not value.startswith('/') or value.startswith('//') or '\\' in value
            or posixpath.normpath(value) != value):
        raise ValueError('{} must be an absolute canonical path'.format(field))
    return value


def _service(value, field):
    _identifier(value, field, SERVICE_NAME_PATTERN)


def _process(value, field):
    _identifier(value, field, PROCESS_NAME_PATTERN)


def _unique_list(value, field, check, allow_empty):
    if not isinstance(value, list) or (not value and not allow_empty):
        raise ValueError('{} must be a{} string array'.format(
            field, 'n' if allow_empty else ' non-empty'))
    for item in value:
        check(item, field)
    if len(value) != len(set(value)):
        raise ValueError('duplicate entry in {}'.format(field))
    return list(value)


def _config_root(value, field):
    _posix_path(value, field)
    if value in PROTECTED_DESTINATIONS or value.count('/') < 2:
        raise ValueError('{} must name a specific configuration directory'.format(field))


def _port_baseline(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != PORT_BASELINE_FIELDS:
        raise ValueError('port_baseline must be null or declare argv, format, and timeout_s')
    _argv(value['argv'], 'port_baseline argv')
    if value['format'] not in PORT_BASELINE_FORMATS:
        raise ValueError('unknown port_baseline format')
    _positive_integer(value['timeout_s'], 'port_baseline timeout_s')
    return deepcopy(value)


def _dut_ssh(value):
    if not isinstance(value, dict) or set(value) != DUT_SSH_FIELDS:
        raise ValueError('dut_ssh must declare user, identity_file, and known_hosts')
    _identifier(value['user'], 'dut_ssh user', SSH_USER_PATTERN)
    for field in ('identity_file', 'known_hosts'):
        _posix_path(value[field], 'dut_ssh ' + field)
    return deepcopy(value)


def _start_order(value, services, dut_os):
    if value is None:
        priority = SONIC_START_PRIORITY if dut_os == 'sonic' else ()
        first = [service for service in priority if service in services]
        return first + [service for service in services if service not in first]
    order = _unique_list(value, 'service_start_order', _service, allow_empty=True)
    if sorted(order) != sorted(services):
        raise ValueError('service_start_order must order exactly services_to_stop')
    return order


def _dataplane_timeout(value):
    if value['backend'] != 'vsonic_ovs':
        if 'vsonic_dataplane_timeout_s' in value:
            raise ValueError('vsonic_dataplane_timeout_s applies only to vsonic_ovs')
        return None
    timeout = value.get('vsonic_dataplane_timeout_s', DEFAULT_VSONIC_DATAPLANE_TIMEOUT_S)
    _positive_integer(timeout, 'vsonic_dataplane_timeout_s')
    if timeout >= value['timeout_s']:
        raise ValueError('vsonic_dataplane_timeout_s (default {}) must be shorter than '
                         'timeout_s'.format(DEFAULT_VSONIC_DATAPLANE_TIMEOUT_S))
    return timeout


def validate_runtime_config(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError('runtime config must be an object')
    _reject_credentials(value)
    missing = [field for field in REQUIRED_FIELDS if field not in value]
    if missing:
        raise ValueError('missing runtime config fields: {}'.format(', '.join(missing)))
    if type(value['schema_version']) is not int or value['schema_version'] != 1:
        raise ValueError('runtime config schema_version must be 1')
    if value['backend'] not in BACKENDS:
        raise ValueError('unknown runtime backend')
    for field in ('dut_id', 'ptf_host_id', 'ptf_container', 'saiserver_container'):
        _identifier(value[field], field)
    _identifier(value['dut_limit'], 'dut_limit')
    if value['dut_limit'] != value['dut_id']:
        raise ValueError('dut_limit must match dut_id for a single DUT')
    for field in ('inventory', 'saiserver_image', 'case_source',
                  'header_dir', 'experimental_header_dir', 'adapter_path'):
        _text(value[field], field)
    _posix_path(value['ptf_root'], 'ptf_root')
    if not SSH_SAFE_PATH_PATTERN.fullmatch(value['ptf_root']):
        raise ValueError('ptf_root must use only letters, digits, _, ., - and /')
    for field in ('start_argv', 'stop_argv'):
        _argv(value[field], field)
    for field in ('rpc_port', 'timeout_s', 'expected_connected_ports'):
        _positive_integer(value[field], field)
    if value['rpc_port'] > MAX_RPC_PORT:
        raise ValueError('rpc_port must be in 1..65535')
    if 'services' in value:
        raise ValueError('services is not supported; use services_to_stop')
    unknown = sorted(set(value).difference(REQUIRED_FIELDS, OPTIONAL_FIELDS))
    if unknown:
        raise ValueError('unknown runtime config fields: {}'.format(', '.join(unknown)))
    dut_os = value.get('dut_os', 'sonic')
    if dut_os not in DUT_OS_VALUES:
        raise ValueError('unknown dut_os')
    if dut_os == 'none' and value['backend'] != 'physical_fanout':
        raise ValueError('dut_os none requires the physical_fanout backend')
    defaults = DUT_OS_DEFAULTS[dut_os]
    undeclared = [field for field in PROFILE_FIELDS if field not in value and field not in defaults]
    if undeclared:
        raise ValueError('dut_os {} requires {}'.format(dut_os, ', '.join(undeclared)))
    profile = {field: value[field] if field in value else defaults[field]
               for field in PROFILE_FIELDS}
    services = _unique_list(profile['services_to_stop'], 'services_to_stop', _service,
                            allow_empty=True)
    result = deepcopy(value)
    result['dut_os'] = dut_os
    result['dut_identity_file'] = _posix_path(
        value.get('dut_identity_file', DEFAULT_DUT_IDENTITY_FILE), 'dut_identity_file')
    result['image_identity_files'] = _unique_list(
        profile['image_identity_files'], 'image_identity_files', _posix_path, allow_empty=False)
    result['services_to_stop'] = services
    result['service_start_order'] = _start_order(
        value.get('service_start_order'), services, dut_os)
    result['asic_owner_processes'] = _unique_list(
        profile['asic_owner_processes'], 'asic_owner_processes', _process, allow_empty=True)
    result['port_baseline'] = _port_baseline(profile['port_baseline'])
    result['dut_config_roots'] = _unique_list(
        profile['dut_config_roots'], 'dut_config_roots', _config_root, allow_empty=True)
    result['dut_ssh'] = _dut_ssh(value['dut_ssh'])
    timeout = _dataplane_timeout(value)
    if timeout is not None:
        result['vsonic_dataplane_timeout_s'] = timeout
    return result
