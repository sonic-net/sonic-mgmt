import re
from copy import deepcopy


BACKENDS = ('physical_fanout', 'vsonic_ovs')
DEFAULT_SERVICES = (
    'swss', 'syncd', 'radv', 'lldp', 'dhcp_relay', 'teamd', 'bgp',
    'pmon', 'telemetry', 'acms', 'snmp',
)
REQUIRED_FIELDS = (
    'schema_version', 'backend', 'dut_id', 'ptf_host_id', 'ptf_container',
    'inventory', 'dut_limit', 'saiserver_container', 'saiserver_image',
    'start_argv', 'stop_argv', 'rpc_port', 'timeout_s', 'expected_connected_ports',
    'ptf_root', 'case_source', 'header_dir', 'adapter_path',
)
IDENTIFIER_PATTERN = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]*')
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
    for field in ('inventory', 'saiserver_image', 'ptf_root', 'case_source',
                  'header_dir', 'adapter_path'):
        _text(value[field], field)
    for field in ('start_argv', 'stop_argv'):
        _argv(value[field], field)
    for field in ('rpc_port', 'timeout_s', 'expected_connected_ports'):
        _positive_integer(value[field], field)
    if value['rpc_port'] > MAX_RPC_PORT:
        raise ValueError('rpc_port must be in 1..65535')
    if 'services' in value:
        raise ValueError('services is not supported; use services_to_stop')
    services = value.get('services_to_stop', list(DEFAULT_SERVICES))
    if not isinstance(services, list):
        raise ValueError('services_to_stop must be a string array')
    for service in services:
        _identifier(service, 'service')
    if len(services) != len(set(services)):
        raise ValueError('duplicate service')
    result = deepcopy(value)
    result['services_to_stop'] = list(services)
    return result
