import copy
from unittest.mock import patch

import pytest

from tests.ranking.runtime_config import validate_runtime_config


DEFAULT_SERVICES = [
    'swss', 'syncd', 'radv', 'lldp', 'dhcp_relay', 'teamd', 'bgp',
    'pmon', 'telemetry', 'acms', 'snmp',
]


def test_default_profile_is_offline_and_does_not_mutate_input(profile):
    original = copy.deepcopy(profile)
    with patch('subprocess.run') as run:
        validated = validate_runtime_config(profile)
        run.assert_not_called()
    assert validated == dict(
        original, dut_os='sonic', dut_identity_file='/etc/machine-id',
        image_identity_files=['/etc/sonic/sonic_version.yml'],
        services_to_stop=DEFAULT_SERVICES,
        service_start_order=['syncd', 'swss'] + DEFAULT_SERVICES[2:],
        asic_owner_processes=['syncd'],
        port_baseline={'argv': ['show', 'interfaces', 'status'],
                       'format': 'sonic_interfaces_status', 'timeout_s': 300},
        dut_config_roots=['/etc/sai.d', '/usr/share/sonic/device'])
    assert validate_runtime_config(validated) == validated
    assert profile == original
    validated['start_argv'].append('--changed')
    validated['services_to_stop'].clear()
    assert profile == original
    assert validate_runtime_config(profile)['services_to_stop'] == DEFAULT_SERVICES


@pytest.mark.parametrize('backend', ['physical_fanout', 'vsonic_ovs'])
@pytest.mark.parametrize('services_to_stop', [['swss', 'syncd'], []])
def test_backend_and_complete_service_override(profile, backend, services_to_stop):
    profile.update(backend=backend, services_to_stop=services_to_stop)
    original = copy.deepcopy(profile)
    validated = validate_runtime_config(profile)
    assert all(validated[key] == value for key, value in original.items())
    assert set(validated['service_start_order']) == set(services_to_stop)
    if backend == 'vsonic_ovs':
        assert validated['vsonic_dataplane_timeout_s'] == 180
    assert validated['services_to_stop'] == services_to_stop
    assert validated['services_to_stop'] is not services_to_stop
    validated['services_to_stop'].append('bgp')
    assert profile == original


@pytest.mark.parametrize('services_to_stop', [None, ['swss', 'syncd'], ['bgp']])
def test_legacy_services_field_is_rejected(profile, services_to_stop):
    profile['services'] = ['swss', 'syncd']
    if services_to_stop is not None:
        profile['services_to_stop'] = services_to_stop
    with pytest.raises(ValueError, match='services'):
        validate_runtime_config(profile)


@pytest.mark.parametrize('dut_limit', ['dut-*', 'dut-a,dut-b', 'dut-b', 'all', '*'])
def test_dut_limit_rejects_unowned_targets(profile, dut_limit):
    profile['dut_limit'] = dut_limit
    with pytest.raises(ValueError, match='dut_limit'):
        validate_runtime_config(profile)


@pytest.mark.parametrize('dut_id', ['dut-a', 'dut-b', 'dut_1.example'])
def test_dut_limit_accepts_only_matching_identifier(profile, dut_id):
    profile.update(dut_id=dut_id, dut_limit=dut_id)
    assert validate_runtime_config(profile)['dut_limit'] == dut_id


@pytest.mark.parametrize('field,value', [
    ('schema_version', True), ('schema_version', 2),
    ('backend', 'unknown'), ('backend', []),
    ('timeout_s', True), ('timeout_s', 0), ('timeout_s', 1.5),
    ('rpc_port', 0), ('rpc_port', 65536), ('rpc_port', True),
    ('expected_connected_ports', 0), ('expected_connected_ports', '32'),
    ('expected_connected_ports', True),
    ('start_argv', '/usr/bin/saiserverv2.sh start'),
    ('stop_argv', []), ('start_argv', ['']), ('stop_argv', [None]),
    ('start_argv', ['/bin/start\x00']),
    ('dut_id', 'dut-a;id'), ('ptf_host_id', ''),
    ('ptf_container', 'ptf-a\n'), ('dut_limit', ''),
    ('inventory', None), ('ptf_root', ''), ('case_source', 12),
    ('header_dir', '\x00'), ('adapter_path', []), ('saiserver_image', ''),
    ('saiserver_container', 'x;id'),
    ('services_to_stop', 'swss,syncd'), ('services_to_stop', ['swss', 'swss']),
    ('services_to_stop', ['swss;id']), ('services_to_stop', [True]),
])
def test_invalid_profile_values(profile, field, value):
    profile[field] = value
    with pytest.raises(ValueError):
        validate_runtime_config(profile)


@pytest.mark.parametrize('field', [
    'schema_version', 'backend', 'dut_id', 'ptf_host_id', 'ptf_container',
    'inventory', 'dut_limit', 'saiserver_container', 'saiserver_image',
    'start_argv', 'stop_argv', 'rpc_port', 'timeout_s', 'expected_connected_ports',
    'ptf_root', 'case_source', 'header_dir', 'experimental_header_dir',
    'adapter_path', 'dut_ssh',
])
def test_required_fields(profile, field):
    profile.pop(field)
    with pytest.raises(ValueError):
        validate_runtime_config(profile)


@pytest.mark.parametrize('key', [
    'password', 'PASSWORD', 'ansible_password', 'ansible_ssh_pass',
    'credentials', 'api_token', 'private_key', 'vault_password', 'secret',
])
def test_sensitive_fields_rejected(profile, key):
    profile[key] = 'do-not-store'
    with pytest.raises(ValueError):
        validate_runtime_config(profile)


def test_nested_credentials_rejected(profile):
    profile['metadata'] = [{'credentials': {'username': 'admin'}}]
    with pytest.raises(ValueError):
        validate_runtime_config(profile)


@pytest.mark.parametrize('value', [None, [], {}, True])
def test_invalid_profile_types(value):
    with pytest.raises(ValueError):
        validate_runtime_config(value)


def test_argv_is_preserved_as_literal_arguments(profile):
    profile['start_argv'] = ['/usr/bin/saiserverv2.sh', 'start', 'literal with spaces']
    assert validate_runtime_config(profile)['start_argv'] == profile['start_argv']


@pytest.mark.parametrize('port', [1, 65535])
def test_rpc_port_boundaries(profile, port):
    profile['rpc_port'] = port
    assert validate_runtime_config(profile)['rpc_port'] == port
