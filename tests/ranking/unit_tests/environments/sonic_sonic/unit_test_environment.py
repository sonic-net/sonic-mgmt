from copy import deepcopy
import json
from pathlib import Path

import pytest
import yaml


EXAMPLE = Path(__file__).resolve().parents[3] / 'environments' / 'sonic_sonic' / 'environment.yml'


def _load(path):
    from tests.ranking.environments.sonic_sonic.environment import load_environment

    return load_environment(path)


def _values():
    return yaml.safe_load(EXAMPLE.read_text(encoding='utf-8'))


def _write(tmp_path, values, name='environment.yml'):
    path = tmp_path / name
    path.write_text(yaml.safe_dump(values, sort_keys=False), encoding='utf-8')
    return path


def test_sonic_sonic_template_has_one_environment_and_explicit_ptf_paths():
    value = _load(EXAMPLE)

    assert value['schema_version'] == 1
    assert value['type'] == 'sonic_sonic'
    assert value['controller']['connection'] == 'ssh'
    assert 'topology' not in value
    assert value['hosts']['dut'] == {
        'name': 'sonic-dut', 'address': '192.0.2.10', 'user': 'root'}
    assert value['hosts']['ptf'] == {
        'name': 'sonic-ptf', 'address': '192.0.2.20', 'user': 'root'}
    assert value['ptf']['workdir'] == '/SAI-TEST'
    assert value['ptf']['executable'] == '/SAI-TEST/test/ptf/ptf'
    assert value['ptf']['case_dir'] == '/SAI-TEST/ptf'
    assert value['ptf']['binding_dir'] == '/usr/lib/python3/dist-packages'
    assert value['ptf']['collector_dir'] == '/tmp/sai_test_results'
    assert value['dut']['rpc_port'] == 9092
    assert value['ptf']['arguments'] == ['--relax']
    assert [item['id'] for item in value['ports'].values()] == list(range(1, 33))


def test_public_template_uses_synthetic_non_overlapping_port_data():
    from tests.ranking.environments.sonic_sonic.port_mapping import (
        load_port_config,
    )

    root = EXAMPLE.parent
    names = ['Ethernet{}'.format(index) for index in range(1, 33)]
    assert list(_values()['ports']) == names

    config_db = json.loads(
        (root / 'dut' / 'config_db.json').read_text(encoding='utf-8'))['PORT']
    port_config = load_port_config(root / 'dut' / 'port_config.ini')
    assert list(config_db) == names
    assert list(port_config) == names
    for index, name in enumerate(names, start=1):
        lanes = list(range((index - 1) * 4 + 1, index * 4 + 1))
        assert config_db[name]['lanes'] == ','.join(map(str, lanes))
        assert config_db[name]['alias'] == name
        assert config_db[name]['description'] == name
        assert config_db[name]['index'] == str(index)
        assert config_db[name]['speed'] == '400000'
        assert config_db[name]['fec'] == 'rs'
        assert port_config[name]['lanes'] == lanes
        assert port_config[name]['alias'] == name
        assert port_config[name]['index'] == str(index)
        assert port_config[name]['speed'] == '400000'
        assert port_config[name]['fec'] == 'rs'

    topology = (root / 'README.md').read_text(encoding='utf-8')
    assert 'synthetic placeholders' in topology


def test_sonic_sonic_environment_module_does_not_import_framework_core():
    source = (EXAMPLE.parent / 'environment.py').read_text(encoding='utf-8')

    assert 'tests.ranking.common' not in source
    assert 'tests.ranking.environments.sonic_sonic' not in source


def test_controller_connection_is_optional_and_defaults_to_ssh(tmp_path):
    value = _values()
    value['controller'].pop('connection', None)

    assert _load(_write(tmp_path, value))['controller']['connection'] == 'ssh'


def test_optional_password_is_accepted_but_never_echoed_in_validation_error(tmp_path):
    value = _values()
    value['hosts']['dut']['auth'] = {'password': 'sensitive-value'}
    loaded = _load(_write(tmp_path, value))
    assert loaded['hosts']['dut']['auth']['password'] == 'sensitive-value'

    invalid = deepcopy(value)
    invalid['hosts']['dut']['unexpected'] = 'sensitive-value'
    with pytest.raises(ValueError) as error:
        _load(_write(tmp_path, invalid, 'invalid.yml'))
    assert 'sensitive-value' not in str(error.value)


@pytest.mark.parametrize('mutate,match', [
    (lambda value: value.update({'unknown': True}), 'unsupported'),
    (lambda value: value['hosts']['dut'].update({'address': 'bad host/name'}), 'address'),
    (lambda value: value['dut'].update({'rpc_port': 0}), 'rpc_port'),
    (lambda value: value['ptf'].update({'case_dir': '/SAI-TEST/../ptf'}), 'case_dir'),
    (lambda value: value['ports']['Ethernet2'].update({'id': 1}), 'duplicate|contiguous'),
    (lambda value: value['ports']['Ethernet2'].update({'interface': 'Ethernet1'}), 'duplicate'),
    (lambda value: value['hosts']['dut'].update({'auth': {'token': 'hidden'}}), 'auth'),
    (lambda value: value['hosts']['dut'].update({'auth': {'password': 7}}), 'password'),
    (lambda value: value['controller'].update({'connection': 'local'}), 'connection'),
    (lambda value: value.update({'ports': []}), 'ports'),
])
def test_invalid_environment_is_rejected_without_serializing_values(tmp_path, mutate, match):
    value = _values()
    mutate(value)
    with pytest.raises(ValueError, match=match):
        _load(_write(tmp_path, value))


@pytest.mark.parametrize('rpc_port', (1, 9091, 9093, 65535))
def test_sonic_sonic_rpc_port_is_fixed_by_the_case_contract(tmp_path, rpc_port):
    value = _values()
    value['dut']['rpc_port'] = rpc_port

    with pytest.raises(ValueError, match='exactly 9092'):
        _load(_write(tmp_path, value))


@pytest.mark.parametrize('arguments', (
    [], ['--platform', 'eth'], ['--relax', '--relax'], ['--relax', '--platform'],
))
def test_sonic_sonic_ptf_arguments_are_fixed_by_the_case_contract(tmp_path, arguments):
    value = _values()
    value['ptf']['arguments'] = arguments

    with pytest.raises(ValueError, match='exactly.*--relax'):
        _load(_write(tmp_path, value))


def test_duplicate_yaml_key_is_rejected(tmp_path):
    path = tmp_path / 'environment.yml'
    path.write_text('schema_version: 1\nschema_version: 1\n', encoding='utf-8')

    with pytest.raises(ValueError, match='duplicate'):
        _load(path)


def test_ptf_address_accepts_ipv4(tmp_path):
    value = _values()
    value['hosts']['ptf']['address'] = '192.0.2.5'

    assert _load(_write(tmp_path, value))['hosts']['ptf']['address'] == '192.0.2.5'


@pytest.mark.parametrize('address', (
    'ptf-1.lab.example',
    'switch01',
    '2001:db8::5',
))
def test_ptf_address_rejects_non_ipv4_input(tmp_path, address):
    value = _values()
    value['hosts']['ptf']['address'] = address

    with pytest.raises(ValueError, match='hosts.ptf.address.*IPv4'):
        _load(_write(tmp_path, value))


@pytest.mark.parametrize('address', ('dut.lab.example', '2001:db8::10'))
def test_dut_address_keeps_hostname_and_ipv6_support(tmp_path, address):
    value = _values()
    value['hosts']['dut']['address'] = address

    assert _load(_write(tmp_path, value))['hosts']['dut']['address'] == address


@pytest.mark.parametrize('address', (
    'bad_host.example',
    '-leading.example',
    'trailing-.example',
    'empty..label',
    '{}.example'.format('a' * 64),
    '{}.example'.format('.'.join(['a' * 63] * 4)),
))
def test_host_address_rejects_invalid_dns_labels_without_echoing_value(
        tmp_path, address):
    value = _values()
    value['hosts']['ptf']['address'] = address

    with pytest.raises(ValueError, match='address') as error:
        _load(_write(tmp_path, value))
    assert address not in str(error.value)
