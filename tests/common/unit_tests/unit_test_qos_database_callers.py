"""Exercise local database command builders without DUT fixtures."""

import ast
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[3]


def load_definitions(path, names, namespace):
    tree = ast.parse((ROOT / path).read_text())
    definitions = [node for node in tree.body
                   if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names]
    for node in definitions:
        node.decorator_list = []
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


@pytest.fixture
def pfc():
    namespace = {'logger': Mock(), 'six': SimpleNamespace(text_type=str)}
    tree = ast.parse((ROOT / 'tests/pfcwd/test_pfcwd_function.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name):
            if node.targets[0].id in {'BF_PROFILE', 'BF_PROFILE_TABLE', 'DB_SEPARATORS'}:
                namespace[node.targets[0].id] = ast.literal_eval(node.value)
    return load_definitions('tests/pfcwd/test_pfcwd_function.py',
                            {'is_static_profile', 'PfcCmd'}, namespace)


@pytest.mark.parametrize('database', ['APPL_DB', 'CONFIG_DB'])
@pytest.mark.parametrize('static', [False, True])
def test_buffer_updates_keep_database_and_threshold(pfc, database, static):
    asic = Mock()
    asic.run_redis_cmd.return_value = ['4096'] if static else ['']
    dut = Mock()
    dut.get_port_asic_instance.return_value = asic
    pfc['PfcCmd'].isBufferInApplDb = staticmethod(lambda _: database == 'APPL_DB')
    pfc['PfcCmd'].update_alpha(dut, 'Ethernet0', 'profile', '3', '4096')
    template = pfc['BF_PROFILE_TABLE'] if database == 'APPL_DB' else pfc['BF_PROFILE']
    assert asic.run_redis_cmd.call_args_list[0].kwargs['argv'] == [
        'sonic-db-cli', database, 'HGET', template.format('profile'), 'static_th']
    assert asic.run_redis_cmd.call_args.kwargs['argv'] == [
        'sonic-db-cli', database, 'HSET', template.format('profile'),
        'static_th' if static else 'dynamic_th', '4096' if static else '3']


@pytest.mark.parametrize('database', ['APPL_DB', 'CONFIG_DB'])
@pytest.mark.parametrize('static', [False, True])
def test_buffer_reads_keep_profile_separator_and_values(pfc, database, static):
    template = pfc['BF_PROFILE_TABLE'] if database == 'APPL_DB' else pfc['BF_PROFILE']
    calls = []

    def execute(argv):
        calls.append(argv)
        if argv[-1] == 'profile':
            return ['[' + template.format('profile') + ']']
        if argv[-1] == 'static_th':
            return ['4096'] if static else ['']
        return ['3']

    asic = SimpleNamespace(run_redis_cmd=execute)
    dut = SimpleNamespace(get_port_asic_instance=lambda _: asic)
    pfc['PfcCmd'].isBufferInApplDb = staticmethod(lambda _: database == 'APPL_DB')
    result = pfc['PfcCmd'].get_mmu_params(dut, 'Ethernet0', set())
    assert result == ('profile', 0 if static else '3', '4096' if static else 0)
    assert all(argv[:2] == ['sonic-db-cli', database] for argv in calls)
    assert all(argv[3].startswith('BUFFER_') for argv in calls)


def test_storm_write_stays_on_queue_asic_and_counters_database(pfc):
    asic = Mock()
    dut = Mock()
    dut.get_queue_oid_asic_instance.return_value = asic
    pfc['PfcCmd'].set_storm_status(dut, 'oid:0x123', 'enabled')
    asic.run_redis_cmd.assert_called_once_with(argv=[
        'sonic-db-cli', 'COUNTERS_DB', 'HSET', 'COUNTERS:oid:0x123', 'DEBUG_STORM', 'enabled'])


@pytest.mark.parametrize('status', ['enable', 'disable'])
def test_pfcwd_setup_uses_namespace_database_helper(status):
    namespace = load_definitions('tests/generic_config_updater/test_pfcwd_interval.py',
                                 {'enable_default_pfcwd_configuration'},
                                 {'json': json, 'pytest_assert': lambda condition, _: condition})
    dut = Mock()
    dut.shell.return_value = {'rc': 0, 'stdout': json.dumps({
        'DEVICE_METADATA|localhost': {'value': {'default_pfcwd_status': status}}})}
    dut.get_asic_ids.return_value = [0, 1, 2]
    asics = {index: Mock() for index in (1, 2)}
    for asic in asics.values():
        asic.command.return_value = {'rc': 0}
    dut.asic_instance.side_effect = asics.__getitem__
    namespace['enable_default_pfcwd_configuration'](dut)
    for asic in asics.values():
        if status == 'disable':
            asic.run_sonic_db_cli_cmd.assert_called_once_with(
                'CONFIG_DB hset "DEVICE_METADATA|localhost" default_pfcwd_status enable')
        else:
            asic.run_sonic_db_cli_cmd.assert_not_called()


@pytest.mark.parametrize("path", ["tests/qos/test_qos_dscp_mapping.py"])
def test_local_config_commands_do_not_request_cluster_mode(path):
    text = (ROOT / path).read_text()
    assert "redis-cli -n 4 -c " not in text
    assert "sonic-db-cli CONFIG_DB " in text
