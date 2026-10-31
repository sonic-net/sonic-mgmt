"""Check local dump commands without loading DUT integration fixtures."""
import ast
from enum import Enum
import json
import logging
import os
from pathlib import Path
import shlex
from types import SimpleNamespace
from typing import List
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_function(relative, name, namespace, class_name=None):
    path = ROOT / relative
    tree = ast.parse(path.read_text())
    body = tree.body
    if class_name:
        body = next(node for node in body if isinstance(node, ast.ClassDef) and node.name == class_name).body
    function = next(node for node in body if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace[name]


@pytest.fixture
def dump_builder():
    return load_function('common/devices/sonic.py', 'get_sonic_db_dump_command',
                         {'shlex': shlex}, 'SonicHost')


@pytest.mark.parametrize('supports_netns', [False, True])
@pytest.mark.parametrize('namespaces,release', [([], 'master'), (['asic0', 'asic1'], 'master'), ([], '201911')])
def test_failure_dump_preserves_database_and_namespace(namespaces, release, supports_netns, dump_builder):
    mapping = {'APPL_DB': 0, 'ASIC_DB': 1, 'COUNTERS_DB': 2, 'CONFIG_DB': 4, 'STATE_DB': 6}
    host = SimpleNamespace(is_multi_asic=bool(namespaces), sonic_release=release,
                           get_asic_namespace_list=lambda: namespaces)
    host.command = Mock(return_value={'stdout': '--netns NAMESPACE' if supports_netns else 'dump options'})
    host.get_sonic_db_dump_command = lambda db, namespace=None: dump_builder(host, db, namespace)

    class Hosts(list):
        pass

    hosts = Hosts([host])
    hosts.shell = Mock(return_value={'stdout': json.dumps({'DATABASES': {
        name: {'id': index} for name, index in mapping.items()}})})
    host.shell = hosts.shell
    host.shell_cmds = Mock()
    hosts.shell_cmds = Mock()
    hosts.fetch = Mock()
    namespace = {'os': os, 'json': json, 'safe_filename': lambda value: value}
    collect = load_function('conftest.py', 'collect_db_dump_on_duts', namespace)
    request = SimpleNamespace(node=SimpleNamespace(nodeid='test-local-dump', rep_call=SimpleNamespace(failed=True)))
    collect(request, hosts)
    expected_names = {name for name in mapping if name != 'STATE_DB' or release != '201911'}
    groups = (host.shell_cmds if namespaces else hosts.shell_cmds).call_args_list
    assert len(groups) == len(namespaces or [''])
    for group, netns in zip(groups, namespaces or ['']):
        commands = group.kwargs['cmds'][1:]
        assert len(commands) == len(expected_names)
        for name in expected_names:
            expected = 'sonic-db-dump -n {}'.format(name)
            if netns:
                if supports_netns:
                    expected += ' --netns ' + netns
                expected = 'sudo ip netns exec {} {}'.format(netns, expected)
            expected += ' -y -o /tmp/db_dump/test-local-dump'
            expected += ('/' + netns if netns else '') + '/' + str(mapping[name])
            assert expected in commands


@pytest.mark.parametrize('supports_netns', [False, True])
@pytest.mark.parametrize('namespace', [None, 'asic0'])
@pytest.mark.parametrize('family,key', [('ipv4', 'ROUTE_TABLE:0.0.0.0/0'), ('ipv6', 'ROUTE_TABLE:::/0')])
def test_default_route_dump_keeps_selected_asic(namespace, family, key, supports_netns, dump_builder):
    host = Mock()
    host.command.return_value = {'stdout': '--netns NAMESPACE' if supports_netns else 'dump options'}
    host.get_sonic_db_dump_command = lambda db, namespace=None: dump_builder(host, db, namespace)
    host.shell.return_value = {'stdout': '{}'}
    obj = SimpleNamespace(namespace=namespace, sonichost=host)
    method = load_function('common/devices/sonic_asic.py', 'get_default_route_from_app_db',
                           {'json': json, 'DEFAULT_NAMESPACE': None}, 'SonicAsic')
    assert method(obj, family) == {}
    command = host.shell.call_args.args[0]
    expected = 'sonic-db-dump -n APPL_DB'
    if namespace:
        if supports_netns:
            expected += ' --netns ' + namespace
        expected = 'sudo ip netns exec {} {}'.format(namespace, expected)
    assert command == expected + ' -y -k "{}" --pretty'.format(key)
    assert host.command.call_count == (1 if namespace else 0)


@pytest.mark.parametrize('db,name', [(0, 'APPL_DB'), (4, 'CONFIG_DB'), (6, 'STATE_DB')])
def test_dualtor_dump_keeps_database_and_key(db, name):
    host = Mock()
    host.shell.return_value = {'stdout_lines': ['{}']}
    method = load_function('common/dualtor/control_plane_utils.py', '_dump_db',
                           {'json': json, 'logger': Mock(),
                            'SONIC_DB_NAME_MAP': {0: 'APPL_DB', 4: 'CONFIG_DB', 6: 'STATE_DB'}}, 'DBChecker')
    assert method(SimpleNamespace(duthost=host), db, 'MUX*') == {}
    host.shell.assert_called_once_with('sonic-db-dump -n {} -k "MUX*"'.format(name))


@pytest.mark.parametrize('db,name', [(0, 'APPL_DB'), (1, 'ASIC_DB'), (4, 'CONFIG_DB')])
def test_nat_dump_keeps_database_and_value_format(db, name):
    execute = Mock(return_value={'rc': 0, 'stdout': '{"key":{"value":{"field":"value"},"ttl":5}}'})
    method = load_function('nat/nat_helpers.py', 'get_redis_val',
                           {'json': json, 'exec_command': execute,
                            'SONIC_DB_NAME_BY_ID': {0: 'APPL_DB', 1: 'ASIC_DB', 4: 'CONFIG_DB'}})
    host = Mock()
    assert method(host, db, 'NAT') == {'key': {'value': {'field': 'value'}}}
    execute.assert_called_once_with(host, ['sonic-db-dump -n {} --pretty -k *NAT*'.format(name)])


def test_snapshot_enum_names_map_to_named_databases(tmp_path):
    class DBType(Enum):
        APPL = 0
        ASIC = 1
        CONFIG = 4
        STATE = 6

    dump = Mock(return_value={})
    host = Mock(hostname='dut')
    obj = SimpleNamespace(_duthost=host, _snapshot_base_dir=str(tmp_path))
    method = load_function('common/db_comparison.py', 'take_snapshot',
                           {'List': List, 'DBType': DBType, 'logger': logging.getLogger(__name__),
                            'os': os, 'json': json, 'dut_dump': dump}, 'SonicRedisDBSnapshotter')
    method(obj, 'before', list(DBType))
    for db, call in zip(DBType, dump.call_args_list):
        assert call.args[0] == 'sonic-db-dump -n {}_DB --pretty'.format(db.name)
        assert call.args[3] == db.name


@pytest.mark.parametrize('name', ['CONFIG_DB', 'APPL_DB', 'STATE_DB'])
@pytest.mark.parametrize('keys', [[], ['TABLE']])
def test_configlet_dump_keeps_keys_and_database(tmp_path, name, keys):
    dump = Mock(return_value={})
    method = load_function('common/configlet/utils.py', 'get_dump',
                           {'dut_dump': dump, 'os': os, 'json': json, 'log_info': Mock()})
    info = {'sonic_db_name': name, 'keys_to_compare': keys,
            'keys_to_skip_comp': [], 'keys_skip_val_comp': []}
    method(Mock(), 'snapshot', info, str(tmp_path), str(tmp_path))
    expected = 'sonic-db-dump -n {} --pretty'.format(name)
    if keys:
        expected += ' -k "TABLE*"'
    assert dump.call_args.args[0] == expected


@pytest.mark.parametrize('supports_netns', [False, True])
@pytest.mark.parametrize('namespace', [None, 'asic0', 'asic with spaces'])
@pytest.mark.parametrize('database', ['CONFIG_DB', 'database with spaces'])
def test_dump_builder_quotes_arguments_and_probes_only_namespaces(
        dump_builder, supports_netns, namespace, database):
    host = Mock()
    host.command.return_value = {'stdout': '--netns NAMESPACE' if supports_netns else 'dump options'}
    command = dump_builder(host, database, namespace)
    expected = ['sonic-db-dump', '-n', database]
    if namespace is not None:
        if supports_netns:
            expected += ['--netns', namespace]
        expected = ['sudo', 'ip', 'netns', 'exec', namespace] + expected
        host.command.assert_called_once_with('sonic-db-dump --help')
    else:
        host.command.assert_not_called()
    assert shlex.split(command) == expected


def test_dump_builder_preserves_help_errors(dump_builder):
    host = Mock()
    host.command.side_effect = RuntimeError('dump executable is missing')
    with pytest.raises(RuntimeError, match='dump executable is missing'):
        dump_builder(host, 'CONFIG_DB', 'asic0')
    host.command.assert_called_once_with('sonic-db-dump --help')


@pytest.mark.parametrize('supports_netns', [False, True])
@pytest.mark.parametrize('namespace', [None, 'asic0'])
def test_default_route_dump_preserves_errors_without_retry(dump_builder, supports_netns, namespace):
    host = Mock()
    host.command.return_value = {'stdout': '--netns NAMESPACE' if supports_netns else 'dump options'}
    host.get_sonic_db_dump_command = lambda db, namespace=None: dump_builder(host, db, namespace)
    host.shell.side_effect = RuntimeError('database connection failed')
    method = load_function('common/devices/sonic_asic.py', 'get_default_route_from_app_db',
                           {'json': json}, 'SonicAsic')
    with pytest.raises(RuntimeError, match='database connection failed'):
        method(SimpleNamespace(namespace=namespace, sonichost=host))
    host.shell.assert_called_once()
    assert host.command.call_count == (1 if namespace else 0)


@pytest.mark.parametrize('supports_netns', [False, True])
@pytest.mark.parametrize('namespace', [None, 'asic0'])
def test_configlet_pfc_dump_keeps_namespace_and_filters(dump_builder, supports_netns, namespace):
    host = Mock(is_multi_asic=namespace is not None)
    host.command.return_value = {'stdout': '--netns NAMESPACE' if supports_netns else 'dump options'}
    host.get_sonic_db_dump_command = lambda db, namespace=None: dump_builder(host, db, namespace)
    host.get_frontend_asic_namespace_list.return_value = [namespace]
    host.shell.side_effect = [
        {'stdout': json.dumps({'DEVICE_METADATA|localhost': {'value': {'default_pfcwd_status': 'enable'}}})},
        {'stdout': '{"PFC_WD|Ethernet0": {}}'}]
    method = load_function('common/configlet/utils.py', 'chk_for_pfc_wd', {'json': json, 'log_debug': Mock()})
    assert method(host) is True
    expected = ['sonic-db-dump', '-n', 'CONFIG_DB']
    if namespace is not None:
        if supports_netns:
            expected += ['--netns', namespace]
        expected = ['sudo', 'ip', 'netns', 'exec', namespace] + expected
    assert shlex.split(host.shell.call_args.args[0]) == expected + ['--pretty', '-k', 'PFC_WD*']
    assert host.command.call_count == (1 if namespace else 0)


def test_failure_dumps_use_each_duts_namespace_capability(dump_builder):
    class Hosts(list):
        pass

    hosts = Hosts()
    for supports_netns in (False, True):
        host = SimpleNamespace(is_multi_asic=True, sonic_release='master',
                               get_asic_namespace_list=lambda: ['asic0'])
        host.command = Mock(return_value={'stdout': '--netns NAMESPACE' if supports_netns else 'dump options'})
        host.shell = Mock(return_value={'stdout': json.dumps({'DATABASES': {'CONFIG_DB': {'id': 4}}})})
        host.shell_cmds = Mock()
        host.get_sonic_db_dump_command = lambda db, namespace=None, host=host: dump_builder(host, db, namespace)
        hosts.append(host)
    hosts.shell = Mock()
    hosts.shell_cmds = Mock()
    hosts.fetch = Mock()
    collect = load_function('conftest.py', 'collect_db_dump_on_duts',
                            {'os': os, 'json': json, 'safe_filename': lambda value: value})
    request = SimpleNamespace(node=SimpleNamespace(nodeid='mixed-images', rep_call=SimpleNamespace(failed=True)))
    collect(request, hosts)
    prefixes = ['sudo ip netns exec asic0 sonic-db-dump -n CONFIG_DB',
                'sudo ip netns exec asic0 sonic-db-dump -n CONFIG_DB --netns asic0']
    for host, prefix in zip(hosts, prefixes):
        host.shell_cmds.assert_called_once_with(cmds=[
            'mkdir -p /tmp/db_dump/mixed-images/asic0',
            prefix + ' -y -o /tmp/db_dump/mixed-images/asic0/4'])
        host.command.assert_called_once_with('sonic-db-dump --help')
    hosts.shell_cmds.assert_not_called()
