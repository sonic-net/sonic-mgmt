"""Check local dump commands without loading DUT integration fixtures."""
import ast
from enum import Enum
import json
import logging
import os
from pathlib import Path
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


@pytest.mark.parametrize('namespaces,release', [([], 'master'), (['asic0', 'asic1'], 'master'), ([], '201911')])
def test_failure_dump_preserves_database_and_namespace(namespaces, release):
    mapping = {'APPL_DB': 0, 'ASIC_DB': 1, 'COUNTERS_DB': 2, 'CONFIG_DB': 4, 'STATE_DB': 6}
    host = SimpleNamespace(is_multi_asic=bool(namespaces), sonic_release=release,
                           get_asic_namespace_list=lambda: namespaces)

    class Hosts(list):
        pass

    hosts = Hosts([host])
    hosts.shell = Mock(return_value={'stdout': json.dumps({'DATABASES': {
        name: {'id': index} for name, index in mapping.items()}})})
    host.shell = hosts.shell
    hosts.shell_cmds = Mock()
    hosts.fetch = Mock()
    namespace = {'os': os, 'json': json, 'safe_filename': lambda value: value}
    collect = load_function('conftest.py', 'collect_db_dump_on_duts', namespace)
    request = SimpleNamespace(node=SimpleNamespace(nodeid='test-local-dump', rep_call=SimpleNamespace(failed=True)))
    collect(request, hosts)
    expected_names = {name for name in mapping if name != 'STATE_DB' or release != '201911'}
    groups = hosts.shell_cmds.call_args_list
    assert len(groups) == len(namespaces or [''])
    for group, netns in zip(groups, namespaces or ['']):
        commands = group.kwargs['cmds'][1:]
        assert len(commands) == len(expected_names)
        for name in expected_names:
            expected = 'sonic-db-dump' + (' --netns ' + netns if netns else '')
            expected += ' -n {} -y -o /tmp/db_dump/test-local-dump'.format(name)
            expected += ('/' + netns if netns else '') + '/' + str(mapping[name])
            assert expected in commands


@pytest.mark.parametrize('namespace', [None, 'asic0'])
@pytest.mark.parametrize('family,key', [('ipv4', 'ROUTE_TABLE:0.0.0.0/0'), ('ipv6', 'ROUTE_TABLE:::/0')])
def test_default_route_dump_keeps_selected_asic(namespace, family, key):
    host = Mock()
    host.shell.return_value = {'stdout': '{}'}
    obj = SimpleNamespace(namespace=namespace, sonichost=host)
    method = load_function('common/devices/sonic_asic.py', 'get_default_route_from_app_db',
                           {'json': json, 'DEFAULT_NAMESPACE': None}, 'SonicAsic')
    assert method(obj, family) == {}
    command = host.shell.call_args.args[0]
    assert command == 'sonic-db-dump -n APPL_DB' + (' --netns ' + namespace if namespace else '') + \
        ' -y -k "{}" --pretty'.format(key)


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
