"""Exercise local socket and chassis TCP commands without DUT fixtures."""

import ast
import logging
from pathlib import Path
from types import MethodType, SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load_method(relative, class_name, method):
    source = ROOT / relative
    tree = ast.parse(source.read_text())
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    fn = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == method)
    namespace = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), 'exec'), namespace)
    return namespace[method]


@pytest.mark.parametrize('use_tcp', [False, True])
def test_host_command_preserves_explicit_transport(use_tcp):
    method = load_method('common/devices/sonic.py', 'SonicHost', 'run_sonic_db_cli_cmd')
    host = SimpleNamespace(command=Mock(return_value={'stdout': 'PONG'}))
    database = 'CHASSIS_APP_DB' if use_tcp else 'CONFIG_DB'
    assert method(host, database + ' PING', use_tcp=use_tcp) == {'stdout': 'PONG'}
    expected = 'sonic-db-cli ' + ('' if use_tcp else '-s ') + database + ' PING'
    host.command.assert_called_once_with(expected, verbose=False)


@pytest.mark.parametrize('use_tcp', [False, True])
def test_asic_command_preserves_namespace_and_transport(use_tcp):
    method = load_method('common/devices/sonic_asic.py', 'SonicAsic', 'run_sonic_db_cli_cmd')
    host = SimpleNamespace(sonichost=SimpleNamespace(command=Mock()),
                           sonic_db_cli='sonic-db-cli -s -n asic3', cli_ns_option='-n asic3')
    method(host, 'STATE_DB PING', use_tcp=use_tcp)
    prefix = 'sonic-db-cli -n asic3' if use_tcp else 'sonic-db-cli -s -n asic3'
    host.sonichost.command.assert_called_once_with(prefix + ' STATE_DB PING', verbose=False)


@pytest.mark.parametrize('class_name,database,use_tcp', [('SonicDbCli', 'APPL_DB', False),
                                                         ('VoqDbCli', 'CHASSIS_APP_DB', True)])
def test_database_helpers_keep_chassis_on_tcp(class_name, database, use_tcp):
    source = ROOT / 'common/helpers/sonic_db.py'
    tree = ast.parse(source.read_text())
    classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name in ('SonicDbCli', 'VoqDbCli')]
    namespace = {'logger': logging.getLogger(__name__)}
    exec(compile(ast.Module(body=classes, type_ignores=[]), str(source), 'exec'), namespace)
    command = Mock(return_value={'stdout': 'PONG', 'stdout_lines': ['PONG']})
    host = SimpleNamespace(command=command)
    host.run_sonic_db_cli_cmd = MethodType(
        load_method('common/devices/sonic.py', 'SonicHost', 'run_sonic_db_cli_cmd'), host)
    helper = namespace[class_name].__new__(namespace[class_name])
    helper.host, helper.database = host, database
    helper._run_and_raise(helper._cli_prefix() + 'PING')
    argv = command.call_args.args[0].split()
    assert argv == ['sonic-db-cli'] + ([] if use_tcp else ['-s']) + [database, 'PING']
