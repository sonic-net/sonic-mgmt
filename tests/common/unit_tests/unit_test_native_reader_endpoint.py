"""Check explicit native-reader endpoints without importing testbed fixtures."""

import ast
import json
from pathlib import Path
import shlex
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[3]


class Asic:
    pass


@pytest.fixture
def helper():
    path = ROOT / 'tests/common/helpers/sonic_db.py'
    tree = ast.parse(path.read_text())
    definitions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in {'redis_cli_argv', 'redis_cli_command'}]
    namespace = {'SonicAsic': Asic, 'json': json, 'shlex': shlex}
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


@pytest.mark.parametrize('is_asic', [False, True])
@pytest.mark.parametrize('port', [0, 6380])
def test_reader_uses_database_instance_metadata(helper, is_asic, port):
    metadata = {'INSTANCES': {
        'primary': {'port': 6379, 'unix_socket_path': '/primary.sock'},
        'target': {'hostname': '127.0.0.2', 'port': port, 'unix_socket_path': '/target socket.sock'}},
        'DATABASES': {'CONFIG_DB': {'id': 71, 'instance': 'target'}}}
    host = Asic() if is_asic else Mock()
    host.run_redis_cmd = Mock(return_value=json.dumps(metadata, indent=2).splitlines())
    host.command = Mock(return_value={'stdout': json.dumps(metadata)})
    arguments = helper['redis_cli_argv'](host, 'CONFIG_DB')
    endpoint = ['-s', '/target socket.sock'] if port == 0 else ['-h', '127.0.0.2', '-p', '6380']
    assert arguments == ['redis-cli'] + endpoint + ['-n', '71']
    command = helper['redis_cli_command'](host, 'CONFIG_DB')
    assert shlex.split(command) == arguments
    if is_asic:
        assert host.run_redis_cmd.call_count == 2
        host.command.assert_not_called()
    else:
        assert host.command.call_count == 2
        host.run_redis_cmd.assert_not_called()
    assert '--user' not in arguments and '-a' not in arguments


def test_zero_port_without_socket_does_not_fall_back_to_tcp(helper):
    host = Mock()
    host.command.return_value = {'stdout': json.dumps({
        'INSTANCES': {'redis': {'port': 0}},
        'DATABASES': {'CONFIG_DB': {'id': 4, 'instance': 'redis'}}})}
    with pytest.raises(KeyError, match='unix_socket_path'):
        helper['redis_cli_argv'](host, 'CONFIG_DB')


@pytest.mark.parametrize('database', [4, '4'])
def test_numeric_reader_ids_stay_in_the_primary_instance(helper, database):
    host = Mock()
    host.command.return_value = {'stdout': json.dumps({
        'INSTANCES': {'redis': {'port': 0, 'unix_socket_path': '/primary.sock'},
                      'bmp': {'port': 6400}},
        'DATABASES': {'CONFIG_DB': {'id': 4, 'instance': 'redis'},
                      'OTHER_DB': {'id': 4, 'instance': 'bmp'}}})}
    assert helper['redis_cli_argv'](host, database) == ['redis-cli', '-s', '/primary.sock', '-n', '4']
