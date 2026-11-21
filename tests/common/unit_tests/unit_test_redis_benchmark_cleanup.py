"""Run the benchmark cleanup command without gNMI or DUT fixtures."""
import ast
import fnmatch
from importlib.machinery import ModuleSpec
from pathlib import Path
import shlex
import sys
from types import ModuleType
from unittest.mock import Mock

import pytest


def cleanup_function():
    path = Path(__file__).resolve().parents[2] / 'gnmi_benchmark/helpers.py'
    function = next(node for node in ast.parse(path.read_text()).body
                    if isinstance(node, ast.FunctionDef) and node.name == '_remove_routes')
    namespace = {'shlex': shlex}
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['_remove_routes']


def test_cleanup_uses_local_login_and_preserves_unrelated_keys(monkeypatch):
    credentials = Mock(name="native_pool")
    keys = {'VNET_ROUTE_TUNNEL|Test_0|1/32', 'VNET_ROUTE_TUNNEL|Test_1|2/32',
            'VNET|Test_0', 'VXLAN_TUNNEL|TunnelTest',
            'VNET_ROUTE_TUNNEL|Other_0|1/32', 'VNET|Other_0', 'VXLAN_TUNNEL|Other'}
    unrelated = {key for key in keys if 'Other' in key}
    client = Mock()
    client.scan_iter.side_effect = lambda match: iter(sorted(key for key in keys if fnmatch.fnmatchcase(key, match)))
    client.delete.side_effect = lambda *names: keys.difference_update(names)
    redis = ModuleType('redis')
    redis.Redis = Mock(return_value=client)
    package = ModuleType('swsscommon')
    package.__path__ = []
    package.__spec__ = ModuleSpec('swsscommon', loader=None, is_package=True)
    auth = ModuleType('swsscommon.redis')
    auth.__spec__ = ModuleSpec('swsscommon.redis', loader=None)
    auth.connection_pool = Mock(return_value=credentials)
    monkeypatch.setitem(sys.modules, 'redis', redis)
    monkeypatch.setitem(sys.modules, 'swsscommon', package)
    if credentials is None:
        monkeypatch.delitem(sys.modules, 'swsscommon.redis', raising=False)
    else:
        monkeypatch.setitem(sys.modules, 'swsscommon.redis', auth)

    def shell(command, **kwargs):
        args = shlex.split(command)
        assert args[:2] == ['python3', '-c']
        exec(compile(args[2], '<DUT cleanup command>', 'exec'), {})
        return {'rc': 0}

    host = Mock()
    host.shell.side_effect = shell
    cleanup_function()(host, 'Test', 'TunnelTest')
    if credentials is None:
        auth.connection_pool.assert_not_called()
    else:
        auth.connection_pool.assert_called_once_with(unix_socket_path='/var/run/redis/redis.sock', db=4)
    redis.Redis.assert_called_once_with(connection_pool=credentials)
    assert keys == unrelated


def test_cleanup_reports_failed_dut_command():
    host = Mock()
    host.shell.return_value = {'rc': 1, 'stderr': 'missing selected writer credential'}
    with pytest.raises(RuntimeError, match='Unable to remove generated benchmark routes'):
        cleanup_function()(host, 'Test', 'TunnelTest')


def test_cleanup_does_not_ignore_errors_from_present_helper(monkeypatch):
    redis = ModuleType('redis')
    redis.Redis = Mock()
    package = ModuleType('swsscommon')
    package.__path__ = []
    package.__spec__ = ModuleSpec('swsscommon', loader=None, is_package=True)
    auth = ModuleType('swsscommon.redis')
    auth.__spec__ = ModuleSpec('swsscommon.redis', loader=None)
    auth.connection_pool = Mock(side_effect=RuntimeError('missing selected credential'))
    for name, module in [('redis', redis), ('swsscommon', package),
                         ('swsscommon.redis', auth)]:
        monkeypatch.setitem(sys.modules, name, module)
    host = Mock()
    host.shell.side_effect = lambda command, **kwargs: exec(shlex.split(command)[2], {})
    with pytest.raises(RuntimeError, match='missing selected credential'):
        cleanup_function()(host, 'Test', 'TunnelTest')
    redis.Redis.assert_not_called()
