"""Check network database commands without loading DUT fixtures."""

import ast
from pathlib import Path
import shlex
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


def test_bbr_presence_checks_keep_integer_output_during_fallback():
    namespace = load_definitions('tests/bgp/bgp_bbr_helpers.py', {'config_bbr_by_gcu'},
                                 {'logger': Mock(), 'time': Mock(),
                                  'redis_cli_command': lambda *_: 'redis-cli -s /configured.sock -n 4',
                                  'apply_gcu_patch': Mock(side_effect=RuntimeError('invalid patch'))})
    commands = []

    def execute(command, **kwargs):
        commands.append(command)
        return {'stdout': 'enabled' if ' HGET ' in command else '1'}

    namespace['config_bbr_by_gcu'](SimpleNamespace(shell=execute), 'enabled')
    assert commands[:2] == ['redis-cli -s /configured.sock -n 4 EXISTS "BGP_BBR|all"',
                            'redis-cli -s /configured.sock -n 4 HEXISTS "BGP_BBR|all" "status"']
    assert commands[-2:] == ['sonic-db-cli CONFIG_DB HSET "BGP_BBR|all" "status" "enabled"',
                             'sonic-db-cli CONFIG_DB HGET "BGP_BBR|all" "status"']


@pytest.mark.parametrize('filename', ['test_vxlan_bfd_tsa.py', 'test_vxlan_ecmp.py',
                                      'test_vxlan_ecmp_switchover.py'])
def test_cleanup_keeps_hash_key_and_field_separate(filename):
    tree = ast.parse((ROOT / 'tests/vxlan' / filename).read_text())
    command = next(node for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and isinstance(node.func, ast.Attribute) and node.func.attr == 'format'
                   and isinstance(node.func.value, ast.Constant)
                   and node.func.value.value.startswith('sonic-db-cli CONFIG_DB hdel '))
    text = eval(compile(ast.Expression(body=command), filename, 'eval'),
                {'redis_string': 'INTERFACE', 'intf': 'Ethernet0'})
    assert shlex.split(text) == ['sonic-db-cli', 'CONFIG_DB', 'hdel',
                                 'INTERFACE|Ethernet0', 'vnet_name']


@pytest.mark.parametrize("path", ["tests/sub_port_interfaces/conftest.py",
                                  "tests/vxlan/test_vxlan_decap.py"])
def test_local_config_commands_do_not_request_cluster_mode(path):
    text = (ROOT / path).read_text()
    assert "redis-cli -n 4 -c " not in text
    assert "sonic-db-cli CONFIG_DB " in text
