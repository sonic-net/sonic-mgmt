"""SNMP database queries retain their local transport and namespace."""
import ast
from pathlib import Path
import shlex
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[2]


def load(relative, name, namespace, owner=None):
    path = ROOT / relative
    tree = ast.parse(path.read_text())
    body = tree.body
    if owner:
        body = next(n for n in body if isinstance(n, ast.ClassDef) and n.name == owner).body
    node = next(n for n in body if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), 'exec'), namespace)
    return namespace[name]


@pytest.mark.parametrize('namespace', [None, 'asic3'])
@pytest.mark.parametrize('port', ['Ethernet0', 'PortChannel1', 'eth0'])
def test_snmp_fact_collection_retains_status_queries(namespace, port):
    host = Mock()
    host.interface_facts.return_value = {'ansible_facts': {'ansible_interface_facts': {port: {'mtu': 9100}}}}
    host.config_facts.return_value = {
        'ansible_facts': {
            'port_name_to_alias_map': {'Ethernet0': 'fortyGigE0/0'},
            'PORT': {'Ethernet0': {'speed': '100000', 'admin_status': 'up'}},
            'PORTCHANNEL': {'PortChannel1': {'admin_status': 'up'}},
            'MGMT_PORT': {'eth0': {'admin_status': 'up'}},
        },
    }
    host.shell.return_value = {'stdout': 'up'}
    method = load('snmp/test_snmp_interfaces.py', 'collect_all_facts', {})
    result = method(host, [port], namespace)
    cmd = shlex.split(host.shell.call_args.args[0])
    prefix = ['sonic-db-cli', '-s'] + (['-n', namespace] if namespace else [])
    assert cmd[:len(prefix)] == prefix
    assert cmd[len(prefix)] == ('STATE_DB' if port == 'eth0' else 'APPL_DB')
    assert list(result.values())[0]['operstatus'] == 'up'
