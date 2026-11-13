import ast
from pathlib import Path
from types import SimpleNamespace

import pytest


SOURCE = (Path(__file__).resolve().parents[2] / 'cases' / 'ptf' / 'config'
          / 'port_configer.py')


def _method(name, namespace):
    tree = ast.parse(SOURCE.read_text(encoding='utf-8'))
    class_node = next(
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == 'PortConfiger')
    method = next(
        node for node in class_node.body
        if isinstance(node, ast.FunctionDef) and node.name == name)
    module = ast.Module(body=[method], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, str(SOURCE), 'exec'), namespace)
    return namespace[name]


@pytest.mark.parametrize('invalid_oid', (0, 0.0, None, 101.0))
def test_invalid_hostif_oid_is_not_sent_to_thrift(invalid_oid):
    for method_name in (
            'create_host_intf',
            'create_port_hostif_by_port_config_ini'):
        calls = []
        values = iter((invalid_oid, 101))
        namespace = {
            'List': list,
            'Port': object,
            'sai_thrift_create_hostif_table_entry': lambda *args, **kwargs: 11,
            'sai_thrift_create_hostif_trap': lambda *args, **kwargs: 12,
            'sai_thrift_create_hostif': lambda *args, **kwargs: next(values),
            'sai_thrift_set_hostif_attribute': (
                lambda *args, **kwargs: calls.append(kwargs['hostif_oid'])),
            'SAI_HOSTIF_TABLE_ENTRY_TYPE_WILDCARD': 1,
            'SAI_HOSTIF_TABLE_ENTRY_CHANNEL_TYPE_NETDEV_PHYSICAL_PORT': 2,
            'SAI_HOSTIF_TRAP_TYPE_TTL_ERROR': 3,
            'SAI_PACKET_ACTION_TRAP': 4,
            'SAI_HOSTIF_TYPE_NETDEV': 5,
            'SAI_NULL_OBJECT_ID': 0,
        }
        create = _method(method_name, namespace)
        ports = [
            SimpleNamespace(
                oid=100 + index,
                config=SimpleNamespace(name='Ethernet{}'.format(index + 1)),
                host_itf_id=None)
            for index in range(2)
        ]
        owner = SimpleNamespace(client=object())

        table, hostifs = create(owner, ports)

        assert table == 11
        assert hostifs == [None, 101]
        assert calls == [101]
        assert ports[0].host_itf_id is None
        assert ports[1].host_itf_id == 101
