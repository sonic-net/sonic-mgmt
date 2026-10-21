import ast
import json
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest


CASES = Path(__file__).resolve().parents[1] / 'cases'


def _method(filename, class_name, name, namespace):
    tree = ast.parse((CASES / filename).read_text())
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == class_name)
    method = next(node for node in cls.body
                  if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[method], type_ignores=[]), filename, 'exec'), namespace)
    return namespace[name]


@pytest.fixture
def port_loaders(monkeypatch):
    monkeypatch.syspath_prepend(str(CASES))
    from config.config_db_loader import ConfigDBLoader
    from config.port_config_ini_loader import PortConfigInILoader
    return ConfigDBLoader, PortConfigInILoader


def test_recreating_ports_preserves_the_ordered_config_objects(tmp_path, port_loaders):
    config_loader, ini_loader = port_loaders
    config_path = tmp_path / 'config.json'
    config_path.write_text(json.dumps({'PORT': {
        'Ethernet40': {'lanes': '40,41,42,43', 'speed': '400000'},
        'Ethernet8': {'lanes': '8,9,10,11', 'speed': '400000'},
    }}))
    ini_path = tmp_path / 'port_config.ini'
    ini_path.write_text('# name lanes index speed\n'
                        'Ethernet40 40,41,42,43 11 400000\n'
                        'Ethernet8 8,9,10,11 3 400000\n')
    ini = ini_loader(str(ini_path))
    ini.parse_port_config()
    ordered = config_loader(str(config_path)).get_port_config()
    case = SimpleNamespace(client=object(), ports_config=ordered,
                           port_config_ini_loader=ini)
    creations = []
    attrs = iter([{'number_of_active_ports': 0},
                  {'port_list': SimpleNamespace(idlist=[])}])
    namespace = {
        'sai_thrift_get_switch_attribute': lambda *a, **kw: next(attrs),
        'sai_thrift_object_list_t': SimpleNamespace,
        'sai_thrift_u32_list_t': SimpleNamespace,
        'sai_thrift_create_port': lambda *a, **kw: creations.append(kw),
        'SAI_PORT_FEC_MODE_RS': 1, 'SAI_PORT_FEC_MODE_FC': 2,
        'SAI_PORT_FEC_MODE_NONE': 0,
    }
    _method('sai_base_test.py', 'SaiHelperBase', 'createPorts', namespace)(case)
    assert case.ports_config is ordered
    assert [item.lanes for item in case.ports_config] == [[40, 41, 42, 43], [8, 9, 10, 11]]
    assert [item['hw_lane_list'].uint32list for item in creations] == [
        [40, 41, 42, 43], [8, 9, 10, 11]]


@pytest.mark.parametrize('platform', ['ctc', 'brcm', 'common'])
def test_logical_port_positions_keep_actual_nonconsecutive_ptf_ids(platform):
    case = SimpleNamespace(dev_port_list=[])
    namespace = {'config': {'interfaces': [(0, 18, 'eth18'), (0, 7, 'eth7')]},
                 'get_platform': lambda: platform}
    _method('sai_base_test.py', 'SaiHelperBase', 'getSwitchPorts', namespace)(case)
    assert case.dev_port_list == [18, 7]
    assert (case.dev_port0, case.dev_port1, case.tg0, case.tg1) == (18, 7, 18, 7)


def test_ini_object_positions_are_sequential(tmp_path, port_loaders):
    path = tmp_path / 'port_config.ini'
    path.write_text('# name lanes index speed\n'
                    'Ethernet40 40,41,42,43 11 400000\n'
                    'Ethernet8 8,9,10,11 3 400000\n')
    _, loader = port_loaders
    ports, objects = loader(str(path)).parse_port_config()
    assert list(objects) == [0, 1]
    assert [port.name for port in objects.values()] == list(ports)


def _sort_ports(configs, ports):
    namespace = {'List': List, 'PortConfig': SimpleNamespace, 'Port': SimpleNamespace}
    method = _method('config/port_configer.py', 'PortConfiger',
                     'sort_port_list_by_config', namespace)
    return method(None, configs, ports)


def test_lane_mapping_preserves_configuration_order():
    configs = [SimpleNamespace(name='Ethernet40', lanes=[40, 41]),
               SimpleNamespace(name='Ethernet8', lanes=[8, 9])]
    ports = [SimpleNamespace(oid=8, default_lane_list=[8, 9]),
             SimpleNamespace(oid=40, default_lane_list=[40, 41])]
    actual = _sort_ports(configs, ports)
    assert [port.oid for port in actual] == [40, 8]
    assert [port.config for port in actual] == configs


@pytest.mark.parametrize('lanes', [[], [[8, 9]], [[40, 41], [40, 41]]])
def test_missing_or_ambiguous_runtime_lanes_are_rejected(lanes):
    configs = [SimpleNamespace(name='Ethernet40', lanes=[40, 41])]
    ports = [SimpleNamespace(oid=index + 1, default_lane_list=value)
             for index, value in enumerate(lanes)]
    with pytest.raises(ValueError, match='Ethernet40'):
        _sort_ports(configs, ports)
