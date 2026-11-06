import ast
from pathlib import Path
from types import SimpleNamespace
from typing import List

import pytest


CASES = Path(__file__).resolve().parents[2] / 'cases' / 'ptf'


def _method(filename, class_name, name, namespace):
    tree = ast.parse((CASES / filename).read_text(encoding='utf-8'))
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == class_name)
    method = next(node for node in cls.body
                  if isinstance(node, ast.FunctionDef) and node.name == name)
    exec(compile(ast.Module(body=[method], type_ignores=[]), filename, 'exec'), namespace)
    return namespace[name]


def _class(filename, class_name, namespace):
    tree = ast.parse((CASES / filename).read_text(encoding='utf-8'))
    cls = next(node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == class_name)
    exec(compile(ast.Module(body=[cls], type_ignores=[]), filename, 'exec'), namespace)
    return namespace[class_name]


@pytest.mark.parametrize('platform', ['brcm', 'common'])
def test_logical_port_positions_follow_ptf_interface_order(platform):
    case = SimpleNamespace(dev_port_list=[])
    namespace = {
        'config': {'interfaces': [(0, 18, 'eth18'), (0, 7, 'eth7')]},
        'get_platform': lambda: platform,
    }

    _method('sai_base_test.py', 'SaiHelperBase', 'getSwitchPorts', namespace)(case)

    assert case.dev_port_list == [18, 7]
    assert (case.dev_port0, case.dev_port1, case.tg0, case.tg1) == (18, 7, 18, 7)


def test_lane_mapping_preserves_configuration_order():
    configs = [SimpleNamespace(name='Ethernet40', lanes=[40, 41]),
               SimpleNamespace(name='Ethernet8', lanes=[8, 9])]
    ports = [SimpleNamespace(oid=8, default_lane_list=[8, 9]),
             SimpleNamespace(oid=40, default_lane_list=[40, 41])]
    namespace = {'List': List, 'PortConfig': SimpleNamespace, 'Port': SimpleNamespace}
    method = _method(
        'config/port_configer.py', 'PortConfiger',
        'sort_port_list_by_config', namespace,
    )

    actual = method(None, configs, ports)

    assert [port.oid for port in actual] == [40, 8]
    assert [port.config for port in actual] == configs


class _SkipTest(Exception):
    pass


class _SaiHelperBase:
    def setUp(self):
        self.base_setup_called = True

    def tearDown(self):
        self.base_teardown_called = True


def _broadcom_autoneg_case():
    namespace = {
        'SaiHelperBase': _SaiHelperBase,
        'SkipTest': _SkipTest,
        'get_platform': lambda: 'brcm',
        'group': lambda _name: lambda cls: cls,
        'time': SimpleNamespace(sleep=lambda _seconds: None),
    }
    return _class('saiport.py', 'PortAutoNegAttributeTest', namespace)


def test_broadcom_autoneg_skips_without_injected_host_control():
    case = _broadcom_autoneg_case()()
    case.port30 = 30

    with pytest.raises(
            _SkipTest,
            match='requires an explicitly injected host-control transport'):
        case.setUp()
    assert not getattr(case, 'base_setup_called', False)


def test_broadcom_autoneg_uses_injected_host_control_for_setup_and_restore():
    class Transport:
        def __init__(self):
            self.commands = []

        def exec_command(self, command):
            self.commands.append(command)
            return None, None, None

    transport = Transport()
    case = _broadcom_autoneg_case()()
    case.port30 = 30
    case.ssh = transport

    case.setUp()
    case._restore_broadcom_host_control()

    assert case.base_setup_called is True
    assert transport.commands == [
        'config interface autoneg Ethernet31 enabled',
        'config interface autoneg Ethernet31 disabled',
        "docker exec syncd sh -c 'bcmcmd \"bsh -c '\\''lt pc_port update "
        "LINK_TRAINING=1 PORT_ID=125'\\''\"'",
    ]


def test_broadcom_autoneg_setup_failure_restores_and_tears_down():
    class Transport:
        def __init__(self):
            self.commands = []

        def exec_command(self, command):
            self.commands.append(command)
            if command.endswith('enabled'):
                raise RuntimeError('setup failed')
            return None, None, None

    case = _broadcom_autoneg_case()()
    case.port30 = 30
    case.ssh = Transport()

    with pytest.raises(RuntimeError, match='setup failed'):
        case.setUp()

    assert case.base_setup_called is True
    assert case.base_teardown_called is True
    assert case.ssh.commands[1:] == [
        'config interface autoneg Ethernet31 disabled',
        "docker exec syncd sh -c 'bcmcmd \"bsh -c '\\''lt pc_port update "
        "LINK_TRAINING=1 PORT_ID=125'\\''\"'",
    ]
