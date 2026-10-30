import ast
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/snappi_tests/snappi_fixtures.py")


def _assert(condition, message):
    assert condition, message


def _load_config_functions():
    names = {
        "is_snappi_multidut",
        "_snappi_port_link_training",
        "snappi_dut_base_config",
    }
    nodes = [node for node in ast.parse(MODULE_PATH.read_text()).body
             if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in nodes} == names
    namespace = {
        "logger": MagicMock(),
        "pytest_assert": _assert,
        "_config_pfc_classes": MagicMock(),
        "setup_dut_ports": lambda **kw: (
            kw["config"], kw["port_config_list"], kw["snappi_ports"]
        )
    }
    module = ast.Module(body=nodes, type_ignores=[])
    exec(compile(module, str(MODULE_PATH), "exec"), namespace)
    return namespace


def _dut(hostname, port_table, modular=False):
    host = MagicMock()
    host.hostname = hostname
    host.get_facts.return_value = {"modular_chassis": modular}
    host.config_facts.return_value = {"ansible_facts": {"PORT": port_table}}
    return host


def _port(peer_device, peer_port, index, namespace=None):
    port = {
        "peer_device": peer_device,
        "peer_port": peer_port,
        "location": "chassis/{}".format(index),
        "speed": "400000",
    }
    if namespace:
        port["asic_value"] = namespace
    return port


def _config():
    config = MagicMock()
    ports = []
    layer1_configs = []

    def add_port(name, location):
        port = SimpleNamespace(name=name, location=location)
        ports.append(port)
        return port

    def add_layer1():
        layer1 = MagicMock()
        layer1_configs.append(layer1)
        return [layer1]

    config.ports.port.side_effect = add_port
    config.ports.__iter__.side_effect = lambda: iter(ports)
    config.layer1.layer1.side_effect = add_layer1
    return config, layer1_configs


def _build(hosts, ports):
    namespace = _load_config_functions()
    config, layers = _config()
    api = MagicMock()
    api.config.return_value = config
    result = namespace["snappi_dut_base_config"](hosts, ports, api)
    assert result[0] is config
    assert len(result[2]) == len(ports)
    return layers, namespace


def _port_settings(layers):
    return [(layer.port_names, layer.auto_negotiation.link_training)
            for layer in layers]


def test_single_dut_mixed_settings_use_separate_layer1_configs():
    host = _dut("dut", {"Ethernet0": {"link_training": "off"}})
    ports = [_port("dut", "Ethernet0", 0), _port("dut", "Ethernet4", 1)]
    layers, namespace = _build([host], ports)
    assert _port_settings(layers) == [
        (["Port 0"], False), (["Port 1"], True)
    ]
    host.config_facts.assert_called_once_with(host="dut", source="running")
    assert namespace["_config_pfc_classes"].call_count == 2


def test_uniform_explicit_off_uses_one_layer1_config():
    host = _dut("dut", {
        "Ethernet0": {"link_training": "off"},
        "Ethernet4": {"link_training": "off"},
    })
    layers, namespace = _build([host], [
        _port("dut", "Ethernet0", 0), _port("dut", "Ethernet4", 1)
    ])
    assert _port_settings(layers) == [(["Port 0", "Port 1"], False)]
    assert layers[0].name == "L1 config"
    assert namespace["_config_pfc_classes"].call_count == 1


def test_multi_dut_uses_each_ports_actual_dut():
    first = _dut("first", {"Ethernet0": {"link_training": "on"}})
    second = _dut("second", {"Ethernet0": {"link_training": "off"}})
    ports = [_port("first", "Ethernet0", 0),
             _port("second", "Ethernet0", 1)]
    layers, _ = _build([first, second], ports)
    assert _port_settings(layers) == [
        (["Port 0"], True), (["Port 1"], False)
    ]
    first.config_facts.assert_called_once_with(host="first", source="running")
    second.config_facts.assert_called_once_with(
        host="second", source="running"
    )


@pytest.mark.parametrize("modular,hosts,expected", [
    (False, 1, True),
    (False, 2, False),
    (True, 1, False),
])
def test_unset_link_training_keeps_legacy_default(modular, hosts, expected):
    duts = [_dut("dut{}".format(i), {}, modular=modular) for i in range(hosts)]
    ports = [_port(duts[0].hostname, "Ethernet0", 0),
             _port(duts[0].hostname, "Ethernet4", 1)]
    layers, _ = _build(duts, ports)
    assert len(layers) == 1
    assert layers[0].port_names == ["Port 0", "Port 1"]
    assert layers[0].auto_negotiation.link_training is expected
    duts[0].config_facts.assert_called_once()


def test_modular_chassis_reads_each_port_namespace():
    host = _dut("dut", {}, modular=True)
    host.config_facts.side_effect = [
        {"ansible_facts": {"PORT": {"Ethernet0": {"link_training": "on"}}}},
        {"ansible_facts": {"PORT": {"Ethernet0": {"link_training": "off"}}}},
    ]
    ports = [_port("dut", "Ethernet0", 0, "asic0"),
             _port("dut", "Ethernet0", 1, "asic1")]
    layers, _ = _build([host], ports)
    assert [layer.auto_negotiation.link_training
            for layer in layers] == [True, False]
    assert host.config_facts.call_args_list[0].kwargs["namespace"] == "asic0"
    assert host.config_facts.call_args_list[1].kwargs["namespace"] == "asic1"


def test_single_asic_none_namespace_does_not_pass_namespace_argument():
    host = _dut("dut", {"Ethernet0": {"link_training": "off"}})
    layers, _ = _build([host], [_port("dut", "Ethernet0", 0, "None")])
    assert layers[0].auto_negotiation.link_training is False
    host.config_facts.assert_called_once_with(host="dut", source="running")


def test_failed_config_read_warns_and_uses_legacy_default():
    host = _dut("dut", {})
    host.config_facts.side_effect = RuntimeError("unavailable")
    layers, namespace = _build([host], [_port("dut", "Ethernet0", 0)])
    assert layers[0].auto_negotiation.link_training is True
    namespace["logger"].warning.assert_called_once()


def test_invalid_explicit_link_training_is_rejected():
    host = _dut("dut", {"Ethernet0": {"link_training": "unexpected"}})
    with pytest.raises(ValueError, match="Invalid link_training value"):
        _build([host], [_port("dut", "Ethernet0", 0)])
