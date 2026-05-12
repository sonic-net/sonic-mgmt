import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import ANY, MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/snappi_tests/snappi_fixtures.py")


class _DummySnappiPortConfig:
    def __init__(self, peer_port=None, **kwargs):
        self.peer_port = peer_port


class _DummySnappiPortType:
    RtrInterface = "RtrInterface"
    IPInterface = "IPInterface"


def _ensure_package(name):
    if name in sys.modules:
        return sys.modules[name]
    module = types.ModuleType(name)
    module.__path__ = []
    sys.modules[name] = module
    return module


def _install_stub_modules():
    for pkg in [
        "tests",
        "tests.common",
        "tests.common.fixtures",
        "tests.common.snappi_tests",
        "tests.common.helpers",
        "tests.common.macsec",
        "tests.common.snappi_tests.uhd",
    ]:
        _ensure_package(pkg)

    snappi_mod = types.ModuleType("snappi")
    snappi_mod.api = lambda *a, **k: object()
    sys.modules["snappi"] = snappi_mod

    errors_mod = types.ModuleType("tests.common.errors")

    class RunAnsibleModuleFail(Exception):
        pass

    errors_mod.RunAnsibleModuleFail = RunAnsibleModuleFail
    sys.modules["tests.common.errors"] = errors_mod

    conn_graph_mod = types.ModuleType("tests.common.fixtures.conn_graph_facts")
    conn_graph_mod.conn_graph_facts = object()
    conn_graph_mod.fanout_graph_facts = object()
    sys.modules["tests.common.fixtures.conn_graph_facts"] = conn_graph_mod

    common_helpers_mod = types.ModuleType("tests.common.snappi_tests.common_helpers")
    common_helpers_mod.get_addrs_in_subnet = lambda *a, **k: []
    common_helpers_mod.get_peer_snappi_chassis = lambda *a, **k: []
    common_helpers_mod.get_ipv6_addrs_in_subnet = lambda *a, **k: []
    common_helpers_mod.parse_override = lambda *a, **k: (False, None)
    sys.modules["tests.common.snappi_tests.common_helpers"] = common_helpers_mod

    snappi_helpers_mod = types.ModuleType("tests.common.snappi_tests.snappi_helpers")

    class SnappiFanoutManager:
        def __init__(self, *a, **k):
            pass

    snappi_helpers_mod.SnappiFanoutManager = SnappiFanoutManager
    snappi_helpers_mod.get_snappi_port_location = lambda *a, **k: ""
    snappi_helpers_mod.get_macs = lambda *a, **k: []
    snappi_helpers_mod.get_ip_addresses = lambda *a, **k: []
    snappi_helpers_mod.subnet_mask_from_hosts = lambda *a, **k: 24
    snappi_helpers_mod.get_dut_port_id = lambda *a, **k: None
    sys.modules["tests.common.snappi_tests.snappi_helpers"] = snappi_helpers_mod

    port_mod = types.ModuleType("tests.common.snappi_tests.port")
    port_mod.SnappiPortConfig = _DummySnappiPortConfig
    port_mod.SnappiPortType = _DummySnappiPortType
    sys.modules["tests.common.snappi_tests.port"] = port_mod

    assertions_mod = types.ModuleType("tests.common.helpers.assertions")
    assertions_mod.pytest_assert = lambda cond, msg="": (_ for _ in ()).throw(AssertionError(msg)) if not cond else None
    assertions_mod.pytest_require = assertions_mod.pytest_assert
    sys.modules["tests.common.helpers.assertions"] = assertions_mod

    vars_mod = types.ModuleType("tests.common.snappi_tests.variables")
    vars_mod.pfcQueueGroupSize = 8
    vars_mod.pfcQueueValueDict = {}
    vars_mod.dut_ip_start = "0.0.0.0"
    vars_mod.snappi_ip_start = "0.0.0.0"
    vars_mod.prefix_length = 24
    vars_mod.dut_ipv6_start = "::"
    vars_mod.snappi_ipv6_start = "::"
    vars_mod.v6_prefix_length = 64
    vars_mod.dut_ip_for_non_macsec_port = "0.0.0.0"
    sys.modules["tests.common.snappi_tests.variables"] = vars_mod

    macsec_mod = types.ModuleType("tests.common.macsec.macsec_config_helper")
    macsec_mod.set_macsec_profile = lambda *a, **k: None
    macsec_mod.enable_macsec_port = lambda *a, **k: None
    macsec_mod.disable_macsec_port = lambda *a, **k: None
    macsec_mod.delete_macsec_profile = lambda *a, **k: None
    sys.modules["tests.common.macsec.macsec_config_helper"] = macsec_mod

    uhd_mod = types.ModuleType("tests.common.snappi_tests.uhd.uhd_helpers")

    class NetworkConfigSettings:
        pass

    uhd_mod.NetworkConfigSettings = NetworkConfigSettings
    uhd_mod.create_front_panel_ports = lambda *a, **k: []
    uhd_mod.create_connections = lambda *a, **k: []
    uhd_mod.create_uhdIp_list = lambda *a, **k: []
    uhd_mod.create_arp_bypass = lambda *a, **k: []
    uhd_mod.create_profiles = lambda *a, **k: []
    sys.modules["tests.common.snappi_tests.uhd.uhd_helpers"] = uhd_mod


def _load_target_module():
    real_pytest = sys.modules.get("pytest")
    pytest_stub = types.ModuleType("pytest")
    fixture_decorator = (lambda *a, **k: a[0] if a and callable(a[0])
                         else lambda f: f)
    pytest_stub.fixture = fixture_decorator
    pytest_stub.FixtureRequest = object
    sys.modules["pytest"] = pytest_stub

    try:
        _install_stub_modules()
        spec = importlib.util.spec_from_file_location(
            "unit_target_snappi_fixtures", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        if real_pytest is not None:
            sys.modules["pytest"] = real_pytest
        else:
            del sys.modules["pytest"]

    return module


@pytest.fixture(scope="module")
def snappi_fixtures_module():
    return _load_target_module()


def test_tgen_port_info_override_path(snappi_fixtures_module):
    module = snappi_fixtures_module
    request = MagicMock()
    request.config.getoption.return_value = "tbname"
    request.param = {
        "rdma-subtype": {
            "tx_ports": [{"port_name": "Ethernet0", "hostname": "dut-a"}],
            "rx_ports": [{"port_name": "Ethernet4", "hostname": "dut-a"}],
        }
    }
    duthosts = [SimpleNamespace(hostname="dut-a")]
    get_snappi_ports = [{"name": "p1"}, {"name": "p2"}]
    number_of_tx_rx_ports = (1, 1)
    snappi_api = object()

    module.parse_override = MagicMock(return_value=(True, None))
    module.is_snappi_multidut = MagicMock(return_value=True)
    module.get_snappi_ports_for_rdma = MagicMock(return_value=[{"name": "rdma-port"}])
    module.snappi_dut_base_config = MagicMock(return_value=("cfg", ["pc"], ["sp"]))
    module._get_snappi_connected_dut_port = MagicMock(return_value="Ethernet0")
    module.setup_dut_ports = MagicMock()

    gen = module.tgen_port_info(
        request=request,
        snappi_port_selection={},
        get_snappi_ports=get_snappi_ports,
        number_of_tx_rx_ports=number_of_tx_rx_ports,
        duthosts=duthosts,
        snappi_api=snappi_api,
        conn_graph_facts={"graph": 1},
        fanout_graph_facts={"fanout": 1},
    )

    assert next(gen) == ("cfg", ["pc"], ["sp"])
    module.get_snappi_ports_for_rdma.assert_called_once()
    module._get_snappi_connected_dut_port.assert_called_once()

    with pytest.raises(StopIteration):
        next(gen)

    module.setup_dut_ports.assert_called_once_with(False, duthosts, "cfg", ["pc"], ["sp"])


def test_tgen_port_info_non_override_path(snappi_fixtures_module):
    module = snappi_fixtures_module
    request = MagicMock()
    request.config.getoption.return_value = "tbname"
    request.param = "100-single_linecard_single_asic"
    duthosts = [SimpleNamespace(hostname="dut-a")]

    module.parse_override = MagicMock(return_value=(False, None))
    module.snappi_dut_base_config = MagicMock(return_value=("cfg2", ["pc2"], ["sp2"]))
    module._get_snappi_connected_dut_port = MagicMock(return_value="Ethernet0")

    snappi_port_selection = {
        100.0: {
            "single_linecard_single_asic": [{"name": "port-a"}]
        }
    }

    gen = module.tgen_port_info(
        request=request,
        snappi_port_selection=snappi_port_selection,
        get_snappi_ports=[{"name": "unused"}],
        number_of_tx_rx_ports=(1, 1),
        duthosts=duthosts,
        snappi_api=object(),
        conn_graph_facts={"graph": 2},
        fanout_graph_facts={"fanout": 2},
    )

    with pytest.raises(StopIteration) as stop_info:
        next(gen)

    assert stop_info.value.value == ("cfg2", ["pc2"], ["sp2"])
    module.snappi_dut_base_config.assert_called_once_with(
        duthosts,
        [{"name": "port-a"}],
        ANY,
        setup=True,
    )
    module._get_snappi_connected_dut_port.assert_called_once()
