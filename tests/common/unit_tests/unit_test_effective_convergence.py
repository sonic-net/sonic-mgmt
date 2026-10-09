"""Focused tests for effective converged-topology state."""

import ast
import functools
import importlib.util
import ipaddress
import sys
import types
from collections import OrderedDict
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[3]
MISSING = object()


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _load_function(path, name, namespace=None):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
    module = ast.Module(body=[function], type_ignores=[])
    ast.fix_missing_locations(module)
    globals_dict = dict(namespace or {})
    exec(compile(module, str(path), "exec"), globals_dict)
    return globals_dict[name]


@pytest.fixture(scope="module")
def testbed_module():
    if importlib.util.find_spec("ipaddr") is None:
        ipaddr = types.ModuleType("ipaddr")

        class IPNetwork:
            def __init__(self, value):
                interface = ipaddress.ip_interface(value)
                self.ip = interface.ip
                self.netmask = interface.netmask

        ipaddr.IPNetwork = IPNetwork
        sys.modules["ipaddr"] = ipaddr

    return _load_module("testbed_under_test", ROOT / "tests/common/testbed.py")


@pytest.fixture(scope="module")
def converger_module():
    return _load_module("ceos_topo_converger_under_test", ROOT / "ansible/ceos_topo_converger.py")


@pytest.fixture(scope="module")
def testbed_is_multi_vrf():
    return _load_function(ROOT / "tests/common/utilities.py", "testbed_is_multi_vrf")


@pytest.fixture(scope="module")
def get_vm_name_list(testbed_is_multi_vrf):
    return _load_function(
        ROOT / "tests/bgp/bgp_helpers.py",
        "get_vm_name_list",
        {"testbed_is_multi_vrf": testbed_is_multi_vrf},
    )


def _ordinary_topology():
    return {
        "topology": {"VMs": {"ARISTA01T1": {"vm_offset": 0, "vlans": []}}},
        "configuration": {"WRONG01T1": {}},
    }


def _converged_topology():
    return {
        "topo_is_multi_vrf": True,
        "convergence_data": {
            "convergence_mapping": {
                "ARISTA01T1": ["ARISTA01T1", "ARISTA02T1"],
            }
        },
        "topology": {"VMs": {"ARISTA01T1": {"vm_offset": 0, "vlans": []}}},
        "configuration": {"ARISTA01T1": {}, "ARISTA02T1": {}},
    }


def _parse_topology(testbed_module, tmp_path, properties, requested=MISSING):
    vars_dir = tmp_path / "vars"
    vars_dir.mkdir()
    (vars_dir / "topo_t0.yml").write_text(yaml.safe_dump(properties), encoding="utf-8")

    row = {"topo": "t0"}
    if requested is not MISSING:
        row["use_converged_peers"] = requested

    parser = testbed_module.TestbedInfo.__new__(testbed_module.TestbedInfo)
    parser.testbed_filename = str(tmp_path / "testbed.yaml")
    parser.testbed_topo = OrderedDict([("tb", row)])
    parser.TOPOLOGY_FILEPATH = "vars"
    parser.parse_topo()
    return parser.testbed_topo["tb"]


@pytest.mark.parametrize("requested", [True, "true", "True"])
def test_complete_topology_resolves_effective_true(
    testbed_module, testbed_is_multi_vrf, get_vm_name_list, tmp_path, requested
):
    tbinfo = _parse_topology(testbed_module, tmp_path, _converged_topology(), requested)

    assert tbinfo["use_converged_peers"] is True
    assert testbed_is_multi_vrf(tbinfo) is True
    assert get_vm_name_list(tbinfo, "T1") == ["ARISTA01T1", "ARISTA02T1"]


@pytest.mark.parametrize("requested", [True, "true", "True"])
def test_requested_but_unconverted_topology_resolves_effective_false(
    testbed_module, testbed_is_multi_vrf, get_vm_name_list, tmp_path, requested
):
    tbinfo = _parse_topology(testbed_module, tmp_path, _ordinary_topology(), requested)

    assert tbinfo["use_converged_peers"] is False
    assert testbed_is_multi_vrf(tbinfo) is False
    assert get_vm_name_list(tbinfo, "T1") == ["ARISTA01T1"]
    assert tbinfo["topo"]["properties"].get("convergence_data") is None


@pytest.mark.parametrize("requested", [MISSING, False, "false", "False"])
def test_false_or_missing_request_stays_false(testbed_module, tmp_path, requested):
    tbinfo = _parse_topology(testbed_module, tmp_path, _ordinary_topology(), requested)
    assert tbinfo["use_converged_peers"] is False


def test_loaded_converged_topology_is_authoritative_even_if_raw_request_is_false(testbed_module, tmp_path):
    tbinfo = _parse_topology(testbed_module, tmp_path, _converged_topology(), False)
    assert tbinfo["use_converged_peers"] is True


def test_internal_topology_marker_must_be_boolean(testbed_module, tmp_path):
    properties = _converged_topology()
    properties["topo_is_multi_vrf"] = "true"

    with pytest.raises(ValueError, match="topo_is_multi_vrf must be a boolean"):
        _parse_topology(testbed_module, tmp_path, properties, True)


@pytest.mark.parametrize(
    "convergence_data",
    [
        MISSING,
        {},
        {"convergence_mapping": {}},
        {"convergence_mapping": {"ARISTA01T1": []}},
    ],
)
def test_partial_converged_topology_is_rejected(testbed_module, tmp_path, convergence_data):
    properties = _ordinary_topology()
    properties["topo_is_multi_vrf"] = True
    if convergence_data is not MISSING:
        properties["convergence_data"] = convergence_data

    with pytest.raises(ValueError, match="Invalid converged topology.*convergence_mapping"):
        _parse_topology(testbed_module, tmp_path, properties, True)


@pytest.mark.parametrize(
    "value, expected",
    [(True, True), (False, False), ("true", True), ("True", True), ("false", False), (None, False)],
)
def test_consumer_helper_normalizes_effective_field(testbed_is_multi_vrf, value, expected):
    assert testbed_is_multi_vrf({"use_converged_peers": value}) is expected


def test_tbinfo_cache_is_process_local_and_can_be_cleared():
    loads = []

    class FakeTestbedInfo:
        def __init__(self, filename):
            self.filename = filename
            loads.append(filename)

    load_testbed_info = _load_function(
        ROOT / "tests/conftest.py",
        "_load_testbed_info",
        {"lru_cache": functools.lru_cache, "TestbedInfo": FakeTestbedInfo},
    )

    first = load_testbed_info("testbed.yaml")
    assert load_testbed_info("testbed.yaml") is first
    assert loads == ["testbed.yaml"]

    load_testbed_info.cache_clear()
    assert load_testbed_info("testbed.yaml") is not first
    assert loads == ["testbed.yaml", "testbed.yaml"]


def test_converter_postcondition_rejects_incomplete_output(converger_module, monkeypatch, tmp_path):
    source = tmp_path / "source.yml"
    output = tmp_path / "output.yml"
    source.write_text(yaml.safe_dump({"topology": {}}), encoding="utf-8")

    def write_incomplete(converger):
        output.write_text(yaml.safe_dump({"topo_is_multi_vrf": True}), encoding="utf-8")

    monkeypatch.setattr(converger_module.SonicTopoConverger, "run", write_incomplete)

    with pytest.raises(ValueError, match="convergence_mapping"):
        converger_module.converge_testbed(str(source), str(output))


def test_ceos_converter_still_emits_complete_converged_schema(converger_module, tmp_path):
    source = ROOT / "ansible/vars/topo_t0.yml"
    output = tmp_path / "topo_t0.yml"

    converger_module.converge_testbed(str(source), str(output))
    properties = yaml.safe_load(output.read_text(encoding="utf-8"))

    converger_module.validate_converged_topology(properties)
    assert properties["topo_is_multi_vrf"] is True
    assert properties["convergence_data"]["convergence_mapping"]
