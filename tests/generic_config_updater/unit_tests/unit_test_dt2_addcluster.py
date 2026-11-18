"""Offline coverage of shared helpers and their legacy/single-ASIC entry points."""

import ast
import builtins
import importlib.util
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import jsonpatch
import pytest
from defusedxml.common import EntitiesForbidden


ROOT = Path(__file__).resolve().parents[1]


def caller_helpers(single_asic):
    """Execute the actual helper imports without loading native testbed fixtures."""
    filename = "test_dt2_addcluster.py" if single_asic else "test_multiasic_addcluster.py"
    path = ROOT / filename
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = [
        node for node in tree.body
        if isinstance(node, ast.ImportFrom)
        and (node.module or "").startswith(("tests.generic_config_updater.util.", "util."))
    ]
    namespace = {"__package__": "tests.generic_config_updater"}
    exec(compile(ast.Module(body=imports, type_ignores=[]), str(path), "exec"), namespace)
    return namespace


@pytest.mark.parametrize("single_asic", [True, False])
def test_callers_generate_patches_with_their_original_contracts(tmp_path, single_asic):
    helpers = caller_helpers(single_asic)
    current = {"DEVICE_NEIGHBOR_METADATA": {}}
    desired = {"DEVICE_NEIGHBOR_METADATA": {"T1": {"type": "LeafRouter"}}}
    if not single_asic:
        current, desired = {"asic0": current}, {"asic0": desired}
    full, reduced = tmp_path / "full.json", tmp_path / "reduced.json"
    full.write_text(json.dumps(desired))
    reduced.write_text(json.dumps(current))

    result = helpers["generate_config_patch"](str(full), str(reduced))
    if single_asic:
        patch_file, = result
    else:
        patch_file = result
    patch = json.loads(Path(patch_file).read_text())
    assert jsonpatch.apply_patch(current, patch) == desired


def write_minigraph(tmp_path):
    ns = "{Microsoft.Search.Autopilot.Evolution}"
    root = ET.Element(ns + "AutopilotGraph")
    sessions = ET.SubElement(root, ns + "PeeringSessions")
    png = ET.SubElement(root, ns + "PngDec")
    devices = ET.SubElement(png, ns + "Devices")
    links = ET.SubElement(png, ns + "DeviceInterfaceLinks")
    dpg = ET.SubElement(root, ns + "DeviceDataPlaneInfo")
    channels = ET.SubElement(dpg, ns + "PortChannelInterfaces")
    interfaces = ET.SubElement(dpg, ns + "IPInterfaces")
    for neighbor, port, alias, channel in [
        ("T1", "Ethernet0", "etp1", "PortChannel1"),
        ("OTHER_T1", "Ethernet8", "etp2", "PortChannel2"),
    ]:
        session = ET.SubElement(sessions, ns + "BGPSession")
        ET.SubElement(session, ns + "StartRouter").text = "DUT"
        ET.SubElement(session, ns + "EndRouter").text = neighbor
        device = ET.SubElement(devices, ns + "Device")
        ET.SubElement(device, ns + "Hostname").text = neighbor
        link = ET.SubElement(links, ns + "DeviceLinkBase")
        for key, value in {
            "StartDevice": "DUT", "StartPort": port,
            "EndDevice": neighbor, "EndPort": "Ethernet0",
        }.items():
            ET.SubElement(link, ns + key).text = value
        portchannel = ET.SubElement(channels, ns + "PortChannel")
        ET.SubElement(portchannel, ns + "Name").text = channel
        ET.SubElement(portchannel, ns + "AttachTo").text = alias
        interface = ET.SubElement(interfaces, ns + "IPInterface")
        ET.SubElement(interface, ns + "AttachTo").text = channel
    source = tmp_path / "original.xml"
    ET.ElementTree(root).write(source)
    return source


@pytest.mark.parametrize("single_asic", [True, False])
def test_minigraph_callers_keep_distinct_removal_behavior(tmp_path, single_asic):
    helpers = caller_helpers(single_asic)
    source, output = write_minigraph(tmp_path), tmp_path / "reduced.xml"
    refactor_class = helpers["MinigraphRefactor"]
    if single_asic:
        refactor = refactor_class("T1", {"Ethernet0": "etp1"})
        success, affected = refactor.process_minigraph(str(source), str(output))
        assert success and affected == {"Ethernet0"}
    else:
        refactor = refactor_class("T1")
        assert refactor.process_minigraph(str(source), str(output)) is True

    reduced = ET.parse(output).getroot()
    ns = "{Microsoft.Search.Autopilot.Evolution}"
    expected_channels = {"PortChannel2"} if single_asic else {"PortChannel1", "PortChannel2"}
    assert {node.text for node in reduced.findall(".//" + ns + "PortChannel/" + ns + "Name")} == expected_channels
    assert {node.text for node in reduced.findall(".//" + ns + "IPInterface/" + ns + "AttachTo")} == expected_channels
    assert [node.text for node in reduced.findall(".//" + ns + "BGPSession/" + ns + "EndRouter")] == ["OTHER_T1"]
    assert [node.text for node in reduced.findall(".//" + ns + "DeviceLinkBase/" + ns + "StartPort")] == ["Ethernet8"]


def test_legacy_generator_preserves_property_patches_and_table_filtering(tmp_path):
    helpers = caller_helpers(False)
    current = {"asic0": {
        "PORT": {"Ethernet0": {"lanes": "0,1,2,3", "speed": "100000", "admin_status": "up"}},
        "ACL_TABLE": {"MIRROR": {"type": "MIRROR", "ports": []}},
        "INTERFACE": {},
        "QUEUE": {},
    }}
    desired = json.loads(json.dumps(current))
    desired["asic0"]["PORT"]["Ethernet0"]["speed"] = "400000"
    desired["asic0"]["ACL_TABLE"]["MIRROR"]["ports"] = ["Ethernet0"]
    desired["asic0"]["INTERFACE"] = {"Ethernet0": {}, "Ethernet0|192.0.2.0/31": {}}
    desired["asic0"]["QUEUE"] = {"Ethernet0|0": {"scheduler": "scheduler.0"}}
    full, reduced = tmp_path / "full.json", tmp_path / "reduced.json"
    full.write_text(json.dumps(desired))
    reduced.write_text(json.dumps(current))

    patch_file = helpers["generate_config_patch"](str(full), str(reduced))
    patch = json.loads(Path(patch_file).read_text())
    assert {"op": "replace", "path": "/asic0/PORT/Ethernet0/speed", "value": "400000"} in patch
    expected = json.loads(json.dumps(desired))
    expected["asic0"]["INTERFACE"] = {}
    expected["asic0"]["QUEUE"] = {}
    assert jsonpatch.apply_patch(current, patch) == expected
    assert not (tmp_path / "generated_patch_metadata.json").exists()


@pytest.mark.parametrize("single_asic", [True, False])
def test_minigraph_callers_preserve_missing_neighbor_result(tmp_path, single_asic):
    helpers = caller_helpers(single_asic)
    source, output = write_minigraph(tmp_path), tmp_path / "reduced.xml"
    refactor = helpers["MinigraphRefactor"]("MISSING_T1")
    result = refactor.process_minigraph(str(source), str(output))
    if single_asic:
        success, affected = result
        assert success is False and affected == set()
    else:
        assert result is False
    assert ET.tostring(ET.parse(output).getroot()) == ET.tostring(ET.parse(source).getroot())


def test_single_asic_minigraph_still_rejects_entity_definitions(tmp_path):
    helpers = caller_helpers(True)
    source, output = write_minigraph(tmp_path), tmp_path / "reduced.xml"
    xml = source.read_text().replace(">T1<", ">&neighbor;<")
    source.write_text('<!DOCTYPE AutopilotGraph [<!ENTITY neighbor "T1">]>\n' + xml)
    with pytest.raises(EntitiesForbidden):
        helpers["MinigraphRefactor"]("T1").process_minigraph(str(source), str(output))
    assert not output.exists()


def test_legacy_helpers_do_not_require_single_asic_dependencies(tmp_path, monkeypatch):
    original_import = builtins.__import__

    def legacy_import(name, *args, **kwargs):
        if name.startswith("defusedxml") or name == "tests.generic_config_updater.util.verify_patch":
            raise ModuleNotFoundError(name)
        return original_import(name, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(builtins, "__import__", legacy_import)
        modules = {}
        for name in ("generate_patch", "process_minigraph"):
            spec = importlib.util.spec_from_file_location(name, ROOT / "util" / (name + ".py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            modules[name] = module
        full, reduced = tmp_path / "full.json", tmp_path / "reduced.json"
        full.write_text('{"asic0": {}}')
        reduced.write_text('{"asic0": {}}')
        patch_file = modules["generate_patch"].generate_config_patch(str(full), str(reduced))
        assert json.loads(Path(patch_file).read_text()) == []
        source = write_minigraph(tmp_path)
        refactor = modules["process_minigraph"].MinigraphRefactor("T1")
        assert refactor.process_minigraph(str(source), str(tmp_path / "reduced.xml")) is True
