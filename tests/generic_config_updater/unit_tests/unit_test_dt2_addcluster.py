"""Offline coverage of the isolated single-ASIC helper imports and legacy APIs."""

import ast
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import jsonpatch
import pytest


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


@pytest.mark.parametrize("single_asic", [True, False])
def test_minigraph_callers_keep_distinct_removal_behavior(tmp_path, single_asic):
    helpers = caller_helpers(single_asic)
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
    source, output = tmp_path / "original.xml", tmp_path / "reduced.xml"
    ET.ElementTree(root).write(source)

    refactor_class = helpers["MinigraphRefactor"]
    if single_asic:
        refactor = refactor_class("T1", {"Ethernet0": "etp1"})
        success, affected = refactor.process_minigraph(str(source), str(output))
        assert success and affected == {"Ethernet0"}
    else:
        refactor = refactor_class("T1")
        assert refactor.process_minigraph(str(source), str(output)) is True

    reduced = ET.parse(output).getroot()
    expected_channels = {"PortChannel2"} if single_asic else {"PortChannel1", "PortChannel2"}
    assert {node.text for node in reduced.findall(".//" + ns + "PortChannel/" + ns + "Name")} == expected_channels
    assert {node.text for node in reduced.findall(".//" + ns + "IPInterface/" + ns + "AttachTo")} == expected_channels
    assert [node.text for node in reduced.findall(".//" + ns + "BGPSession/" + ns + "EndRouter")] == ["OTHER_T1"]
    assert [node.text for node in reduced.findall(".//" + ns + "DeviceLinkBase/" + ns + "StartPort")] == ["Ethernet8"]
