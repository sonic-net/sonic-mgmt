"""Offline regressions for maximum-breakout link inventory."""

import csv
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[3] / "ansible/scripts/map_breakout_links.py"
SPEC = importlib.util.spec_from_file_location("map_breakout_links", SCRIPT)
mapping = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mapping)


@pytest.fixture
def inputs(tmp_path):
    platform = tmp_path / "platform.json"
    platform.write_text(json.dumps({"interfaces": {
        "Ethernet0": {"lanes": "41,7", "breakout_modes": {
            "1x200G[100G]": ["etp1"], "2x100G": ["etp1a", "etp1b"]}},
        "Ethernet8": {"lanes": "93", "breakout_modes": {"1x10G": ["etp2"]}},
    }}))
    lookup = tmp_path / "pg_profile_lookup.ini"
    lookup.write_text("# speed cable size xon xoff threshold\n"
                      "100000 5m 100 20 30 1\n"
                      "100000 40m 200 20 40 2\n")
    links = tmp_path / "links.csv"
    with links.open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["StartDevice", "StartPort", "EndDevice", "EndPort", "BandWidth", "VlanID"])
        writer.writerows([
            ["dut", "Ethernet0", "leaf", "Ethernet1", "100000", "100"],
            ["leaf", "etp1a", "dut", "etp1b", "100000", "101"],
            ["dut", "Ethernet8", "arista", "Ethernet20", "10000", ""],
            ["leaf", "Ethernet8", "root", "Ethernet30", "10000", "102"],
        ])
    return platform, lookup, links


def run_mapping(inputs, excluded=()):
    platform, lookup, links = inputs
    device = mapping.load_device(platform)
    return mapping.build_mapping(links, "dut", "leaf", device, device,
                                 mapping.load_lookup(lookup), excluded)


def test_maps_explicit_lanes_reversed_rows_and_lookup(inputs):
    """Resolve by actual lane metadata and preserve wiring and lookup values."""
    before = [path.read_bytes() for path in inputs]
    result = run_mapping(inputs)
    first, second, excluded = result["links"]
    assert first["dut"]["lanes"] == [41]
    assert first["peer"]["lanes"] == [7]
    assert second["dut"]["port"] == "Ethernet1"
    assert first["eligible"] and second["eligible"]
    assert not excluded["eligible"]
    assert "Ethernet8" in result["protected_peer_cages"]
    mode = result["dut_mode_buffer_inputs"]["Ethernet0"]["1x200G[100G]"]
    assert mode["speeds_without_lookup"] == [200000]
    assert [case["cable"] for case in mode["buffer_cases"]] == ["5m", "40m"]
    assert mode["buffer_cases"][0]["size"] == "100"
    assert first["csv_attributes"]["VlanID"] == "100"
    assert [path.read_bytes() for path in inputs] == before


def test_exclusion_protects_whole_cage_on_both_ends(inputs):
    """One excluded child prevents breakout of its DUT and peer parent cages."""
    result = run_mapping(inputs, ["etp1a"])
    assert not any(link["eligible"] for link in result["links"])
    assert "Ethernet0" in result["protected_dut_cages"]
    assert "Ethernet0" in result["protected_peer_cages"]


@pytest.mark.parametrize("excluded", [False, True])
def test_shared_connection_freezes_dut_only_cleanup_unless_explicitly_excluded(inputs, excluded):
    """Outside-peer wiring fixes breakout but permits DUT forwarding cleanup unless explicitly excluded."""
    result = run_mapping(inputs, ["Ethernet8"] if excluded else [])
    assert result["dut_forwarding_cleanup_cages"] == ([] if excluded else ["Ethernet8"])
    assert "Ethernet8" in result["protected_dut_cages"]
    assert "Ethernet8" in result["protected_peer_cages"]
    assert not result["links"][-1]["eligible"]


def test_incomplete_shared_wiring_does_not_authorize_forwarding_cleanup(inputs):
    """A missing wiring channel keeps the whole shared-connected DUT cage fully protected."""
    links = inputs[2]
    lines = links.read_text().splitlines()
    links.write_text("\n".join(
        [lines[0], "dut,Ethernet0,shared-leaf,Ethernet36,100000,100"] + lines[-2:]) + "\n")
    result = run_mapping(inputs)
    assert "Ethernet0" in result["protected_dut_cages"]
    assert "Ethernet0" not in result["dut_forwarding_cleanup_cages"]


@pytest.mark.parametrize("mode,speed", [("1x10G", 10000), ("1x25G[10G]", 25000)])
@pytest.mark.parametrize("excluded", [False, True])
def test_low_speed_cages_are_eligible_unless_explicitly_excluded(inputs, mode, speed, excluded):
    """Dedicated 10G/25G cages participate normally and still honor explicit whole-cage protection."""
    platform, lookup, links = inputs
    document = json.loads(platform.read_text())
    document["interfaces"]["Ethernet8"]["breakout_modes"] = {mode: ["etp2"]}
    platform.write_text(json.dumps(document))
    lines = links.read_text().splitlines()[:3]
    lines.append("dut,Ethernet8,leaf,Ethernet8,{},102".format(speed))
    links.write_text("\n".join(lines) + "\n")
    result = run_mapping(inputs, ["Ethernet8"] if excluded else [])
    assert result["links"][0]["eligible"] and result["links"][1]["eligible"]
    assert result["links"][2]["eligible"] is (not excluded)
    expected = ["Ethernet8"] if excluded else []
    assert result["protected_dut_cages"] == result["protected_peer_cages"] == expected


def test_unrepresented_child_protects_cage(inputs):
    """An incomplete CSV cannot authorize changing an entire cage."""
    links = inputs[2]
    lines = links.read_text().splitlines()
    links.write_text("\n".join(lines[:2] + lines[3:]) + "\n")
    assert not run_mapping(inputs)["links"][0]["eligible"]


def test_peer_exclusion_propagates_through_connected_cages(tmp_path):
    """Protect connected cages transitively when peer and DUT cage boundaries differ."""
    dut = {"ports": {
        "d0": {"port": "d0", "cage": "D0", "supported_speeds": [100000]},
        "d1": {"port": "d1", "cage": "D0", "supported_speeds": [100000]},
        "d2": {"port": "d2", "cage": "D1", "supported_speeds": [100000]},
    }, "aliases": {}, "cages": {}}
    peer = {"ports": {
        "p0": {"port": "p0", "cage": "P0", "supported_speeds": [100000]},
        "p1": {"port": "p1", "cage": "P1", "supported_speeds": [100000]},
        "p2": {"port": "p2", "cage": "P1", "supported_speeds": [100000]},
        "reserved": {"port": "reserved", "cage": "P0", "supported_speeds": [100000]},
    }, "aliases": {}, "cages": {}}
    links = tmp_path / "links.csv"
    links.write_text("StartDevice,StartPort,EndDevice,EndPort,BandWidth\n"
                     "dut,d0,leaf,p0,100000\n"
                     "dut,d1,leaf,p1,100000\n"
                     "dut,d2,leaf,p2,100000\n")
    result = mapping.build_mapping(links, "dut", "leaf", dut, peer, [])
    assert result["protected_dut_cages"] == ["D0", "D1"]
    assert result["protected_peer_cages"] == ["P0", "P1"]
    assert not any(link["eligible"] for link in result["links"])


@pytest.mark.parametrize("mutation, message", [
    (lambda text: text.replace("dut,Ethernet0", "dut,Ethernet99"), "absent from"),
    (lambda text: text + text.splitlines()[1] + "\n", "Duplicate peer endpoint"),
    (lambda text: text.replace("100000,100", "200000,100"), "bandwidth is unsupported"),
])
def test_rejects_invalid_wiring(inputs, mutation, message):
    """Reject unresolved, duplicated, and speed-inconsistent physical endpoints."""
    links = inputs[2]
    links.write_text(mutation(links.read_text()))
    with pytest.raises(ValueError, match=message):
        run_mapping(inputs)


def test_derives_multilane_children_and_alternate_speeds(tmp_path):
    """Split ordered lanes with SONiC child offsets, not numeric hardware lane IDs."""
    platform = tmp_path / "platform.json"
    platform.write_text(json.dumps({"interfaces": {
        "Ethernet16": {"lanes": "90,12,71,3,64,6,25,1", "breakout_modes": {
            "1x800G": ["etp3"], "2x400G": ["etp3a", "etp3b"],
            "4x200G[100G]": ["etp3a", "etp3b", "etp3c", "etp3d"]}},
    }}))
    device = mapping.load_device(platform)
    assert list(device["ports"]) == ["Ethernet16", "Ethernet18", "Ethernet20", "Ethernet22"]
    assert device["ports"]["Ethernet18"]["lanes"] == [71, 3]
    assert device["ports"]["Ethernet18"]["supported_speeds"] == [100000, 200000]
    assert mapping.resolve_port(device, "etp3d")["lanes"] == [25, 1]
    assert device["cages"]["Ethernet16"]["maximum_breakout_modes"] == ["4x200G[100G]"]


@pytest.mark.parametrize("mixed", ["4x100G(4)+1x400G(4)", "1x400G(4)+4x100G(4)"])
def test_mixed_capabilities_do_not_hide_uniform_modes(tmp_path, mixed):
    """Keep advertised mixed modes while deriving wiring from the finest uniform partition."""
    platform = tmp_path / "platform.json"
    uniform = {"1x800G": ["etp1"], "8x100G": ["etp1{}".format(i) for i in range(8)]}
    platform.write_text(json.dumps({"interfaces": {
        "Ethernet0": {"lanes": "0,1,2,3,4,5,6,7", "breakout_modes": dict(
            uniform, **{mixed: ["mixed{}".format(i) for i in range(5)]})},
    }}))
    before = platform.read_bytes()
    device = mapping.load_device(platform)
    assert device["cages"]["Ethernet0"]["breakout_modes"] == dict(
        uniform, **{mixed: ["mixed{}".format(i) for i in range(5)]})
    assert device["cages"]["Ethernet0"]["maximum_breakout_modes"] == ["8x100G"]
    assert list(device["ports"]) == ["Ethernet{}".format(i) for i in range(8)]
    variant = (100000, 400000) if mixed.startswith("4x") else (400000, 100000)
    children = mapping.expand_mode("Ethernet0", device["cages"]["Ethernet0"], mixed, variant)
    assert [child["port"] for child in children] == (
        ["Ethernet0", "Ethernet1", "Ethernet2", "Ethernet3", "Ethernet4"] if mixed.startswith("4x")
        else ["Ethernet0", "Ethernet4", "Ethernet5", "Ethernet6", "Ethernet7"])
    assert [len(child["lanes"]) for child in children] == (
        [1, 1, 1, 1, 4] if mixed.startswith("4x") else [4, 1, 1, 1, 1])
    assert [child["speed"] for child in children] == (
        [100000] * 4 + [400000] if mixed.startswith("4x") else [400000] + [100000] * 4)
    assert platform.read_bytes() == before


@pytest.mark.parametrize("modes, message", [
    ({"3x100G": ["a", "b", "c"]}, "not divisible"),
    ({"2x100G": ["a"]}, "invalid aliases"),
    ({"2x100G": ["a", "b"], "2x50G": ["c", "d"]}, "ambiguous child aliases"),
    ({"2x100G": ["a", "a"]}, "Duplicate derived port"),
    ({"1x100G(2)+1x50G(2)": ["a", "b"]}, "assigned lane count differs"),
    ({"2x100G": ["a", "b"], "1x100G(1)+broken": ["a", "b"]}, "Unsupported breakout mode"),
])
def test_rejects_ambiguous_platform_layout(inputs, modes, message):
    """Reject incomplete or ambiguous platform layouts without a port-table fallback."""
    platform = inputs[0]
    data = json.loads(platform.read_text())
    data["interfaces"]["Ethernet0"]["breakout_modes"] = modes
    platform.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=message):
        run_mapping(inputs)


def test_rejects_ambiguous_cage_lanes(inputs):
    """A physical lane cannot belong to two parent cages."""
    platform = inputs[0]
    data = json.loads(platform.read_text())
    data["interfaces"]["Ethernet8"]["lanes"] = "41"
    platform.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="multiple cages"):
        run_mapping(inputs)


def test_multiple_maximum_modes_retain_all_speeds(inputs):
    """Equally split modes with consistent aliases contribute all advertised speeds."""
    platform = inputs[0]
    data = json.loads(platform.read_text())
    data["interfaces"]["Ethernet0"]["breakout_modes"]["2x50G"] = ["etp1a", "etp1b"]
    platform.write_text(json.dumps(data))
    assert mapping.load_device(platform)["ports"]["Ethernet0"]["supported_speeds"] == [50000, 100000]


def test_rejects_malformed_and_duplicate_lookup(inputs):
    """Reject lookup rows rather than guessing omitted buffer values."""
    lookup = inputs[1]
    lookup.write_text(lookup.read_text() + "100000 5m 1 2 3 4\n")
    with pytest.raises(ValueError, match="duplicate speed/cable"):
        run_mapping(inputs)
    lookup.write_text("# speed cable size xon xoff threshold\n100000 5m 1\n")
    with pytest.raises(ValueError, match="expected 6 columns"):
        run_mapping(inputs)


def test_mixed_operating_combinations_and_channel_speeds(tmp_path):
    """Mixed alternatives are ordered combinations, not a single speed shared by every child."""
    mode = "1x100G[50G](1)+1x200G[100G](1)"
    assert mapping.mode_variants(mode) == [
        (50000, 100000), (50000, 200000), (100000, 100000), (100000, 200000)]
    platform = tmp_path / "platform.json"
    platform.write_text(json.dumps({"interfaces": {
        "Ethernet0": {"lanes": "9,3", "breakout_modes": {mode: ["a", "b"]}},
    }}))
    device = mapping.load_device(platform)
    assert device["ports"]["Ethernet0"]["supported_speeds"] == [50000, 100000]
    assert device["ports"]["Ethernet1"]["supported_speeds"] == [100000, 200000]
    with pytest.raises(ValueError, match="Unsupported mode/speed"):
        mapping.expand_mode("Ethernet0", device["cages"]["Ethernet0"], mode, (200000, 100000))


def test_cli_outputs_json_or_actionable_error(inputs):
    """Exercise actual CLI serialization and failure status without device access."""
    platform, lookup, links = inputs
    command = [sys.executable, str(SCRIPT), "--hostname", "dut", "--peer-hostname", "leaf",
               "--platform-json", str(platform), "--peer-platform-json", str(platform),
               "--pg-profile-lookup", str(lookup), "--links-csv", str(links)]
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    assert len(json.loads(completed.stdout)["links"]) == 3
    platform.unlink()
    completed = subprocess.run(command, capture_output=True, text=True)
    assert completed.returncode == 1
    assert "Error:" in completed.stderr
    assert not completed.stdout
