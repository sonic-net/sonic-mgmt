"""Hardware-free tests for the post-apply verification helpers.

These run without a DUT so that the logic which decides *what* gets verified is
itself verified. That matters more than it looks: an earlier bug in this area made
the ACL check silently verify nothing, and it went unnoticed precisely because the
logic lived in a module that could only be exercised on hardware.

Run with:
    pytest --noconftest tests/generic_config_updater/test_verify_patch_local.py
"""

import json
import os

import pytest

from tests.generic_config_updater.util.verify_patch import (
    compare_touched_entries,
    normalize_config,
    patch_cable_length_ports,
    patch_touched_entries,
    unescape_json_pointer,
)

# Hardware-free unit tests, but every test module under tests/ must carry a topology
# marker (enforced by .azure-pipelines/markers_check). 'any' is accurate here: these
# tests never touch a DUT, so no topology excludes them.
pytestmark = [
    pytest.mark.topology('any'),
]

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
NDM_REFERENCE_PATCH = os.path.join(THIS_DIR, "files", "ndm_addcluster_reference_patch.json")


def load_ndm_patch():
    with open(NDM_REFERENCE_PATCH) as f:
        return json.load(f)


class TestUnescapeJsonPointer:
    def test_slash_escape(self):
        assert unescape_json_pointer("10.0.0.56~131") == "10.0.0.56/31"

    def test_tilde_escape(self):
        assert unescape_json_pointer("a~0b") == "a~b"

    def test_escape_order(self):
        # '~01' must decode to '~1', not to '/'. Decoding '~0' first would produce
        # '~1' and a second pass would wrongly turn it into '/'.
        assert unescape_json_pointer("~01") == "~1"

    def test_plain_token_untouched(self):
        assert unescape_json_pointer("Ethernet316") == "Ethernet316"


class TestNormalizeConfig:
    def test_flat_config_passthrough(self):
        config = {"PORT": {"Ethernet0": {"admin_status": "up"}}}
        assert normalize_config(config) == config

    def test_localhost_namespace_unwrapped(self):
        tables = {"PORT": {"Ethernet0": {"admin_status": "up"}}}
        assert normalize_config({"localhost": tables}) == tables

    def test_empty_namespace_unwrapped(self):
        tables = {"PORT": {"Ethernet0": {"admin_status": "up"}}}
        assert normalize_config({"": tables}) == tables

    def test_non_dict_returns_empty(self):
        assert normalize_config(["not", "a", "config"]) == {}

    def test_localhost_as_a_real_table_key_is_not_unwrapped(self):
        # DEVICE_METADATA has a 'localhost' entry. A config whose namespace section
        # holds no upper-case table names must not be mistaken for a namespace wrapper.
        config = {"DEVICE_METADATA": {"localhost": {"hostname": "dut"}}}
        assert normalize_config(config) == config


class TestPatchTouchedEntries:
    def test_flat_add(self):
        touched = patch_touched_entries([{"op": "add", "path": "/PORT/Ethernet316", "value": {}}])
        assert touched == {"PORT": {"Ethernet316"}}

    def test_localhost_prefix_stripped(self):
        touched = patch_touched_entries(
            [{"op": "add", "path": "/localhost/PORT/Ethernet316", "value": {}}])
        assert touched == {"PORT": {"Ethernet316"}}

    def test_append_resolves_to_the_whole_entry(self):
        # An append to a field inside EVERFLOW must still mark the EVERFLOW entry for
        # comparison, so a patch that clobbers 'type' or drops an existing binding fails.
        touched = patch_touched_entries(
            [{"op": "add", "path": "/ACL_TABLE/EVERFLOW/ports/-", "value": "PortChannel1015"}])
        assert touched == {"ACL_TABLE": {"EVERFLOW"}}

    def test_three_segment_path_uses_the_entry_not_the_field(self):
        # CABLE_LENGTH is keyed by profile name, with per-port fields inside it.
        touched = patch_touched_entries(
            [{"op": "add", "path": "/CABLE_LENGTH/AZURE/Ethernet316", "value": "40m"}])
        assert touched == {"CABLE_LENGTH": {"AZURE"}}

    def test_escaped_key_is_decoded(self):
        touched = patch_touched_entries(
            [{"op": "add", "path": "/PORTCHANNEL_INTERFACE/PortChannel1015|10.0.0.56~131", "value": {}}])
        assert touched == {"PORTCHANNEL_INTERFACE": {"PortChannel1015|10.0.0.56/31"}}

    def test_whole_table_operation_is_skipped(self):
        # A path with a single segment addresses a whole table and has no entry key.
        assert patch_touched_entries([{"op": "add", "path": "/PORT", "value": {}}]) == {}

    def test_ndm_reference_patch_covers_every_table_it_touches(self):
        # Pins the verification scope against the real NDM patch. If patch generation
        # grows a new table, this test fails until verification covers it too.
        touched = patch_touched_entries(load_ndm_patch())
        assert set(touched) == {
            "PORTCHANNEL", "PORTCHANNEL_INTERFACE", "ACL_TABLE", "PORT",
            "DEVICE_NEIGHBOR", "PORT_QOS_MAP", "PFC_WD", "CABLE_LENGTH",
            "BUFFER_PG", "BUFFER_QUEUE", "QUEUE", "PORTCHANNEL_MEMBER",
            "DEVICE_NEIGHBOR_METADATA", "BGP_NEIGHBOR",
        }

    def test_ndm_reference_patch_buffer_and_queue_entries(self):
        # The buffer/queue operations were added when patch generation was aligned with
        # NDM. Verification must see them, or that alignment goes unchecked on hardware.
        touched = patch_touched_entries(load_ndm_patch())
        assert touched["BUFFER_PG"] == {"Ethernet316|0"}
        assert touched["BUFFER_QUEUE"] == {
            "Ethernet316|0-2", "Ethernet316|3-4", "Ethernet316|5-6"}
        assert touched["QUEUE"] == {"Ethernet316|{}".format(i) for i in range(7)}
        assert touched["PORTCHANNEL_INTERFACE"] == {
            "PortChannel1015",
            "PortChannel1015|10.0.0.56/31",
            "PortChannel1015|fc00::71/126",
        }


class TestCompareTouchedEntries:
    PATCH = [{"op": "add", "path": "/PORT/Ethernet316", "value": {}}]

    def test_identical_entries_report_no_difference(self):
        config = {"PORT": {"Ethernet316": {"speed": "400000", "admin_status": "up"}}}
        assert compare_touched_entries(config, config, self.PATCH) == []

    def test_wrong_field_value_is_reported(self):
        baseline = {"PORT": {"Ethernet316": {"speed": "400000"}}}
        actual = {"PORT": {"Ethernet316": {"speed": "100000"}}}
        differences = compare_touched_entries(baseline, actual, self.PATCH)
        assert len(differences) == 1
        assert "speed" in differences[0]
        assert "400000" in differences[0] and "100000" in differences[0]

    def test_missing_field_after_apply_is_reported(self):
        baseline = {"PORT": {"Ethernet316": {"speed": "400000", "fec": "rs"}}}
        actual = {"PORT": {"Ethernet316": {"speed": "400000"}}}
        differences = compare_touched_entries(baseline, actual, self.PATCH)
        assert len(differences) == 1
        assert "fec" in differences[0]

    def test_extra_field_after_apply_is_reported(self):
        baseline = {"PORT": {"Ethernet316": {"speed": "400000"}}}
        actual = {"PORT": {"Ethernet316": {"speed": "400000", "mtu": "9100"}}}
        differences = compare_touched_entries(baseline, actual, self.PATCH)
        assert len(differences) == 1
        assert "mtu" in differences[0]

    def test_entry_missing_after_apply_is_reported(self):
        baseline = {"PORT": {"Ethernet316": {"speed": "400000"}}}
        differences = compare_touched_entries(baseline, {"PORT": {}}, self.PATCH)
        assert differences == ["PORT|Ethernet316: missing after the patch was applied"]

    def test_entry_absent_from_baseline_is_reported(self):
        # Points at patch generation: the patch invents something the known-good
        # configuration never contained.
        differences = compare_touched_entries({"PORT": {}}, {"PORT": {}}, self.PATCH)
        assert len(differences) == 1
        assert "absent from the baseline" in differences[0]

    def test_ignored_fields_are_skipped(self):
        baseline = {"PORT": {"Ethernet316": {"speed": "400000", "index": "1"}}}
        actual = {"PORT": {"Ethernet316": {"speed": "400000", "index": "9"}}}
        assert compare_touched_entries(baseline, actual, self.PATCH, ignore_fields=["index"]) == []

    def test_untouched_entries_are_not_compared(self):
        # Scoping to the patch is what keeps this check from being flaky: unrelated
        # background churn in the running configuration must not fail the test.
        baseline = {"PORT": {"Ethernet316": {"speed": "400000"}, "Ethernet0": {"speed": "400000"}}}
        actual = {"PORT": {"Ethernet316": {"speed": "400000"}, "Ethernet0": {"speed": "10000"}}}
        assert compare_touched_entries(baseline, actual, self.PATCH) == []

    def test_acl_binding_clobbered_by_the_patch_is_caught(self):
        # The failure an existence check cannot see: the ACL entry is present, but the
        # patch replaced the port list instead of appending to it.
        patch = [{"op": "add", "path": "/ACL_TABLE/EVERFLOW/ports/-", "value": "PortChannel1015"}]
        baseline = {"ACL_TABLE": {"EVERFLOW": {
            "type": "MIRROR", "ports@": "PortChannel1001,PortChannel1015"}}}
        actual = {"ACL_TABLE": {"EVERFLOW": {
            "type": "MIRROR", "ports@": "PortChannel1015"}}}
        differences = compare_touched_entries(baseline, actual, patch)
        assert len(differences) == 1
        assert "PortChannel1001" in differences[0]

    def test_namespace_wrapped_actual_config_is_comparable(self):
        baseline = {"PORT": {"Ethernet316": {"speed": "400000"}}}
        actual = {"localhost": {"PORT": {"Ethernet316": {"speed": "400000"}}}}
        assert compare_touched_entries(baseline, actual, self.PATCH) == []

    def test_escaped_key_is_matched_against_the_config(self):
        patch = [{"op": "add",
                  "path": "/PORTCHANNEL_INTERFACE/PortChannel1015|10.0.0.56~131",
                  "value": {}}]
        baseline = {"PORTCHANNEL_INTERFACE": {"PortChannel1015|10.0.0.56/31": {}}}
        assert compare_touched_entries(baseline, baseline, patch) == []
        differences = compare_touched_entries(baseline, {"PORTCHANNEL_INTERFACE": {}}, patch)
        assert differences == [
            "PORTCHANNEL_INTERFACE|PortChannel1015|10.0.0.56/31: missing after the patch was applied"]

    def test_non_dict_entry_values_are_compared_directly(self):
        patch = [{"op": "add", "path": "/CABLE_LENGTH/AZURE", "value": "40m"}]
        baseline = {"CABLE_LENGTH": {"AZURE": "40m"}}
        actual = {"CABLE_LENGTH": {"AZURE": "5m"}}
        differences = compare_touched_entries(baseline, actual, patch)
        assert len(differences) == 1
        assert "40m" in differences[0] and "5m" in differences[0]


class TestPatchCableLengthPorts:
    """CABLE_LENGTH is the one table whose ports are fields rather than keys.

    Getting this wrong is silent: the lossless BUFFER_PG precondition check would
    pass vacuously because it saw no ports to demand a cable length for.
    """

    def test_per_port_paths(self):
        patch = [
            {"op": "add", "path": "/CABLE_LENGTH/AZURE/Ethernet316", "value": "500m"},
            {"op": "add", "path": "/CABLE_LENGTH/AZURE/Ethernet320", "value": "2000m"},
        ]
        assert patch_cable_length_ports(patch) == {
            "Ethernet316": "500m",
            "Ethernet320": "2000m",
        }

    def test_whole_hash_path(self):
        """A patch may add the entire AZURE hash in one op instead of per port."""
        patch = [{"op": "add", "path": "/CABLE_LENGTH/AZURE",
                  "value": {"Ethernet316": "500m", "Ethernet320": "2000m"}}]
        assert patch_cable_length_ports(patch) == {
            "Ethernet316": "500m",
            "Ethernet320": "2000m",
        }

    def test_remove_reports_none(self):
        patch = [{"op": "remove", "path": "/CABLE_LENGTH/AZURE/Ethernet316"}]
        assert patch_cable_length_ports(patch) == {"Ethernet316": None}

    def test_localhost_prefix_tolerated(self):
        patch = [{"op": "add", "path": "/localhost/CABLE_LENGTH/AZURE/Ethernet316",
                  "value": "500m"}]
        assert patch_cable_length_ports(patch) == {"Ethernet316": "500m"}

    def test_other_tables_ignored(self):
        patch = [
            {"op": "add", "path": "/PORT/Ethernet316", "value": {"speed": "100000"}},
            {"op": "add", "path": "/BUFFER_PG/Ethernet316|0", "value": {"profile": "x"}},
        ]
        assert patch_cable_length_ports(patch) == {}

    def test_zero_metre_is_reported_not_dropped(self):
        """0m means "no lossless PG" and must reach the caller as a real value.

        Treating it as absent would make the precondition check report a missing
        cable length, which is a different and misleading failure.
        """
        patch = [{"op": "add", "path": "/CABLE_LENGTH/AZURE/Ethernet316", "value": "0m"}]
        assert patch_cable_length_ports(patch) == {"Ethernet316": "0m"}

    def test_ndm_reference_patch(self):
        """The real NDM patch sets a cable length for exactly the port it adds."""
        patch = load_ndm_patch()
        cable_lengths = patch_cable_length_ports(patch)

        ports_added = {
            entry["path"].split("/")[-1] for entry in patch
            if entry["path"].startswith("/PORT/")
        }
        assert set(cable_lengths) == ports_added, (
            "NDM sets cable lengths for {} but adds ports {}".format(
                sorted(cable_lengths), sorted(ports_added)))
        assert cable_lengths == {"Ethernet316": "500m"}

    def test_ndm_reference_patch_pushes_no_lossless_pg(self):
        """NDM never pushes the auto-generated lossless PGs; buffermgrd creates them.

        BUFFER_PG|<port>|0 (lossy) is pushed, BUFFER_PG|<port>|3-4 is not -- while
        BUFFER_QUEUE|3-4 *is* pushed, because egress profiles are fixed names and the
        ingress lossless profile is parameterised by speed and cable length.
        """
        patch = load_ndm_patch()
        buffer_pg_paths = {
            entry["path"] for entry in patch if entry["path"].startswith("/BUFFER_PG/")
        }
        assert buffer_pg_paths == {"/BUFFER_PG/Ethernet316|0"}

        for entry in patch:
            value = json.dumps(entry.get("value", ""))
            assert "pg_lossless_" not in value, (
                "NDM reference patch unexpectedly references an auto-generated lossless "
                "profile in {}".format(entry["path"]))

        assert {"/BUFFER_QUEUE/Ethernet316|3-4"} <= {e["path"] for e in patch}
