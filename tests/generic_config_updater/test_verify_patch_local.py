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
    buffer_profile_exists,
    compare_touched_entries,
    config_db_key_exists,
    expected_lossless_profile_name,
    get_config_db_field,
    get_lossless_pg_entries,
    normalize_config,
    normalize_profile_reference,
    patch_added_ports,
    patch_cable_length_ports,
    patch_pushed_lossless_pgs,
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
REFERENCE_PATCH = os.path.join(THIS_DIR, "files", "addcluster_reference_patch.json")


def load_reference_patch():
    """A representative add-cluster patch: one T1 attached to one port via a LAG.

    Hand-written fixtures drift towards whatever the code already does. This one is
    shaped like a full add-cluster payload -- every table an added port touches, in
    the order a real patch carries them -- so the checks below are pinned against a
    realistic whole rather than against per-case snippets.
    """
    with open(REFERENCE_PATCH) as f:
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

    def test_reference_patch_covers_every_table_it_touches(self):
        # Pins the verification scope against a full add-cluster patch. If patch
        # generation grows a new table, this test fails until verification covers it too.
        touched = patch_touched_entries(load_reference_patch())
        assert set(touched) == {
            "PORTCHANNEL", "PORTCHANNEL_INTERFACE", "ACL_TABLE", "PORT",
            "DEVICE_NEIGHBOR", "PORT_QOS_MAP", "PFC_WD", "CABLE_LENGTH",
            "BUFFER_PG", "BUFFER_QUEUE", "QUEUE", "PORTCHANNEL_MEMBER",
            "DEVICE_NEIGHBOR_METADATA", "BGP_NEIGHBOR",
        }

    def test_reference_patch_buffer_and_queue_entries(self):
        # A port added without its buffer/queue entries comes up with default
        # buffering and no PFC. Verification must see these, or that goes unchecked
        # on hardware.
        touched = patch_touched_entries(load_reference_patch())
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

    def test_whole_table_path(self):
        """Regression: /CABLE_LENGTH is a single-segment path.

        Recognising only the 2- and 3-segment shapes reports a valid patch as missing
        cable lengths, failing the run on a correct configuration.
        """
        patch = [{"op": "add", "path": "/CABLE_LENGTH",
                  "value": {"AZURE": {"Ethernet316": "500m", "Ethernet320": "2000m"}}}]
        assert patch_cable_length_ports(patch) == {
            "Ethernet316": "500m", "Ethernet320": "2000m"}

    def test_whole_table_with_non_dict_profile_is_ignored(self):
        patch = [{"op": "add", "path": "/CABLE_LENGTH", "value": {"AZURE": "junk"}}]
        assert patch_cable_length_ports(patch) == {}

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

    def test_reference_patch(self):
        """Every port the patch adds gets a cable length in the same patch.

        Cable length is half the lossless profile lookup key. A port added without
        one gets no lossless BUFFER_PG, and nothing reports an error.
        """
        patch = load_reference_patch()
        cable_lengths = patch_cable_length_ports(patch)

        ports_added = {
            entry["path"].split("/")[-1] for entry in patch
            if entry["path"].startswith("/PORT/")
        }
        assert set(cable_lengths) == ports_added, (
            "cable lengths set for {} but ports added are {}".format(
                sorted(cable_lengths), sorted(ports_added)))
        assert cable_lengths == {"Ethernet316": "500m"}

    def test_reference_patch_pushes_no_lossless_pg(self):
        """An add-cluster patch must not carry the auto-generated lossless PGs.

        BUFFER_PG|<port>|0 (lossy) is pushed, BUFFER_PG|<port>|3-4 is not -- while
        BUFFER_QUEUE|3-4 *is* pushed, because egress profiles are fixed names and the
        ingress lossless profile is parameterised by speed and cable length, so
        buffermgrd has to derive it on link-up.
        """
        patch = load_reference_patch()
        buffer_pg_paths = {
            entry["path"] for entry in patch if entry["path"].startswith("/BUFFER_PG/")
        }
        assert buffer_pg_paths == {"/BUFFER_PG/Ethernet316|0"}

        for entry in patch:
            value = json.dumps(entry.get("value", ""))
            assert "pg_lossless_" not in value, (
                "reference patch unexpectedly references an auto-generated lossless "
                "profile in {}".format(entry["path"]))

        assert {"/BUFFER_QUEUE/Ethernet316|3-4"} <= {e["path"] for e in patch}


class TestPatchPushedLosslessPgs:
    """The patch must not carry pg_lossless_* BUFFER_PG entries itself."""

    PREFIX = "pg_lossless_"

    def test_per_entry_op_is_caught(self):
        patch = [{"op": "add", "path": "/BUFFER_PG/Ethernet316|3-4",
                  "value": {"profile": "pg_lossless_100000_500m_profile"}}]
        assert patch_pushed_lossless_pgs(patch, self.PREFIX) == ["/BUFFER_PG/Ethernet316|3-4"]

    def test_whole_table_op_is_caught(self):
        """Regression: a '/BUFFER_PG' op has no trailing slash.

        A substring test for '/BUFFER_PG/' silently misses this shape, which would let
        the very thing this check exists to prevent through untouched.
        """
        patch = [{"op": "add", "path": "/BUFFER_PG",
                  "value": {"Ethernet316|3-4": {"profile": "pg_lossless_100000_500m_profile"}}}]
        assert patch_pushed_lossless_pgs(patch, self.PREFIX) == ["/BUFFER_PG"]

    def test_localhost_wrapper_is_caught(self):
        patch = [{"op": "add", "path": "/localhost/BUFFER_PG/Ethernet316|3-4",
                  "value": {"profile": "pg_lossless_100000_500m_profile"}}]
        assert patch_pushed_lossless_pgs(patch, self.PREFIX) == [
            "/localhost/BUFFER_PG/Ethernet316|3-4"]

    def test_bracket_reference_form_is_caught(self):
        patch = [{"op": "add", "path": "/BUFFER_PG/Ethernet316|3-4",
                  "value": {"profile": "[BUFFER_PROFILE|pg_lossless_100000_500m_profile]"}}]
        assert patch_pushed_lossless_pgs(patch, self.PREFIX) == ["/BUFFER_PG/Ethernet316|3-4"]

    def test_lossy_pg_is_allowed(self):
        """BUFFER_PG|0 uses a fixed profile name and is pushed normally."""
        patch = [{"op": "add", "path": "/BUFFER_PG/Ethernet316|0",
                  "value": {"profile": "ingress_lossy_profile"}}]
        assert patch_pushed_lossless_pgs(patch, self.PREFIX) == []

    def test_table_named_like_a_prefix_is_not_matched(self):
        """BUFFER_PG_ANOTHER must not match on a startswith-style comparison."""
        patch = [{"op": "add", "path": "/BUFFER_PG_SOMETHING/Ethernet316|3-4",
                  "value": {"profile": "pg_lossless_100000_500m_profile"}}]
        assert patch_pushed_lossless_pgs(patch, self.PREFIX) == []

    def test_reference_patch_is_clean(self):
        assert patch_pushed_lossless_pgs(load_reference_patch(), self.PREFIX) == []


class TestPatchAddedPorts:
    """Preconditions apply to ports the patch *adds*, not every port it touches."""

    def test_whole_entry_add(self):
        patch = [{"op": "add", "path": "/PORT/Ethernet316",
                  "value": {"speed": "100000", "mtu": "9100"}}]
        assert patch_added_ports(patch) == {
            "Ethernet316": {"speed": "100000", "mtu": "9100"}}

    def test_whole_table_add(self):
        patch = [{"op": "add", "path": "/PORT",
                  "value": {"Ethernet316": {"speed": "100000"}}}]
        assert patch_added_ports(patch) == {"Ethernet316": {"speed": "100000"}}

    def test_single_field_add(self):
        patch = [{"op": "add", "path": "/PORT/Ethernet316/speed", "value": "100000"}]
        assert patch_added_ports(patch) == {"Ethernet316": {"speed": "100000"}}

    def test_replace_and_remove_are_not_adds(self):
        """A patch editing an existing port need not restate cable length or neighbor."""
        patch = [
            {"op": "replace", "path": "/PORT/Ethernet316/mtu", "value": "9000"},
            {"op": "remove", "path": "/PORT/Ethernet320"},
        ]
        assert patch_added_ports(patch) == {}

    def test_reference_patch(self):
        added = patch_added_ports(load_reference_patch())
        assert set(added) == {"Ethernet316"}
        assert added["Ethernet316"]["speed"] == "100000"

    def test_reference_added_ports_all_have_speed(self):
        """Speed is half the lossless profile lookup key; a port added without it
        gets no lossless BUFFER_PG and reports no error."""
        added = patch_added_ports(load_reference_patch())
        assert added and all(fields.get("speed") for fields in added.values())


class FakeDut:
    """Minimal stand-in for duthost, returning canned results per shell command.

    Lets the CONFIG_DB/APPL_DB parsing run in the hardware-free suite. That parsing is
    the risky part: each helper collapses a shell result into a boolean or a lookup, and
    every one of those failure modes is silent on a real device.
    """

    def __init__(self, responses, default=None):
        self.responses = responses
        self.default = default or {"rc": 0, "stdout": ""}
        self.commands = []

    def shell(self, cmd, module_ignore_errors=False):
        self.commands.append(cmd)
        for fragment, result in self.responses.items():
            if fragment in cmd:
                return result
        return self.default


def ok(stdout):
    return {"rc": 0, "stdout": stdout}


class TestNormalizeProfileReference:
    """SONiC writes the profile field as a bare name or as [BUFFER_PROFILE|name]."""

    def test_bare_name(self):
        assert normalize_profile_reference("pg_lossless_100000_500m_profile") == \
            "pg_lossless_100000_500m_profile"

    def test_bracket_reference(self):
        assert normalize_profile_reference("[BUFFER_PROFILE|pg_lossless_100000_500m_profile]") == \
            "pg_lossless_100000_500m_profile"

    def test_whitespace_and_empty(self):
        assert normalize_profile_reference("  ingress_lossy_profile \n") == "ingress_lossy_profile"
        assert normalize_profile_reference("") == ""
        assert normalize_profile_reference(None) == ""

    def test_bracket_without_table_prefix(self):
        assert normalize_profile_reference("[pg_lossless_100000_500m_profile]") == \
            "pg_lossless_100000_500m_profile"

    def test_malformed_reference_with_empty_name(self):
        """'[BUFFER_PROFILE|]' must normalise to empty, not to the table name.

        Returning 'BUFFER_PROFILE|' would be compared against a real profile name and
        produce a confusing mismatch rather than an obvious 'no profile' result.
        """
        assert normalize_profile_reference("[BUFFER_PROFILE|]") == ""
        assert normalize_profile_reference("[]") == ""


class TestExpectedLosslessProfileName:
    def test_matches_sonic_naming(self):
        assert expected_lossless_profile_name("100000", "500m") == \
            "pg_lossless_100000_500m_profile"

    def test_long_cable(self):
        assert expected_lossless_profile_name("400000", "20000m") == \
            "pg_lossless_400000_20000m_profile"


class TestGetConfigDbField:
    def test_returns_value(self):
        dut = FakeDut({"hget": ok("100000\n")})
        assert get_config_db_field(dut, "PORT|Ethernet316", "speed") == "100000"

    def test_failed_command_returns_empty(self):
        dut = FakeDut({"hget": {"rc": 1, "stdout": "boom"}})
        assert get_config_db_field(dut, "PORT|Ethernet316", "speed") == ""


class TestConfigDbKeyExists:
    def test_exact_match(self):
        dut = FakeDut({"keys": ok("BUFFER_PROFILE|pg_lossless_100000_500m_profile\n")})
        assert config_db_key_exists(dut, "BUFFER_PROFILE|pg_lossless_100000_500m_profile")

    def test_absent_key(self):
        dut = FakeDut({"keys": ok("")})
        assert not config_db_key_exists(dut, "BUFFER_PROFILE|nope")

    def test_command_failure_is_not_treated_as_present(self):
        dut = FakeDut({"keys": {"rc": 2, "stdout": ""}})
        assert not config_db_key_exists(dut, "BUFFER_PROFILE|x")


class TestGetLosslessPgEntries:
    PREFIX = "pg_lossless_"

    def test_finds_lossless_and_skips_lossy(self):
        dut = FakeDut({
            'keys "BUFFER_PG|Ethernet316|*"': ok(
                "BUFFER_PG|Ethernet316|0\nBUFFER_PG|Ethernet316|3-4\n"),
            'hget "BUFFER_PG|Ethernet316|0"': ok("ingress_lossy_profile"),
            'hget "BUFFER_PG|Ethernet316|3-4"': ok("pg_lossless_100000_500m_profile"),
        })
        assert get_lossless_pg_entries(dut, "Ethernet316", self.PREFIX) == {
            "BUFFER_PG|Ethernet316|3-4": "pg_lossless_100000_500m_profile"}

    def test_bracket_reference_form_is_recognised(self):
        """Regression: a startswith() test against the raw field misses this form and
        would report a correctly-created lossless PG as missing."""
        dut = FakeDut({
            'keys "BUFFER_PG|Ethernet316|*"': ok("BUFFER_PG|Ethernet316|3-4\n"),
            'hget': ok("[BUFFER_PROFILE|pg_lossless_100000_500m_profile]"),
        })
        assert get_lossless_pg_entries(dut, "Ethernet316", self.PREFIX) == {
            "BUFFER_PG|Ethernet316|3-4": "pg_lossless_100000_500m_profile"}

    def test_no_pgs_returns_empty(self):
        dut = FakeDut({'keys': ok("")})
        assert get_lossless_pg_entries(dut, "Ethernet316", self.PREFIX) == {}

    def test_command_failure_returns_empty(self):
        dut = FakeDut({'keys': {"rc": 1, "stdout": ""}})
        assert get_lossless_pg_entries(dut, "Ethernet316", self.PREFIX) == {}

    def test_only_queries_the_requested_port(self):
        dut = FakeDut({'keys': ok("")})
        get_lossless_pg_entries(dut, "Ethernet316", self.PREFIX)
        assert 'BUFFER_PG|Ethernet316|*' in dut.commands[0]


class TestBufferProfileExists:
    NAME = "pg_lossless_100000_500m_profile"

    def test_present_in_both(self):
        dut = FakeDut({
            'CONFIG_DB keys': ok("BUFFER_PROFILE|pg_lossless_100000_500m_profile"),
            'APPL_DB keys': ok("BUFFER_PROFILE_TABLE:pg_lossless_100000_500m_profile"),
        })
        assert buffer_profile_exists(dut, self.NAME) == (True, True)

    def test_config_db_only(self):
        dut = FakeDut({
            'CONFIG_DB keys': ok("BUFFER_PROFILE|pg_lossless_100000_500m_profile"),
            'APPL_DB keys': ok(""),
        })
        assert buffer_profile_exists(dut, self.NAME) == (True, False)

    def test_absent_from_both(self):
        dut = FakeDut({'CONFIG_DB keys': ok(""), 'APPL_DB keys': ok("")})
        assert buffer_profile_exists(dut, self.NAME) == (False, False)

    def test_similar_longer_name_does_not_count_as_present(self):
        """A profile whose name merely ends with ours must not satisfy the check."""
        dut = FakeDut({
            'CONFIG_DB keys': ok("BUFFER_PROFILE|xx_pg_lossless_100000_500m_profile"),
            'APPL_DB keys': ok("BUFFER_PROFILE_TABLE:xx_pg_lossless_100000_500m_profile"),
        })
        assert buffer_profile_exists(dut, self.NAME) == (False, False)
