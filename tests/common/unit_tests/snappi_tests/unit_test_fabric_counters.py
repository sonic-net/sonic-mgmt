"""Unit tests for the fabric counter clear/check helpers in
``tests/common/snappi_tests/snappi_fixtures.py`` (issue #27863).

The target module imports heavy sonic-mgmt/ansible/snappi deps at import
time, so -- following the convention in unit_test_common_helpers.py -- we
extract just the definitions under test via ``ast`` and exec them in an
isolated namespace instead of importing the module directly.

Run with::

    python3 -m pytest --noconftest \\
        tests/common/unit_tests/snappi_tests/unit_test_fabric_counters.py -v
"""

import ast
from pathlib import Path
from enum import Enum
from unittest.mock import MagicMock

import pytest

MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/snappi_tests/snappi_fixtures.py")


class _FakeRunAnsibleModuleFail(Exception):
    """Stand-in for tests.common.errors.RunAnsibleModuleFail, which itself
    requires the (unavailable in this unit-test environment) ansible
    package to import. Only its name needs to exist for the extracted
    functions' `except RunAnsibleModuleFail:` clauses to resolve."""

    def __init__(self, msg, results=None):
        super().__init__(msg)
        self.results = results


def _load(*names):
    """Extract one or more top-level definitions (functions, classes, or
    simple module-level assignments) from snappi_fixtures.py by name, and
    exec them together in one isolated namespace so interdependent pieces
    (e.g. a function and the Enum/exception it references) resolve
    correctly without importing the whole module.
    """
    tree = ast.parse(MODULE_PATH.read_text())
    wanted = set(names)
    nodes = []
    found = set()
    for node in tree.body:
        node_name = getattr(node, "name", None)
        if node_name in wanted:
            nodes.append(node)
            found.add(node_name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in wanted:
                    nodes.append(node)
                    found.add(target.id)
    missing = wanted - found
    if missing:
        raise LookupError(sorted(missing))

    ns = {
        "Enum": Enum,
        "logger": MagicMock(),
        "RunAnsibleModuleFail": _FakeRunAnsibleModuleFail,
    }
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(MODULE_PATH), "exec"), ns)
    if len(names) == 1:
        return ns[names[0]]
    return tuple(ns[name] for name in names)


# ---------------------------------------------------------------------------
# fabric_capable
# ---------------------------------------------------------------------------

def test_fabric_capable_non_dnx_excluded():
    fabric_capable = _load("fabric_capable")
    facts = {"platform_asic": "cisco-8000", "modular_chassis": True, "num_asic": 8}
    assert fabric_capable(facts) is False


def test_fabric_capable_standalone_single_asic_dnx_excluded():
    fabric_capable = _load("fabric_capable")
    facts = {"platform_asic": "broadcom-dnx", "modular_chassis": False, "num_asic": 1}
    assert fabric_capable(facts) is False


def test_fabric_capable_fixed_multi_asic_dnx_included():
    fabric_capable = _load("fabric_capable")
    facts = {"platform_asic": "broadcom-dnx", "modular_chassis": False, "num_asic": 4}
    assert fabric_capable(facts) is True


def test_fabric_capable_single_asic_modular_chassis_lc_included():
    fabric_capable = _load("fabric_capable")
    facts = {"platform_asic": "broadcom-dnx", "modular_chassis": True, "num_asic": 1}
    assert fabric_capable(facts) is True


def test_fabric_capable_modular_chassis_supervisor_included():
    fabric_capable = _load("fabric_capable")
    facts = {"platform_asic": "broadcom-dnx", "modular_chassis": True, "num_asic": 12}
    assert fabric_capable(facts) is True


# ---------------------------------------------------------------------------
# parse_fabric_counter_rows
# ---------------------------------------------------------------------------

_ASIC_PRESENT_OUTPUT = """\
    ASIC    PORT    STATE    IN_CELL    OUT_CELL    CRC    FEC_CORRECTABLE    FEC_UNCORRECTABLE
    ----    ----    -----    -------    --------    ---    ---------------    ------------------
       0       0       up          0       1,234      0                  0                     0
       0       1     down          0           0      0                  0                     0
       0       2       up          0           5     12                  3                     4
"""

_ASIC_ABSENT_OUTPUT = """\
    PORT    STATE    IN_CELL    OUT_CELL    CRC    FEC_CORRECTABLE    FEC_UNCORRECTABLE
    ----    -----    -------    --------    ---    ---------------    ------------------
       0       up          0       1,234      0                  0                     0
"""

_REORDERED_EXTRA_OUTPUT = """\
    PORT    EXTRA_COL    STATE    FEC_UNCORRECTABLE    CRC
    ----    ---------    -----    ------------------    ---
       3           99       up                     0      5
"""

_REPEATED_HEADER_OUTPUT = """\
ASIC    PORT    STATE    CRC    FEC_UNCORRECTABLE
----    ----    -----    ---    ------------------
   0       0       up      0                     0
   0       1       up     12                     4

ASIC    PORT    STATE    CRC    FEC_UNCORRECTABLE
----    ----    -----    ---    ------------------
   1       0       up      0                     0
"""


def _load_parse_fabric_counter_rows():
    # _FABRIC_REQUIRED_COLUMNS is referenced unconditionally (not just on the
    # error path), so it must always be loaded alongside the parser.
    parse_fabric_counter_rows, _ = _load("parse_fabric_counter_rows", "_FABRIC_REQUIRED_COLUMNS")
    return parse_fabric_counter_rows


def test_parse_fabric_counter_rows_with_asic_column():
    parse_fabric_counter_rows = _load_parse_fabric_counter_rows()
    rows = parse_fabric_counter_rows(_ASIC_PRESENT_OUTPUT)
    assert len(rows) == 3
    assert rows[0]["ASIC"] == "0" and rows[0]["PORT"] == "0" and rows[0]["STATE"] == "up"
    assert rows[2]["CRC"] == "12" and rows[2]["FEC_UNCORRECTABLE"] == "4"


def test_parse_fabric_counter_rows_without_asic_column():
    parse_fabric_counter_rows = _load_parse_fabric_counter_rows()
    rows = parse_fabric_counter_rows(_ASIC_ABSENT_OUTPUT)
    assert len(rows) == 1
    assert "ASIC" not in rows[0]
    assert rows[0]["PORT"] == "0"
    assert rows[0]["CRC"] == "0"


def test_parse_fabric_counter_rows_reordered_and_extra_columns():
    parse_fabric_counter_rows = _load_parse_fabric_counter_rows()
    rows = parse_fabric_counter_rows(_REORDERED_EXTRA_OUTPUT)
    assert len(rows) == 1
    row = rows[0]
    # Values must be read by column NAME, independent of position/extra columns.
    assert row["PORT"] == "3"
    assert row["EXTRA_COL"] == "99"
    assert row["FEC_UNCORRECTABLE"] == "0"
    assert row["CRC"] == "5"


def test_parse_fabric_counter_rows_repeated_header_blocks():
    parse_fabric_counter_rows = _load_parse_fabric_counter_rows()
    rows = parse_fabric_counter_rows(_REPEATED_HEADER_OUTPUT)
    assert len(rows) == 3
    assert [r["ASIC"] for r in rows] == ["0", "0", "1"]


def test_parse_fabric_counter_rows_missing_required_column_raises():
    parse_fabric_counter_rows, FabricCounterParseError, _ = _load(
        "parse_fabric_counter_rows", "FabricCounterParseError", "_FABRIC_REQUIRED_COLUMNS")
    raw = "ASIC    PORT    STATE    CRC\n----    ----    -----    ---\n"
    with pytest.raises(FabricCounterParseError):
        parse_fabric_counter_rows(raw)


def test_parse_fabric_counter_rows_no_header_raises():
    parse_fabric_counter_rows, FabricCounterParseError = _load(
        "parse_fabric_counter_rows", "FabricCounterParseError")
    with pytest.raises(FabricCounterParseError):
        parse_fabric_counter_rows("   \n   \n")


def test_parse_fabric_counter_rows_data_row_before_header_raises():
    parse_fabric_counter_rows, FabricCounterParseError = _load(
        "parse_fabric_counter_rows", "FabricCounterParseError")
    with pytest.raises(FabricCounterParseError):
        parse_fabric_counter_rows("0    0    up    0    0\n")


# ---------------------------------------------------------------------------
# parse_fabric_counter_value
# ---------------------------------------------------------------------------

def _load_parse_fabric_counter_value():
    # _FABRIC_NA_VALUE is referenced unconditionally, so it must always be
    # loaded alongside the function.
    parse_fabric_counter_value, _, _fcpe = _load(
        "parse_fabric_counter_value", "_FABRIC_NA_VALUE", "FabricCounterParseError")
    return parse_fabric_counter_value, _fcpe


def test_parse_fabric_counter_value_plain_integer():
    parse_fabric_counter_value, _ = _load_parse_fabric_counter_value()
    assert parse_fabric_counter_value({"CRC": "7"}, "CRC", "3") == 7


def test_parse_fabric_counter_value_comma_formatted():
    parse_fabric_counter_value, _ = _load_parse_fabric_counter_value()
    assert parse_fabric_counter_value({"CRC": "1,234"}, "CRC", "3") == 1234


def test_parse_fabric_counter_value_na_is_unreadable():
    parse_fabric_counter_value, _ = _load_parse_fabric_counter_value()
    assert parse_fabric_counter_value({"CRC": "N/A"}, "CRC", "3") is None


def test_parse_fabric_counter_value_malformed_raises():
    parse_fabric_counter_value, FabricCounterParseError = _load_parse_fabric_counter_value()
    with pytest.raises(FabricCounterParseError):
        parse_fabric_counter_value({"CRC": "not-a-number"}, "CRC", "3")


# ---------------------------------------------------------------------------
# evaluate_fabric_counter_row
# ---------------------------------------------------------------------------

def _load_evaluate_row():
    # References parse_fabric_counter_value (-> _FABRIC_NA_VALUE, FabricCounterParseError).
    evaluate_fabric_counter_row, _, _, _ = _load(
        "evaluate_fabric_counter_row", "parse_fabric_counter_value",
        "_FABRIC_NA_VALUE", "FabricCounterParseError")
    return evaluate_fabric_counter_row


def test_evaluate_row_state_down_is_ignored():
    evaluate_fabric_counter_row = _load_evaluate_row()
    # STATE != up must short-circuit before the (garbage) counter is ever parsed.
    row = {"PORT": "1", "STATE": "down", "CRC": "not-a-number", "FEC_UNCORRECTABLE": "0"}
    assert evaluate_fabric_counter_row(row) is None


def test_evaluate_row_zero_counters():
    evaluate_fabric_counter_row = _load_evaluate_row()
    row = {"PORT": "1", "STATE": "up", "CRC": "0", "FEC_UNCORRECTABLE": "0"}
    assert evaluate_fabric_counter_row(row) == (0, 0)


def test_evaluate_row_crc_error():
    evaluate_fabric_counter_row = _load_evaluate_row()
    row = {"PORT": "1", "STATE": "up", "CRC": "12", "FEC_UNCORRECTABLE": "0"}
    assert evaluate_fabric_counter_row(row) == (12, 0)


def test_evaluate_row_fec_uncorrectable_error():
    evaluate_fabric_counter_row = _load_evaluate_row()
    row = {"PORT": "1", "STATE": "up", "CRC": "0", "FEC_UNCORRECTABLE": "4"}
    assert evaluate_fabric_counter_row(row) == (0, 4)


def test_evaluate_row_na_counter_is_none_not_zero():
    evaluate_fabric_counter_row = _load_evaluate_row()
    row = {"PORT": "1", "STATE": "up", "CRC": "N/A", "FEC_UNCORRECTABLE": "0"}
    crc, fec = evaluate_fabric_counter_row(row)
    assert crc is None      # unreadable -- never coerced to 0
    assert fec == 0


# ---------------------------------------------------------------------------
# is_fabric_error_fail
# ---------------------------------------------------------------------------

def test_is_fabric_error_fail_local_selected_dut():
    is_fabric_error_fail = _load("is_fabric_error_fail")
    # selected_switch_ids deliberately wrong/empty: must not even be consulted.
    assert is_fabric_error_fail("lc1", {"lc1"}, "999", set()) is True


def test_is_fabric_error_fail_remote_switch_id_selected():
    is_fabric_error_fail = _load("is_fabric_error_fail")
    assert is_fabric_error_fail("sup1", {"lc1"}, "100", {"100"}) is True


def test_is_fabric_error_fail_remote_switch_id_not_selected_is_warning():
    is_fabric_error_fail = _load("is_fabric_error_fail")
    assert is_fabric_error_fail("sup1", {"lc1"}, "999", {"100"}) is False


def test_is_fabric_error_fail_unavailable_remote_mod_is_warning():
    is_fabric_error_fail = _load("is_fabric_error_fail")
    assert is_fabric_error_fail("sup1", {"lc1"}, None, {"100"}) is False


# ---------------------------------------------------------------------------
# resolve_remote_switch_id: ASIC attribution
# ---------------------------------------------------------------------------

def test_resolve_remote_switch_id_multi_asic_row_without_asic_column_unresolved():
    resolve_remote_switch_id = _load("resolve_remote_switch_id")
    duthost = MagicMock()
    duthost.hostname = "lc1"
    duthost.asics = [MagicMock(), MagicMock()]   # multi-ASIC node
    row = {"PORT": "5", "STATE": "up", "CRC": "1", "FEC_UNCORRECTABLE": "0"}  # no "ASIC" key

    result = resolve_remote_switch_id(duthost, row)

    assert result is None
    duthost.asic_instance.assert_not_called()


def test_resolve_remote_switch_id_single_asic_row_without_asic_column_defaults():
    resolve_remote_switch_id = _load("resolve_remote_switch_id")
    duthost = MagicMock()
    duthost.hostname = "pizza1"
    duthost.asics = [MagicMock()]   # single-ASIC node
    duthost.asic_instance.return_value.run_sonic_db_cli_cmd.return_value = {"stdout": "42\n"}
    row = {"PORT": "5", "STATE": "up", "CRC": "1", "FEC_UNCORRECTABLE": "0"}  # no "ASIC" key

    result = resolve_remote_switch_id(duthost, row)

    assert result == "42"
    duthost.asic_instance.assert_called_once_with()


def test_resolve_remote_switch_id_uses_asic_column_when_present():
    resolve_remote_switch_id = _load("resolve_remote_switch_id")
    duthost = MagicMock()
    duthost.hostname = "lc1"
    duthost.asics = [MagicMock(), MagicMock()]
    duthost.asic_instance.return_value.run_sonic_db_cli_cmd.return_value = {"stdout": "7"}
    row = {"ASIC": "1", "PORT": "5", "STATE": "up", "CRC": "1", "FEC_UNCORRECTABLE": "0"}

    result = resolve_remote_switch_id(duthost, row)

    assert result == "7"
    duthost.asic_instance.assert_called_once_with(1)
