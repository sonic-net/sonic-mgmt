"""Unit tests for ECN/WRED counter parsing in ``common_helpers.py``.

The helpers under test normalize ``show queue wredcounters --json`` output:

- ``N/A`` and comma-separated numeric strings become integers
- ``time`` / ``cached_time`` metadata keys are skipped
- JSON field names are mapped to the test API keys
  (``wreddroppacket`` -> ``wred_drop_pkts``, etc.)
- optional TxQ filtering by priority label (``UC3``, ``VOQ3``, ...)

``tests/common/snappi_tests/common_helpers.py`` imports heavy sonic-mgmt
deps at top level, so we extract only the parsing helpers via ``ast`` and
exec them into a shared namespace, mirroring the pattern in
``tests/snappi_tests/unit_tests/pfc/unit_test_m2o_fluctuating_lossless_helper.py``.

Run with::

    python3 -m pytest --noconftest \\
        tests/snappi_tests/unit_tests/ecn/unit_test_ecn_wred_counter_parsing.py \\
        -v
"""

import ast
from pathlib import Path

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/snappi_tests/common_helpers.py")

FUNCTION_NAMES = (
    "_parse_int_counter",
    "_txq_from_priority",
    "_normalize_wred_counter_entry",
    "_parse_wred_counters_json",
    "_filter_wred_counters_by_priority",
)


def _load_functions(names):
    """Load the named top-level functions into a single shared namespace."""
    source = MODULE_PATH.read_text()
    tree = ast.parse(source)
    selected = [node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in names]
    missing = set(names) - {n.name for n in selected}
    if missing:
        raise LookupError(
            "Missing functions {} in {}".format(sorted(missing), MODULE_PATH))
    module = ast.Module(body=selected, type_ignores=[])
    ns = {}
    exec(compile(module, str(MODULE_PATH), "exec"), ns)
    return ns


@pytest.fixture
def helper_ns():
    """Fresh namespace per test so state does not leak across tests."""
    return _load_functions(FUNCTION_NAMES)


SAMPLE_WRED_JSON = {
    "Ethernet0": {
        "time": "2024-01-01 00:00:00",
        "UC3": {
            "wreddroppacket": "N/A",
            "wreddropbytes": "N/A",
            "ecnmarkedpacket": "1,234",
            "ecnmarkedbytes": "5678",
        },
        "UC4": {
            "wreddroppacket": "0",
            "wreddropbytes": "0",
            "ecnmarkedpacket": "0",
            "ecnmarkedbytes": "0",
        },
    },
    "Ethernet8": {
        "cached_time": "2024-01-01 00:00:01",
        "VOQ3": {
            "wreddroppacket": "10",
            "wreddropbytes": "20",
            "ecnmarkedpacket": "N/A",
            "ecnmarkedbytes": "N/A",
        },
    },
}


@pytest.mark.parametrize("value,expected", [
    ("0", 0),
    ("1,234", 1234),
    ("N/A", 0),
    ("n/a", 0),
    ("", 0),
    ("  42  ", 42),
])
def test_parse_int_counter(helper_ns, value, expected):
    """Counter strings from wredstat JSON normalize to integers."""
    assert helper_ns["_parse_int_counter"](value) == expected


@pytest.mark.parametrize("priority,voq,expected", [
    (3, False, "UC3"),
    ("4", False, "UC4"),
    (3, True, "VOQ3"),
    ("UC3", False, "UC3"),
    ("VOQ3", False, "VOQ3"),
    ("MC2", False, "MC2"),
    ("ALL0", False, "ALL0"),
    (None, False, None),
])
def test_txq_from_priority(helper_ns, priority, voq, expected):
    """Numeric and explicit queue labels map to TxQ filter strings."""
    assert helper_ns["_txq_from_priority"](priority, voq=voq) == expected


def test_parse_wred_counters_json_skips_metadata_and_normalizes_values(helper_ns):
    """JSON parser skips time fields and maps wredstat keys to API keys."""
    parsed = helper_ns["_parse_wred_counters_json"](SAMPLE_WRED_JSON)

    assert set(parsed.keys()) == {"Ethernet0", "Ethernet8"}
    assert parsed["Ethernet0"]["UC3"] == {
        "wred_drop_pkts": 0,
        "wred_drop_bytes": 0,
        "ecn_marked_pkts": 1234,
        "ecn_marked_bytes": 5678,
    }
    assert parsed["Ethernet8"]["VOQ3"] == {
        "wred_drop_pkts": 10,
        "wred_drop_bytes": 20,
        "ecn_marked_pkts": 0,
        "ecn_marked_bytes": 0,
    }


@pytest.mark.parametrize("data", [{}, None])
def test_parse_wred_counters_json_empty_input(helper_ns, data):
    """Empty or invalid input returns an empty dict."""
    assert helper_ns["_parse_wred_counters_json"](data) == {}


def test_filter_wred_counters_by_priority_no_filter_returns_all(helper_ns):
    """None filter returns the full parsed structure unchanged."""
    parsed = helper_ns["_parse_wred_counters_json"](SAMPLE_WRED_JSON)
    assert helper_ns["_filter_wred_counters_by_priority"](parsed, None) == parsed


def test_filter_wred_counters_by_priority_filters_txq(helper_ns):
    """Priority filter keeps only the matching TxQ per port."""
    parsed = helper_ns["_parse_wred_counters_json"](SAMPLE_WRED_JSON)
    filtered = helper_ns["_filter_wred_counters_by_priority"](parsed, "UC3")

    assert filtered == {
        "Ethernet0": {
            "UC3": parsed["Ethernet0"]["UC3"],
        },
    }


def test_filter_wred_counters_by_priority_missing_txq_returns_empty(helper_ns):
    """Missing TxQ on all ports returns an empty dict."""
    parsed = helper_ns["_parse_wred_counters_json"](SAMPLE_WRED_JSON)
    assert helper_ns["_filter_wred_counters_by_priority"](parsed, "UC7") == {}
