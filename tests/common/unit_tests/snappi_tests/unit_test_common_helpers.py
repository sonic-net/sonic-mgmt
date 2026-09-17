"""Unit test for ``get_queue_scheduler_weight_dict`` in
``tests/common/snappi_tests/common_helpers.py``.

The target module imports heavy sonic-mgmt deps at import time, so we
extract the function under test via ``ast`` and exec it in an isolated
namespace.

Run with::

    python3 -m pytest --noconftest \\
        tests/common/unit_tests/snappi_tests/unit_test_common_helpers.py -v
"""

import ast
from pathlib import Path
from unittest.mock import MagicMock


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "common/snappi_tests/common_helpers.py")


def _load(name):
    tree = ast.parse(MODULE_PATH.read_text())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            ns = {}
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         str(MODULE_PATH), "exec"), ns)
            return ns[name]
    raise LookupError(name)


# Minimal config_facts modeling the str-msn2700-22 (Mellanox-SN2700) DUT,
# trimmed to the keys read by ``get_queue_scheduler_weight_dict``:
#   scheduler.0 -> lossy queues, DWRR weight 14
#   scheduler.1 -> lossless queues 3 & 4, DWRR weight 15
CONFIG_FACTS = {
    "QUEUE": {
        "Ethernet100": {
            "0": {"scheduler": "scheduler.0"},
            "1": {"scheduler": "scheduler.0"},
            "2": {"scheduler": "scheduler.0"},
            "3": {"scheduler": "scheduler.1",
                  "wred_profile": "AZURE_LOSSLESS"},
            "4": {"scheduler": "scheduler.1",
                  "wred_profile": "AZURE_LOSSLESS"},
            "5": {"scheduler": "scheduler.0"},
            "6": {"scheduler": "scheduler.0"},
        },
    },
    "SCHEDULER": {
        "scheduler.0": {"type": "DWRR", "weight": "14"},
        "scheduler.1": {"type": "DWRR", "weight": "15"},
    },
    "DSCP_TO_TC_MAP": {
        "AZURE": {
            "0": "1", "1": "1", "10": "1", "11": "1", "12": "1", "13": "1",
            "14": "1", "15": "1", "16": "1", "17": "1", "18": "1", "19": "1",
            "2": "1", "20": "1", "21": "1", "22": "1", "23": "1", "24": "1",
            "25": "1", "26": "1", "27": "1", "28": "1", "29": "1", "3": "3",
            "30": "1", "31": "1", "32": "1", "33": "1", "34": "1", "35": "1",
            "36": "1", "37": "1", "38": "1", "39": "1", "4": "4", "40": "1",
            "41": "1", "42": "1", "43": "1", "44": "1", "45": "1", "46": "5",
            "47": "1", "48": "6", "49": "1", "5": "2", "50": "1", "51": "1",
            "52": "1", "53": "1", "54": "1", "55": "1", "56": "1", "57": "1",
            "58": "1", "59": "1", "6": "1", "60": "1", "61": "1", "62": "1",
            "63": "1", "7": "1", "8": "0", "9": "1",
        },
    },
    "TC_TO_QUEUE_MAP": {
        "AZURE": {str(i): str(i) for i in range(8)},
    },
}

EXPECTED = {
    0: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 8},
    1: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 0},
    2: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 5},
    3: {"scheduler": "scheduler.1", "type": "DWRR", "weight": 15, "dscp": 3},
    4: {"scheduler": "scheduler.1", "type": "DWRR", "weight": 15, "dscp": 4},
    5: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 46},
    6: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 48},
    # Queue 7 is not in the per-port QUEUE config; falls back to default.
    7: {"scheduler": None, "type": "DWRR", "weight": 15, "dscp": None},
}


def test_get_queue_scheduler_weight_dict():
    host = MagicMock()
    host.hostname = "test_dut"
    host.config_facts.return_value = {"ansible_facts": CONFIG_FACTS}

    assert _load("get_queue_scheduler_weight_dict")(host) == EXPECTED


def test_get_queue_scheduler_weight_dict_defaults_when_unconfigured():
    """When QUEUE/SCHEDULER are absent, fall back to 8 queues w/ equal weights."""
    host = MagicMock()
    host.hostname = "test_dut"
    facts = {k: v for k, v in CONFIG_FACTS.items()
             if k not in ("QUEUE", "SCHEDULER")}
    host.config_facts.return_value = {"ansible_facts": facts}

    result = _load("get_queue_scheduler_weight_dict")(host)
    assert set(result) == set(range(8))
    assert {v["weight"] for v in result.values()} == {15}
    assert {v["type"] for v in result.values()} == {"DWRR"}
    # DSCP annotations from DSCP_TO_TC_MAP / TC_TO_QUEUE_MAP still apply.
    assert result[0]["dscp"] == 8
    assert result[3]["dscp"] == 3
