"""Unit tests for ``tests/snappi_tests/pfc/files/m2o_fluctuating_lossless_helper.py``.

The reference scenario reproduces the IxNetwork Flow Statistics (DWRR weights: lossless=15, lossy=14)::

    Row  Tx Port  Rx Port  Traffic Item                     Loss %
    1    Port 1   Port 0   Test Flow 1 -> 0 Rate:20         0.000
    2    Port 2   Port 0   Test Flow 2 -> 0 Rate:10         0.000
    3    Port 1   Port 0   1 Background Flow 1 -> 0 Rate:20 11.259
    4    Port 2   Port 0   2 Background Flow 2 -> 0 Rate:20 11.259
    5    Port 1   Port 0   3 Background Flow 1 -> 0 Rate:20 11.259
    6    Port 2   Port 0   4 Background Flow 2 -> 0 Rate:20 11.259

Aggregate offered load is 110% (20 + 10 + 4*20), so ~10% over-subscription
hits the lossy queues. With DWRR weights 15 (Q3, Q4) vs 14 (Q0/Q1/Q2/Q5)
the analytical per-BG-flow loss is ~11.27% — within the helper's 1%
tolerance of the IxNetwork-measured 11.259%.

The target module imports heavy sonic-mgmt deps at top level, so we extract
just ``get_expected_bg_loss_percent`` (and its nested helpers) via ``ast``
and exec it into a shared namespace, mirroring the lightweight pattern in
``tests/common/unit_tests/fixtures/unit_test_conn_graph_facts.py``.

Run with::

    python3 -m pytest --noconftest \\
        tests/snappi_tests/unit_tests/pfc/unit_test_m2o_fluctuating_lossless_helper.py \\
        -v
"""

import ast
from pathlib import Path
from unittest.mock import MagicMock

import pytest


MODULE_PATH = (Path(__file__).resolve().parents[3] /
               "snappi_tests/pfc/files/m2o_fluctuating_lossless_helper.py")

FUNCTION_NAMES = ("get_expected_bg_loss_percent",)


def _load_functions(names):
    """Load the named top-level functions into a single shared namespace.

    The shared namespace is what each function sees as its globals, so calls
    between the loaded functions resolve correctly. Names not loaded (e.g.
    ``get_queue_scheduler_weight_dict``) can be injected by the caller.
    """
    source = MODULE_PATH.read_text()
    tree = ast.parse(source)
    selected = [node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name in names]
    missing = set(names) - {n.name for n in selected}
    if missing:
        raise LookupError(
            "Missing functions {} in {}".format(sorted(missing), MODULE_PATH))
    module = ast.Module(body=selected, type_ignores=[])

    def _pytest_assert(condition, message=""):
        assert condition, message

    ns = {"pytest_assert": _pytest_assert}
    exec(compile(module, str(MODULE_PATH), "exec"), ns)
    return ns


@pytest.fixture
def helper_ns():
    """Fresh namespace per test so injected stubs don't leak across tests."""
    return _load_functions(FUNCTION_NAMES)


# Two DWRR weight profiles, indexed for parametrization.
#   [0] mixed weights: lossless queues (Q3, Q4) heavier than lossy queues
#       — the SN4700 / 7260CX3 default observed in the IxNetwork screenshot.
#   [1] uniform weights: every queue at weight 15, modeling a platform where
#       lossless and lossy schedulers are configured identically.
SCHEDULER_WEIGHT_DICT = [
    {
        0: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 8},
        1: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 0},
        2: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 5},
        3: {"scheduler": "scheduler.1", "type": "DWRR", "weight": 15, "dscp": 3},
        4: {"scheduler": "scheduler.1", "type": "DWRR", "weight": 15, "dscp": 4},
        5: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 46},
        6: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 14, "dscp": 48},
    },
    {
        0: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 15, "dscp": 8},
        1: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 15, "dscp": 0},
        2: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 15, "dscp": 5},
        3: {"scheduler": "scheduler.1", "type": "DWRR", "weight": 15, "dscp": 3},
        4: {"scheduler": "scheduler.1", "type": "DWRR", "weight": 15, "dscp": 4},
        5: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 15, "dscp": 46},
        6: {"scheduler": "scheduler.0", "type": "DWRR", "weight": 15, "dscp": 48},
    },
]

CONFIG_FACTS = {
    "TC_TO_QUEUE_MAP": {
        "AZURE": {str(i): str(i) for i in range(7)},
    },
}

# IxNetwork scenario parameters (matches the m2o_fluctuating_lossless test):
TEST_PRIO_LIST = [3, 4]              # lossless TC3 / TC4
TEST_FLOW_RATE_PERCENT = [20, 10]    # Test Flow 1 / Test Flow 2
BG_PRIO_LIST = [0, 1, 2, 5]          # 4 lossy background TCs
BG_FLOW_RATE_PERCENT = [20, 20, 20, 20]


def _make_egress_duthost(config_facts=None):
    """Create a mock egress DUT whose ``config_facts(...)`` returns the
    canned config_facts dict."""
    duthost = MagicMock()
    duthost.config_facts.return_value = {
        "ansible_facts": config_facts or CONFIG_FACTS,
    }
    return duthost


def _inject_weight_stub(helper_ns, weight_dict=None):
    """Inject a stub for ``get_queue_scheduler_weight_dict`` into the loaded
    namespace so ``get_expected_bg_loss_percent`` can resolve it."""
    helper_ns["get_queue_scheduler_weight_dict"] = MagicMock(
        return_value=weight_dict if weight_dict is not None
        else SCHEDULER_WEIGHT_DICT[0])


# -- Tests for get_expected_bg_loss_percent ----------------------------------
@pytest.mark.parametrize(
    "case_id, weight_dict_idx, expected_loss",
    [
        # SCHEDULER_WEIGHT_DICT[0] — mixed weights (lossless=15, lossy=14):
        #   Q4 (demand 10) is satisfied first; Q3 + 4 lossy queues split the
        #   remaining 90% by weight 15:14:14:14:14 (sum 71). Each lossy queue
        #   gets 90*14/71 = 17.746%.
        #   Per-BG loss = (20 - 17.746) / 20 * 100 = 11.267%
        #   Measured by IxNetwork: 11.259% (within the 1% tolerance).
        ("mixed_weights_15_14", 0, 11.2676),
        # SCHEDULER_WEIGHT_DICT[1] — uniform weights (all queues = 15):
        #   With equal weights the DWRR split is fair-share by active queue.
        #   Iter 1: 6 active queues, share = 100/6 = 16.667%
        #     Q4 demand 10 < 16.667 → satisfied with 10.
        #   Iter 2: 5 active queues, remaining 90%, share = 18% each
        #     All five remaining queues have demand ≥ 18 → fallback split,
        #     each gets exactly 18%.
        #   Per-BG loss = (20 - 18) / 20 * 100 = 10.0%
        ("uniform_weights_15", 1, 10.0),
    ],
)
def test_expected_bg_loss_matches_analytical_dwrr_split(
        helper_ns, case_id, weight_dict_idx, expected_loss):
    """Per-BG-flow loss must match the analytical DWRR split.

    Inputs vary only by the egress scheduler weight profile. The fluctuating
    m2o test parameters are held constant::

        test_prio_list           = [3, 4]
        test_flow_rate_percent   = [20, 10]
        bg_prio_list             = [0, 1, 2, 5]
        bg_flow_rate_percent     = [20, 20, 20, 20]
    """
    _inject_weight_stub(helper_ns, SCHEDULER_WEIGHT_DICT[weight_dict_idx])
    duthost = _make_egress_duthost()

    result = helper_ns["get_expected_bg_loss_percent"](
        egress_duthost=duthost,
        test_prio_list=TEST_PRIO_LIST,
        test_flow_rate_percent=TEST_FLOW_RATE_PERCENT,
        bg_prio_list=BG_PRIO_LIST,
        bg_flow_rate_percent=BG_FLOW_RATE_PERCENT,
    )

    assert result == pytest.approx(expected_loss, abs=0.01)
