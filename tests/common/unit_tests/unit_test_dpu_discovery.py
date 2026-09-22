"""Unit tests for SmartSwitch DPU discovery helpers in device_utils.

Covers the edge cases that drove the review:
  * explicit --ss_target_indices override wins over discovery
  * sparse / non-contiguous DPU IDs (dpu1, dpu3 -> [1, 3])
  * admin-down and missing admin_status DPUs are skipped (fail closed)
  * DPUS-only config (no gnmi_port) -> get_dpu_port returns None
"""

import os
import sys
from unittest.mock import Mock

import logging

# The repo's pytest log_format uses a custom 'funcNamewithModule' record field that
# is normally injected by a conftest-loaded plugin; --noconftest skips it, so add it
# here to keep these tests runnable via `pytest --noconftest`.
_old_record_factory = logging.getLogRecordFactory()


def _record_factory(*args, **kwargs):
    record = _old_record_factory(*args, **kwargs)
    record.funcNamewithModule = "%s.%s" % (record.module, record.funcName)
    return record


logging.setLogRecordFactory(_record_factory)

_TEST_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(_TEST_DIR))
)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from tests.common.platform.device_utils import (  # noqa: E402
    get_configured_dpu_indices,
    get_configured_dpu_names,
    get_dpu_port,
    resolve_upgrade_dpu_indices,
)


def _make_duthost(config_db):
    """Build a fake duthost whose config_facts() returns the given CONFIG_DB dict."""
    duthost = Mock()
    duthost.hostname = "test-dut"
    # device_utils reads duthost.config_facts(...)['ansible_facts'].
    duthost.config_facts.return_value = {"ansible_facts": config_db}
    return duthost


# ---------------------------------------------------------------------------
# get_configured_dpu_indices: sparse IDs
# ---------------------------------------------------------------------------
def test_sparse_dpu_indices_parsed_from_identities():
    # DPU table has non-contiguous ids dpu1 and dpu3 (both admin-up).
    duthost = _make_duthost({
        "DPU": {"dpu1": {"gnmi_port": 50052}, "dpu3": {"gnmi_port": 50052}},
        "CHASSIS_MODULE": {"DPU1": {"admin_status": "up"}, "DPU3": {"admin_status": "up"}},
    })
    # Real identities -> [1, 3], not a positional [0, 1].
    assert get_configured_dpu_indices(duthost) == [1, 3]


# ---------------------------------------------------------------------------
# get_configured_dpu_indices: admin state filtering
# ---------------------------------------------------------------------------
def test_admin_down_dpu_is_skipped():
    # DPU1 is admin-down and must be excluded from discovery.
    duthost = _make_duthost({
        "DPU": {"dpu0": {}, "dpu1": {}, "dpu2": {}},
        "CHASSIS_MODULE": {
            "DPU0": {"admin_status": "up"},
            "DPU1": {"admin_status": "down"},
            "DPU2": {"admin_status": "up"},
        },
    })
    assert get_configured_dpu_indices(duthost) == [0, 2]


def test_missing_chassis_module_entry_is_skipped():
    # DPU1 has no CHASSIS_MODULE entry -> state unverifiable -> fail closed (skip).
    duthost = _make_duthost({
        "DPU": {"dpu0": {}, "dpu1": {}},
        "CHASSIS_MODULE": {"DPU0": {"admin_status": "up"}},
    })
    assert get_configured_dpu_indices(duthost) == [0]


def test_missing_admin_status_key_is_skipped():
    # CHASSIS_MODULE entry exists but has no admin_status -> fail closed (skip).
    duthost = _make_duthost({
        "DPU": {"dpu0": {}, "dpu1": {}},
        "CHASSIS_MODULE": {"DPU0": {"admin_status": "up"}, "DPU1": {}},
    })
    assert get_configured_dpu_indices(duthost) == [0]


def test_include_admin_down_returns_all_indices():
    # include_admin_down=True bypasses the admin-state filter entirely.
    duthost = _make_duthost({
        "DPU": {"dpu0": {}, "dpu1": {}, "dpu2": {}},
        "CHASSIS_MODULE": {
            "DPU0": {"admin_status": "up"},
            "DPU1": {"admin_status": "down"},
            # DPU2 intentionally absent.
        },
    })
    assert get_configured_dpu_indices(duthost, include_admin_down=True) == [0, 1, 2]


# ---------------------------------------------------------------------------
# DPUS-only configuration (name-to-midplane mapping, no gnmi_port)
# ---------------------------------------------------------------------------
def test_dpus_only_config_discovers_names_and_indices():
    # 'DPUS' carries only midplane mapping; discovery must still resolve identities.
    duthost = _make_duthost({
        "DPUS": {"dpu0": {"midplane_interface": "dpu0"}, "dpu1": {"midplane_interface": "dpu1"}},
        "CHASSIS_MODULE": {"DPU0": {"admin_status": "up"}, "DPU1": {"admin_status": "up"}},
    })
    assert get_configured_dpu_names(duthost) == ["dpu0", "dpu1"]
    assert get_configured_dpu_indices(duthost) == [0, 1]


def test_dpus_only_config_has_no_gnmi_port():
    # gnmi_port lives only in 'DPU'; a DPUS-only config -> get_dpu_port returns None.
    duthost = _make_duthost({
        "DPUS": {"dpu0": {"midplane_interface": "dpu0"}},
    })
    assert get_dpu_port(duthost, 0) is None


# ---------------------------------------------------------------------------
# get_dpu_port: hostname-prefixed keys
# ---------------------------------------------------------------------------
def test_get_dpu_port_matches_hostname_prefixed_key():
    # DPU keys may be prefixed with the hostname; match on the trailing index.
    duthost = _make_duthost({
        "DPU": {
            "test-dut-dpu0": {"gnmi_port": 50051},
            "test-dut-dpu3": {"gnmi_port": 50054},
        },
    })
    assert get_dpu_port(duthost, 3) == 50054
    assert get_dpu_port(duthost, 0) == 50051


def test_get_dpu_port_unknown_index_returns_none():
    # An index not present in the DPU table yields None.
    duthost = _make_duthost({"DPU": {"dpu0": {"gnmi_port": 50051}}})
    assert get_dpu_port(duthost, 7) is None


# ---------------------------------------------------------------------------
# resolve_upgrade_dpu_indices: explicit override precedence
# ---------------------------------------------------------------------------
def test_explicit_override_wins_over_discovery():
    # Explicit --ss_target_indices is honored exactly; discovery is not consulted.
    duthost = _make_duthost({
        "DPU": {"dpu0": {}, "dpu1": {}},
        "CHASSIS_MODULE": {"DPU0": {"admin_status": "up"}, "DPU1": {"admin_status": "up"}},
    })
    assert resolve_upgrade_dpu_indices(duthost, "0,3,5") == [0, 3, 5]
    # config_facts must never be read when an explicit selection is given.
    duthost.config_facts.assert_not_called()


def test_explicit_override_tolerates_whitespace():
    # Spaces around comma-separated indices are stripped.
    duthost = _make_duthost({})
    assert resolve_upgrade_dpu_indices(duthost, "1, 2 ,  4") == [1, 2, 4]


def test_no_override_falls_back_to_discovery():
    # Absent --ss_target_indices -> fall back to admin-up discovered indices.
    duthost = _make_duthost({
        "DPU": {"dpu0": {}, "dpu1": {}},
        "CHASSIS_MODULE": {"DPU0": {"admin_status": "up"}, "DPU1": {"admin_status": "down"}},
    })
    assert resolve_upgrade_dpu_indices(duthost, None) == [0]


def test_empty_override_string_falls_back_to_discovery():
    # An empty string is treated as "no explicit selection".
    duthost = _make_duthost({
        "DPU": {"dpu2": {}},
        "CHASSIS_MODULE": {"DPU2": {"admin_status": "up"}},
    })
    assert resolve_upgrade_dpu_indices(duthost, "") == [2]
