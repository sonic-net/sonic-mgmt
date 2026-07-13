"""GCU regression tests for MAC_MOVE_GUARD|GLOBAL.

These tests exercise the sonic-mac-move-guard YANG model through
`config apply-patch` against a live DUT. They verify that:

* A well-formed patch creating, modifying, or removing the
  MAC_MOVE_GUARD|GLOBAL row is accepted by GCU and reflected in
  CONFIG_DB.
* Malformed patches (out-of-range numerics, invalid action enum value,
  non-GLOBAL key) are rejected by the YANG validation step of GCU.

The tests intentionally do not depend on the macmoveguardorch capability
publish or any data-plane behaviour. They cover the YANG/GCU pipeline
only; the FDB-event-driven behaviour is covered by
tests/fdb/test_fdb_mac_move.py.
"""

import logging

import pytest

from tests.common.gu_utils import apply_patch, expect_op_success, expect_op_failure
from tests.common.gu_utils import generate_tmpfile, delete_tmpfile
from tests.common.gu_utils import format_json_patch_for_multiasic
from tests.common.gu_utils import create_checkpoint, delete_checkpoint, rollback_or_reload
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
]


MMG_TABLE = "MAC_MOVE_GUARD"
MMG_KEY = "GLOBAL"

MMG_BASE_VALUE = {
    "enabled": "true",
    "threshold": "5000",
    "detect_interval": "5",
    "action_interval": "120",
    "action": "DISABLE_PORT",
}


def _current_mac_move_guard(duthost):
    """Return the current MAC_MOVE_GUARD CONFIG_DB table as a dict, or {} if absent."""
    config_facts = duthost.config_facts(host=duthost.hostname,
                                        source="running")['ansible_facts']
    return config_facts.get(MMG_TABLE, {})


MMG_YANG_PATH = "/usr/local/yang-models/sonic-mac-move-guard.yang"


@pytest.fixture(autouse=True)
def setup_env(duthosts, rand_one_dut_hostname):
    """Skip if the sonic-mac-move-guard YANG model is not present on the
    DUT (GCU's YANG_DIR is /usr/local/yang-models; without this file, the
    patch cannot be validated). Otherwise checkpoint before each test;
    rollback + delete on teardown."""
    duthost = duthosts[rand_one_dut_hostname]
    if duthost.shell("test -f {}".format(MMG_YANG_PATH),
                     module_ignore_errors=True).get('rc') != 0:
        pytest.skip("sonic-mac-move-guard YANG model not present on DUT "
                    "({}); MAC_MOVE_GUARD GCU validation not applicable."
                    .format(MMG_YANG_PATH))
    create_checkpoint(duthost)

    yield

    try:
        logger.info("Rolling back to checkpoint")
        rollback_or_reload(duthost)
    finally:
        delete_checkpoint(duthost)


def _run_patch(duthost, json_patch, expect_success=True):
    """Apply a JSON patch on the DUT and assert success or failure."""
    json_patch = format_json_patch_for_multiasic(duthost=duthost,
                                                 json_data=json_patch,
                                                 is_host_specific=True)
    tmpfile = generate_tmpfile(duthost)
    logger.info("tmpfile %s, patch %s", tmpfile, json_patch)
    try:
        output = apply_patch(duthost, json_data=json_patch, dest_file=tmpfile)
        if expect_success:
            expect_op_success(duthost, output)
        else:
            expect_op_failure(output)
        return output
    finally:
        delete_tmpfile(duthost, tmpfile)


def _add_global_row(duthost, value=None):
    """Apply an add patch that creates MAC_MOVE_GUARD|GLOBAL with `value`
    (defaults to MMG_BASE_VALUE)."""
    patch = [
        {
            "op": "add",
            "path": f"/{MMG_TABLE}",
            "value": {MMG_KEY: dict(value or MMG_BASE_VALUE)},
        }
    ]
    _run_patch(duthost, patch, expect_success=True)


def test_add_global_row(duthosts, rand_one_dut_hostname):
    """Add MAC_MOVE_GUARD|GLOBAL with action=DISABLE_PORT; verify CONFIG_DB."""
    duthost = duthosts[rand_one_dut_hostname]
    _add_global_row(duthost)

    table = _current_mac_move_guard(duthost)
    pytest_assert(MMG_KEY in table,
                  f"{MMG_TABLE}|{MMG_KEY} missing from CONFIG_DB after apply-patch")
    row = table[MMG_KEY]
    for field, expected in MMG_BASE_VALUE.items():
        pytest_assert(row.get(field) == expected,
                      f"{MMG_TABLE}|{MMG_KEY} field {field}: "
                      f"expected {expected!r}, got {row.get(field)!r}")


def test_add_global_row_dlomwa(duthosts, rand_one_dut_hostname):
    """Add MAC_MOVE_GUARD|GLOBAL with action=DISABLE_LEARN_ON_MAC_WITH_ACL.

    YANG validation accepts the action regardless of whether the platform
    supports SAI_ACL_ACTION_TYPE_SET_DO_NOT_LEARN at PRE_INGRESS — the
    orch soft-disables at runtime. This test only validates the patch
    pipeline, not orch behaviour.
    """
    duthost = duthosts[rand_one_dut_hostname]
    value = dict(MMG_BASE_VALUE)
    value["action"] = "DISABLE_LEARN_ON_MAC_WITH_ACL"
    _add_global_row(duthost, value=value)

    row = _current_mac_move_guard(duthost).get(MMG_KEY, {})
    pytest_assert(row.get("action") == "DISABLE_LEARN_ON_MAC_WITH_ACL",
                  f"action field not set to DISABLE_LEARN_ON_MAC_WITH_ACL, got {row.get('action')!r}")


def test_replace_fields(duthosts, rand_one_dut_hostname):
    """Replace individual leaves after the row exists; verify each takes effect."""
    duthost = duthosts[rand_one_dut_hostname]
    _add_global_row(duthost)

    patch = [
        {"op": "replace", "path": f"/{MMG_TABLE}/{MMG_KEY}/threshold", "value": "2000"},
        {"op": "replace", "path": f"/{MMG_TABLE}/{MMG_KEY}/detect_interval", "value": "10"},
        {"op": "replace", "path": f"/{MMG_TABLE}/{MMG_KEY}/action_interval", "value": "300"},
        {"op": "replace", "path": f"/{MMG_TABLE}/{MMG_KEY}/enabled", "value": "false"},
    ]
    _run_patch(duthost, patch, expect_success=True)

    row = _current_mac_move_guard(duthost).get(MMG_KEY, {})
    pytest_assert(row.get("threshold") == "2000", f"threshold not updated, got {row.get('threshold')!r}")
    pytest_assert(row.get("detect_interval") == "10",
                  f"detect_interval not updated, got {row.get('detect_interval')!r}")
    pytest_assert(row.get("action_interval") == "300",
                  f"action_interval not updated, got {row.get('action_interval')!r}")
    pytest_assert(row.get("enabled") == "false", f"enabled not updated, got {row.get('enabled')!r}")


def test_switch_action(duthosts, rand_one_dut_hostname):
    """Replace the action field; verify the new action is stored."""
    duthost = duthosts[rand_one_dut_hostname]
    _add_global_row(duthost)

    patch = [
        {
            "op": "replace",
            "path": f"/{MMG_TABLE}/{MMG_KEY}/action",
            "value": "DISABLE_LEARN_ON_MAC_WITH_ACL",
        }
    ]
    _run_patch(duthost, patch, expect_success=True)

    row = _current_mac_move_guard(duthost).get(MMG_KEY, {})
    pytest_assert(row.get("action") == "DISABLE_LEARN_ON_MAC_WITH_ACL",
                  f"action not updated, got {row.get('action')!r}")


def test_remove_global_row(duthosts, rand_one_dut_hostname):
    """Remove the entire MAC_MOVE_GUARD table; verify it is gone from CONFIG_DB."""
    duthost = duthosts[rand_one_dut_hostname]
    _add_global_row(duthost)

    patch = [{"op": "remove", "path": f"/{MMG_TABLE}"}]
    _run_patch(duthost, patch, expect_success=True)

    pytest_assert(_current_mac_move_guard(duthost) == {},
                  f"{MMG_TABLE} should be absent from CONFIG_DB after remove")


@pytest.mark.parametrize("field,bad_value,reason", [
    ("threshold", "0", "threshold range is 1..max"),
    ("detect_interval", "0", "detect_interval range is 1..3600"),
    ("detect_interval", "3601", "detect_interval range is 1..3600"),
    ("action_interval", "0", "action_interval range is 1..86400"),
    ("action_interval", "86401", "action_interval range is 1..86400"),
    ("action", "DROP_MAC", "action is restricted to the YANG enum values"),
    ("enabled", "maybe", "enabled must be boolean"),
])
def test_invalid_field_rejected(duthosts, rand_one_dut_hostname, field, bad_value, reason):
    """Patches that violate the YANG model on a single field must be rejected by GCU.

    Each parametrization carries `reason` as documentation only — `expect_op_failure`
    only checks the exit code so the test is robust to error-message wording changes.
    """
    duthost = duthosts[rand_one_dut_hostname]
    _add_global_row(duthost)

    patch = [
        {"op": "replace", "path": f"/{MMG_TABLE}/{MMG_KEY}/{field}", "value": bad_value}
    ]
    _run_patch(duthost, patch, expect_success=False)

    row = _current_mac_move_guard(duthost).get(MMG_KEY, {})
    pytest_assert(row.get(field) == MMG_BASE_VALUE[field],
                  f"{field} should remain {MMG_BASE_VALUE[field]!r} after rejected patch, "
                  f"got {row.get(field)!r}")


def test_non_global_key_rejected(duthosts, rand_one_dut_hostname):
    """Keys other than GLOBAL violate the YANG enum on `name` and must be rejected."""
    duthost = duthosts[rand_one_dut_hostname]

    patch = [
        {
            "op": "add",
            "path": f"/{MMG_TABLE}",
            "value": {"not_global": dict(MMG_BASE_VALUE)},
        }
    ]
    _run_patch(duthost, patch, expect_success=False)

    pytest_assert("not_global" not in _current_mac_move_guard(duthost),
                  "non-GLOBAL key should not appear in CONFIG_DB after rejected patch")
