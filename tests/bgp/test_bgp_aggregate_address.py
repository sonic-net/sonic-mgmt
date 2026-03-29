"""
Tests for the BGP aggregate-address with bbr awareness feature in SONiC,
aligned with: https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testplan/BGP-Aggregate-Address.md

Test Case 1: Scenarios covered via parametrize ipversion, bbr-required, summary-only and as-set.

Test Case 2: Test BBR Features State Change
  During device up, the BBR state may change, and this feature should take action accordingly.

Validations:
  - CONFIG_DB: BGP_AGGREGATE_ADDRESS row content (bbr-required/summary-only/as-set flags)
  - STATE_DB: BGP_AGGREGATE_ADDRESS row content (state flag align with bbr status)
  - FRR running config: aggregate-address line contains expected flags
"""

import ast
import logging
from collections import namedtuple

import pytest

# Functions
from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state, is_bbr_enabled

from tests.common.gcu_utils import apply_gcu_patch
from tests.common.gcu_utils import create_checkpoint, rollback_or_reload, delete_checkpoint
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

# ---- Topology & device-type markers (register in pytest.ini to avoid warnings) ----
pytestmark = [pytest.mark.topology("t1", "m1"), pytest.mark.device_type("vs"), pytest.mark.disable_loganalyzer]

# ---- Constants & helper structures ----
CONSTANTS_FILE = "/etc/sonic/constants.yml"

# Aggregate prefixes
AGGR_V4 = "172.16.51.0/24"
AGGR_V6 = "2000:172:16:50::/64"
BGP_AGGREGATE_ADDRESS = "BGP_AGGREGATE_ADDRESS"
PLACEHOLDER_PREFIX = "192.0.2.0/32"  # RFC5737 TEST-NET-1

AggregateCfg = namedtuple("AggregateCfg", ["prefix", "bbr_required", "summary_only", "as_set"])


@pytest.fixture(scope="module", autouse=True)
def setup_teardown(duthost):
    # This testcase will use GCU to modify several entries in running-config.
    # Restore the config via config_reload may cost too much time.
    # So we leverage GCU for the config update. Setup checkpoint before the test
    # and rollback to it after the test.
    create_checkpoint(duthost)

    # add placeholder aggregate to avoid GCU to remove empty table
    default_aggregates = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    if not default_aggregates:
        gcu_add_placeholder_aggregate(duthost, PLACEHOLDER_PREFIX)

    yield

    try:
        rollback_or_reload(duthost, fail_on_rollback_error=False)
    finally:
        delete_checkpoint(duthost)


# ---- DB & running-config helpers ----
def dump_db(duthost, dbname, tablename):
    """Return current DB content as dict."""
    keys_out = duthost.shell(f"sonic-db-cli {dbname} keys '{tablename}*'", module_ignore_errors=True)["stdout"]
    logger.info(f"dump {dbname} db, table {tablename}, keys output: {keys_out}")
    keys = keys_out.strip().splitlines() if keys_out.strip() else []
    res = {}
    for k in keys:
        fields = duthost.shell(f"sonic-db-cli {dbname} hgetall '{k}'", module_ignore_errors=True)["stdout"]
        logger.info(f"all fields:{fields} for key: {k}")
        prefix = k.removeprefix(f"{tablename}|")

        res[prefix] = ast.literal_eval(fields)
        logger.info("dump config db result: {}".format(res))
    return res


def running_bgp_has_aggregate(duthost, prefix):
    """Grep FRR running BGP config for aggregate-address lines."""
    return duthost.shell(
        f"show runningconfiguration bgp | grep -i 'aggregate-address {prefix}'", module_ignore_errors=True
    )["stdout"]


# ---- GCU JSON patch helpers ----
def gcu_add_placeholder_aggregate(duthost, prefix):
    patch = [
        {
            "op": "add",
            "path": f"/BGP_AGGREGATE_ADDRESS/{prefix.replace('/', '~1')}",
            "value": {"summary-only": "false", "as-set": "false"},
        }
    ]
    logger.info(f"Adding placeholder BGP aggregate {prefix.replace('/', '~1')}")
    return apply_gcu_patch(duthost, patch)


def gcu_add_aggregate(duthost, aggregate_cfg: AggregateCfg):
    logger.info("Add BGP_AGGREGATE_ADDRESS by GCU cmd")
    patch = [
        {
            "op": "add",
            "path": f"/BGP_AGGREGATE_ADDRESS/{aggregate_cfg.prefix.replace('/', '~1')}",
            "value": {
                "bbr-required": "true" if aggregate_cfg.bbr_required else "false",
                "summary-only": "true" if aggregate_cfg.summary_only else "false",
                "as-set": "true" if aggregate_cfg.as_set else "false",
            },
        }
    ]

    apply_gcu_patch(duthost, patch)


def gcu_remove_aggregate(duthost, prefix):
    patch = [{"op": "remove", "path": f"/BGP_AGGREGATE_ADDRESS/{prefix.replace('/', '~1')}"}]

    apply_gcu_patch(duthost, patch)


# ---- Polling timeout for bgpcfgd propagation (CONFIG_DB -> STATE_DB / FRR) ----
BGPCFGD_TIMEOUT = 30  # seconds
BGPCFGD_INTERVAL = 2  # seconds


# ---- Polling helpers for wait_until ----
def _check_state_db_aggregate(duthost, cfg, bbr_enabled):
    """Return True when STATE_DB reflects the expected aggregate state.

    After GCU writes to CONFIG_DB, bgpcfgd asynchronously propagates to
    STATE_DB.  This helper is meant to be polled via wait_until().
    """
    state_db = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
    if cfg.prefix not in state_db:
        return False
    expected_state = "inactive" if (cfg.bbr_required and not bbr_enabled) else "active"
    return state_db[cfg.prefix].get("state") == expected_state


def _check_running_config_aggregate(duthost, cfg, bbr_enabled):
    """Return True when FRR running-config matches the expected aggregate flags.

    After GCU writes to CONFIG_DB, bgpcfgd asynchronously configures FRR.
    This helper is meant to be polled via wait_until().
    """
    running_config = running_bgp_has_aggregate(duthost, cfg.prefix)

    if cfg.bbr_required and not bbr_enabled:
        # Aggregate should NOT be present in FRR when bbr is required but disabled
        return cfg.prefix not in running_config

    # Aggregate should be present with correct flags
    if cfg.prefix not in running_config:
        return False
    if cfg.summary_only and "summary-only" not in running_config:
        return False
    if not cfg.summary_only and "summary-only" in running_config:
        return False
    if cfg.as_set and "as-set" not in running_config:
        return False
    if not cfg.as_set and "as-set" in running_config:
        return False
    return True


# ---- Common Validator for Every Case ----
def verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg: AggregateCfg):
    # CONFIG_DB validation (synchronous — GCU blocks until CONFIG_DB is written)
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(cfg.prefix in config_db, f"Aggregate row {cfg.prefix} not found in CONFIG_DB")
    pytest_assert(
        config_db[cfg.prefix].get("bbr-required") == ("true" if cfg.bbr_required else "false"),
        "bbr-required flag mismatch",
    )
    pytest_assert(
        config_db[cfg.prefix].get("summary-only") == ("true" if cfg.summary_only else "false"),
        "summary-only flag mismatch",
    )
    pytest_assert(config_db[cfg.prefix].get("as-set") == ("true" if cfg.as_set else "false"), "as-set flag mismatch")

    # STATE_DB validation — poll until bgpcfgd propagates the change
    pytest_assert(
        wait_until(BGPCFGD_TIMEOUT, BGPCFGD_INTERVAL, 0, _check_state_db_aggregate, duthost, cfg, bbr_enabled),
        f"Aggregate row {cfg.prefix} not found or state mismatch in STATE_DB after {BGPCFGD_TIMEOUT}s",
    )

    # Running-config validation — poll until bgpcfgd configures FRR
    pytest_assert(
        wait_until(BGPCFGD_TIMEOUT, BGPCFGD_INTERVAL, 0, _check_running_config_aggregate, duthost, cfg, bbr_enabled),
        f"FRR running-config mismatch for aggregate {cfg.prefix} after {BGPCFGD_TIMEOUT}s",
    )


def _check_state_db_aggregate_removed(duthost, prefix):
    """Return True when the aggregate row is gone from STATE_DB."""
    state_db = dump_db(duthost, "STATE_DB", BGP_AGGREGATE_ADDRESS)
    return prefix not in state_db


def _check_running_config_aggregate_removed(duthost, prefix):
    """Return True when the aggregate is gone from FRR running-config."""
    running_config = running_bgp_has_aggregate(duthost, prefix)
    return prefix.split("/")[0] not in running_config


def verify_bgp_aggregate_cleanup(duthost, prefix):
    # CONFIG_DB validation (synchronous)
    config_db = dump_db(duthost, "CONFIG_DB", BGP_AGGREGATE_ADDRESS)
    pytest_assert(prefix not in config_db, f"Aggregate row {prefix} should be cleaned up from CONFIG_DB")

    # STATE_DB validation — poll until bgpcfgd removes the entry
    pytest_assert(
        wait_until(BGPCFGD_TIMEOUT, BGPCFGD_INTERVAL, 0, _check_state_db_aggregate_removed, duthost, prefix),
        f"Aggregate row {prefix} should be cleaned up from STATE_DB after {BGPCFGD_TIMEOUT}s",
    )

    # Running-config validation — poll until bgpcfgd removes from FRR
    pytest_assert(
        wait_until(BGPCFGD_TIMEOUT, BGPCFGD_INTERVAL, 0, _check_running_config_aggregate_removed, duthost, prefix),
        f"aggregate-address {prefix} should not be present in FRR running-config after {BGPCFGD_TIMEOUT}s",
    )


# Test with parameters Combination
@pytest.mark.parametrize(
    "ip_version,bbr_required,summary_only,as_set",
    [
        ("ipv4", True, True, False),  # v4 + bbr-required + summary_only
        ("ipv6", True, True, False),  # v6 + bbr-required + summary_only
        ("ipv4", False, True, True),  # v4 + summary_only + as_set
        ("ipv6", False, False, False),  # v6
    ],
)
def test_bgp_aggregate_address(duthosts, rand_one_dut_hostname, ip_version, bbr_required, summary_only, as_set):
    """
    Unified BGP aggregate-address test with parametrize
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Select specific data
    if ip_version == "ipv4":
        cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)
    else:
        cfg = AggregateCfg(prefix=AGGR_V6, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)

    # get default bbr state
    bbr_enabled = is_bbr_enabled(duthost)

    # Apply aggregate via GCU
    gcu_add_aggregate(duthost, cfg)

    # Verify config db, state db and running config
    verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

    # Cleanup
    gcu_remove_aggregate(duthost, cfg.prefix)

    # Verify config db, state db and running config are cleanup
    verify_bgp_aggregate_cleanup(duthost, cfg.prefix)


# Test BBR Features State Change
@pytest.mark.parametrize(
    "ip_version,bbr_required,summary_only,as_set",
    [
        ("ipv4", True, True, True),  # v4 + bbr-required + summary_only + as_set
        ("ipv6", True, True, False),  # v6 + bbr-required + summary_only
        ("ipv4", False, True, True),  # v4 + summary_only + as_set
        ("ipv6", False, False, True),  # v6 +  as_set
    ],
)
def test_bgp_aggregate_address_when_bbr_changed(
    duthosts, rand_one_dut_hostname, ip_version, bbr_required, summary_only, as_set
):
    """
    During device up, the BBR state may change, and the bgp aggregate address feature should take action accordingly.
    """
    duthost = duthosts[rand_one_dut_hostname]

    bbr_supported, bbr_default_state = get_bbr_default_state(duthost)
    if not bbr_supported:
        pytest.skip("BGP BBR is not supported")

    # Change BBR current state
    if bbr_default_state == "enabled":
        config_bbr_by_gcu(duthost, "disabled")
        bbr_enabled = False
    else:
        config_bbr_by_gcu(duthost, "enabled")
        bbr_enabled = True

    # Select specific data
    if ip_version == "ipv4":
        cfg = AggregateCfg(prefix=AGGR_V4, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)
    else:
        cfg = AggregateCfg(prefix=AGGR_V6, bbr_required=bbr_required, summary_only=summary_only, as_set=as_set)

    # Apply aggregate via GCU
    gcu_add_aggregate(duthost, cfg)

    # Verify config db, statedb and running config
    verify_bgp_aggregate_consistence(duthost, bbr_enabled, cfg)

    # Cleanup
    gcu_remove_aggregate(duthost, cfg.prefix)

    # Verify config db, statedb and running config are cleanup
    verify_bgp_aggregate_cleanup(duthost, cfg.prefix)

    # withdraw BBR state change
    if bbr_enabled:
        config_bbr_by_gcu(duthost, "disabled")
    else:
        config_bbr_by_gcu(duthost, "enabled")
