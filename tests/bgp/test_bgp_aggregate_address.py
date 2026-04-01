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

import logging

import pytest

# Functions
from bgp_bbr_helpers import config_bbr_by_gcu, get_bbr_default_state, is_bbr_enabled

from bgp_aggregate_helpers import (  # noqa: F401
    AggregateCfg,
    gcu_add_aggregate,
    gcu_remove_aggregate,
    setup_teardown,
    verify_bgp_aggregate_consistence,
    verify_bgp_aggregate_cleanup,
)

logger = logging.getLogger(__name__)

# ---- Topology & device-type markers (register in pytest.ini to avoid warnings) ----
pytestmark = [pytest.mark.topology("m1"), pytest.mark.device_type("vs"), pytest.mark.disable_loganalyzer]

# ---- Constants ----
CONSTANTS_FILE = "/etc/sonic/constants.yml"

# Aggregate prefixes
AGGR_V4 = "172.16.51.0/24"
AGGR_V6 = "2000:172:16:50::/64"


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
