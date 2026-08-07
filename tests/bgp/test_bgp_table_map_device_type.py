"""
Test BGP table-map device type gating (SELECTIVE_ROUTE_DOWNLOAD)

Verifies that `table-map SELECTIVE_ROUTE_DOWNLOAD_V4/V6` is generated in the
FRR bgpd config only for device types that should have FIB filtering enabled:
  - UpperSpineRouter              → table-map PRESENT
  - SpineRouter + UpstreamLC      → table-map PRESENT
  - SpineRouter + DownstreamLC    → table-map ABSENT
  - LeafRouter                    → table-map ABSENT

These tests are kept separate from test_bgp_table_map.py to avoid interference
with the module-level device type fixture used in the FIB filtering tests.

Related: Work Item 37441388 (SELECTIVE_ROUTE_DOWNLOAD)
"""

import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.bgp.test_bgp_table_map import (
    set_device_type,
    restart_bgp_and_wait,
    restart_bgp_and_wait_responsive,
)

pytestmark = [
    pytest.mark.topology('t1', 't2', 'lrh', 'urh'),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)

TABLE_MAP_V4 = "table-map SELECTIVE_ROUTE_DOWNLOAD_V4"
TABLE_MAP_V6 = "table-map SELECTIVE_ROUTE_DOWNLOAD_V6"


def is_table_map_configured(duthost):
    """
    Check if table-map SELECTIVE_ROUTE_DOWNLOAD_V4 is in the running FRR config.
    Handles both unified (frr.conf) and split (bgpd.conf) routing config modes.
    """
    routing_mode = duthost.shell(
        "sonic-cfggen -d -v DEVICE_METADATA.localhost.docker_routing_config_mode",
        module_ignore_errors=True
    )["stdout"].strip()
    conf_file = "/etc/frr/frr.conf" if routing_mode == "unified" else "/etc/frr/bgpd.conf"
    output = duthost.shell(
        "docker exec bgp cat {}".format(conf_file), module_ignore_errors=True
    )["stdout"]
    return TABLE_MAP_V4 in output, TABLE_MAP_V6 in output


@pytest.mark.parametrize("device_type,subtype,should_enable", [
    ("UpperSpineRouter", None, True),
    ("SpineRouter", "UpstreamLC", True),
    ("SpineRouter", "DownstreamLC", False),
    ("LeafRouter", None, False),
    ("UpperRegionalHub", None, True),
])
def test_table_map_device_type_check(duthosts, enum_dut_hostname,
                                     device_type, subtype, should_enable):
    """
    Verify table-map is present/absent in bgpd config for each device type.

    Changes device type in DEVICE_METADATA, restarts BGP docker to regenerate
    FRR templates, checks bgpd.conf for table-map directive, then restores.
    """
    duthost = duthosts[enum_dut_hostname]

    original_type = duthost.shell(
        "redis-cli -n 4 HGET 'DEVICE_METADATA|localhost' type",
        module_ignore_errors=True
    )["stdout"].strip() or "ToRRouter"
    original_subtype = duthost.shell(
        "redis-cli -n 4 HGET 'DEVICE_METADATA|localhost' subtype",
        module_ignore_errors=True
    )["stdout"].strip() or None

    try:
        logger.info("Setting device type: {}/{}".format(device_type, subtype))
        set_device_type(duthost, device_type, subtype)
        if should_enable:
            restart_bgp_and_wait(duthost)
        else:
            # Device types where table-map is expected to be disabled (e.g.
            # LeafRouter) may render a peer-group template incompatible with
            # this topology's real neighbors, so full neighbor convergence
            # isn't guaranteed here and isn't needed for this assertion -
            # only bgpd/bgpcfgd being up and having processed CONFIG_DB matters.
            restart_bgp_and_wait_responsive(duthost)

        v4_present, v6_present = is_table_map_configured(duthost)

        pytest_assert(
            v4_present == should_enable,
            "Device {}/{}: {} expected={}, actual={}".format(
                device_type, subtype, TABLE_MAP_V4, should_enable, v4_present)
        )
        pytest_assert(
            v6_present == should_enable,
            "Device {}/{}: {} expected={}, actual={}".format(
                device_type, subtype, TABLE_MAP_V6, should_enable, v6_present)
        )
        logger.info("PASS: {}/{} → table-map enabled={}".format(device_type, subtype, v4_present))
    finally:
        logger.info("Restoring device type: {}/{}".format(original_type, original_subtype))
        set_device_type(duthost, original_type, original_subtype)
        restart_bgp_and_wait(duthost)
        logger.info("Device type restored")
