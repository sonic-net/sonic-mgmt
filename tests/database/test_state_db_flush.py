"""
Test STATE_DB table cleanup during swss cold restart.

Verifies that tables owned by orchagent in STATE_DB are properly cleaned up
when swss is restarted (non-warm-boot). This ensures stale state from a
previous orchagent run does not persist across service restarts.
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.processes_utils import wait_critical_processes

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

# All STATE_DB tables that swss.sh cleans up on cold restart.
# Sentinel keys use a fake sub-key that orchagent will never recreate,
# so their absence after restart proves the cleanup ran.
STATE_DB_CLEANUP_TABLES = [
    "PORT_TABLE",
    "MGMT_PORT_TABLE",
    "VLAN_TABLE",
    "VLAN_MEMBER_TABLE",
    "LAG_TABLE",
    "LAG_MEMBER_TABLE",
    "INTERFACE_TABLE",
    "MIRROR_SESSION",
    "VRF_TABLE",
    "FDB_TABLE",
    "FG_ROUTE_TABLE",
    "BUFFER_POOL",
    "BUFFER_PROFILE",
    "MUX_CABLE_TABLE",
    "ADVERTISE_NETWORK_TABLE",
    "VXLAN_TUNNEL_TABLE",
    "VNET_ROUTE",
    "MACSEC_PORT_TABLE",
    "MACSEC_INGRESS_SA_TABLE",
    "MACSEC_EGRESS_SA_TABLE",
    "MACSEC_INGRESS_SC_TABLE",
    "MACSEC_EGRESS_SC_TABLE",
    "VRF_OBJECT_TABLE",
    "VNET_MONITOR_TABLE",
    "BFD_SESSION_TABLE",
    "SYSTEM_NEIGH_TABLE",
    "FABRIC_PORT_TABLE",
    "TUNNEL_DECAP_TABLE",
    "TUNNEL_DECAP_TERM_TABLE",
    "HIGH_FREQUENCY_TELEMETRY_SESSION_TABLE",
    "PROCESS_HEALTH",
]

SENTINEL_SUBKEY = "__test_sentinel__"


def _sentinel_key(table):
    """Return a sentinel STATE_DB key for the given table."""
    return "{}|{}".format(table, SENTINEL_SUBKEY)


def _set_state_db_entry(duthost, key, field, value):
    """Set a field in a STATE_DB hash key."""
    duthost.shell('sonic-db-cli STATE_DB HSET "{}" "{}" "{}"'.format(key, field, value))


def _key_exists(duthost, key):
    """Check whether a specific key exists in STATE_DB."""
    result = duthost.shell('sonic-db-cli STATE_DB EXISTS "{}"'.format(key))
    return result["stdout"].strip() == "1"


def _is_service_hitting_start_limit(duthost, container_name):
    """Check if a service is hitting the systemd start-limit."""
    result = duthost.shell(
        "sudo systemctl status {}.service | grep 'Active'".format(container_name),
        module_ignore_errors=True
    )
    for line in result["stdout_lines"]:
        if "start-limit-hit" in line:
            return True
    return False


def _restart_swss_and_wait(duthost):
    """Cold-restart the swss service and wait for critical processes."""
    duthost.shell("sudo systemctl reset-failed swss", module_ignore_errors=True)
    duthost.shell("sudo systemctl restart swss")

    # Clear start-limit for any service that may have hit it
    for container in duthost.get_default_critical_services_list():
        if _is_service_hitting_start_limit(duthost, container):
            logger.info("{} hit start limit, resetting".format(container))
            duthost.shell("sudo systemctl reset-failed {}.service".format(container))
            duthost.shell("sudo systemctl start {}.service".format(container))

    wait_critical_processes(duthost)


def test_state_db_cleanup_after_swss_restart(duthosts, rand_one_dut_hostname):
    """
    Verify all orchagent-owned STATE_DB tables are cleaned up during swss cold restart.

    Steps:
        1. Populate a sentinel entry in every STATE_DB table that swss.sh cleans.
        2. Confirm all sentinel entries exist.
        3. Cold-restart swss (single restart for all tables).
        4. Verify every sentinel entry is removed from STATE_DB.
    """
    duthost = duthosts[rand_one_dut_hostname]

    # Populate sentinel keys for all tables
    for table in STATE_DB_CLEANUP_TABLES:
        key = _sentinel_key(table)
        logger.info("Setting sentinel STATE_DB entry: {}".format(key))
        _set_state_db_entry(duthost, key, "test_field", "test_value")

    # Verify all sentinel keys were created
    missing = [t for t in STATE_DB_CLEANUP_TABLES if not _key_exists(duthost, _sentinel_key(t))]
    pytest_assert(
        not missing,
        "Failed to create sentinel entries for tables: {}".format(missing)
    )

    logger.info("Cold-restarting swss service")
    _restart_swss_and_wait(duthost)

    # Verify all sentinel keys are cleaned up
    stale = [t for t in STATE_DB_CLEANUP_TABLES if _key_exists(duthost, _sentinel_key(t))]
    pytest_assert(
        not stale,
        "STATE_DB entries not cleaned up after swss cold restart: {}".format(stale)
    )
