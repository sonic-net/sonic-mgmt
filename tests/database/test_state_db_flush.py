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
    pytest.mark.topology('t0', 't1', 't2', 'lt2', 'ft2'),
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


def test_state_db_cleanup_after_swss_restart(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                             enum_frontend_asic_index):
    """
    Verify all orchagent-owned STATE_DB tables are cleaned up during swss cold restart.

    Steps:
        1. Populate a sentinel entry in every STATE_DB table that swss.sh cleans.
        2. Confirm all sentinel entries exist.
        3. Cold-restart swss for the given ASIC.
        4. Verify every sentinel entry is removed from STATE_DB.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_frontend_asic_index)
    service_name = asichost.get_service_name("swss")
    db_cli = "{} STATE_DB".format(asichost.sonic_db_cli)

    # Populate sentinel keys for all tables
    for table in STATE_DB_CLEANUP_TABLES:
        key = _sentinel_key(table)
        logger.info("Setting sentinel STATE_DB entry: {} (asic {})".format(key, enum_frontend_asic_index))
        duthost.shell('{} HSET "{}" "test_field" "test_value"'.format(db_cli, key))

    # Verify all sentinel keys were created
    missing = []
    for table in STATE_DB_CLEANUP_TABLES:
        result = duthost.shell('{} EXISTS "{}"'.format(db_cli, _sentinel_key(table)))
        if result["stdout"].strip() != "1":
            missing.append(table)
    pytest_assert(not missing,
                  "Failed to create sentinel entries for tables: {}".format(missing))

    # Cold-restart swss for this ASIC
    logger.info("Cold-restarting {} on asic {}".format(service_name, enum_frontend_asic_index))
    duthost.shell("sudo systemctl reset-failed {}".format(service_name), module_ignore_errors=True)
    duthost.shell("sudo systemctl restart {}".format(service_name))

    for container in duthost.get_default_critical_services_list():
        if _is_service_hitting_start_limit(duthost, container):
            logger.info("{} hit start limit, resetting".format(container))
            duthost.shell("sudo systemctl reset-failed {}.service".format(container))
            duthost.shell("sudo systemctl start {}.service".format(container))

    wait_critical_processes(duthost)

    # Verify all sentinel keys are cleaned up
    stale = []
    for table in STATE_DB_CLEANUP_TABLES:
        result = duthost.shell('{} EXISTS "{}"'.format(db_cli, _sentinel_key(table)))
        if result["stdout"].strip() == "1":
            stale.append(table)
    pytest_assert(not stale,
                  "STATE_DB entries not cleaned up after swss cold restart (asic {}): {}".format(
                      enum_frontend_asic_index, stale))
