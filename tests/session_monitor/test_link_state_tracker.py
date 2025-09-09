#!/usr/bin/env python

import logging
import json
import os
import shutil
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
]


SOUTHBOUND_PORTCHANNELS = ['PortChannel1031', 'PortChannel1032']
LOOPBACK_INTERFACE = 'Loopback6'
STATE_DB_TABLE_NAME = 'LINK_STATE_TRACKER_TABLE'
STATE_DB_INSTANCE_NAME = 'WLPoToLo6'
STATE_DB_SCRIPT_ENABLED_KEY = 'is_link_state_tracker_enabled'
STATE_DB_SOUTHBOUND_PC_STATUS_KEY = 'southbound_portchannels_status'
STATE_DB_LOOPBACK_STATUS_KEY = 'loopback6_status'
CONFIG_DB_PATH = '/etc/sonic/config_db.json'
TEMP_FILE = "/tmp/config_db_update.json"
DOCKER_CONTAINER_NAME = 'session-monitor'
SERVICE_NAME = 'link-state-tracker'


def enable_session_monitor_container(duthost):
    """
    Update DEVICE_METADATA with deployment_id = 26 and enable session-monitor feature
    """
    duthost.fetch(src=CONFIG_DB_PATH, dest="/tmp/")

    with open(f"/tmp/{duthost.hostname}{CONFIG_DB_PATH}", "r") as config_file:
        data = json.load(config_file)
    data['DEVICE_METADATA']['localhost']['deployment_id'] = "26"
    data['FEATURE'][DOCKER_CONTAINER_NAME]['state'] = "enabled"

    logger.info(f"Updating DEVICE_METADATA in config_db.json with deployment_id=26 and "
                f"enable {DOCKER_CONTAINER_NAME} feature")
    duthost.copy(content=json.dumps(data, indent=2), dest=TEMP_FILE)
    duthost.shell(f"cp {TEMP_FILE} {CONFIG_DB_PATH}")


def get_available_vlan_id_and_ports(cfg_facts, num_ports_needed):
    """
    Return vlan id and available ports in that vlan if there are enough ports available.

    Args:
        cfg_facts: DUT config facts
        num_ports_needed: number of available ports needed for test
    """
    port_status = cfg_facts["PORT"]
    vlan_id = -1
    available_ports = []
    pytest_require("VLAN_MEMBER" in cfg_facts, "Can't get vlan member")
    for vlan_name, members in list(cfg_facts["VLAN_MEMBER"].items()):
        # Number of members in vlan is insufficient
        if len(members) < num_ports_needed:
            continue

        # Get available ports in vlan
        possible_ports = []
        for vlan_member in members:
            if port_status[vlan_member].get("admin_status", "down") != "up":
                continue

            possible_ports.append(vlan_member)
            if len(possible_ports) == num_ports_needed:
                available_ports = possible_ports[:]
                vlan_id = int(''.join([i for i in vlan_name if i.isdigit()]))
                break

        if vlan_id != -1:
            break

    logger.debug(f"Vlan {vlan_id} has available ports: {available_ports}")
    return vlan_id, available_ports


def setup_test_portchannels(duthost, ptfhost, config_facts, tbinfo):
    """
    Setup test portchannels for link state tracker testing.

    Args:
        duthost: DUT host
        ptfhost: PTF host
        config_facts: DUT config facts
        tbinfo: testbed info
    """
    port_indexes = config_facts['port_index_map']
    duts_map = tbinfo["duts_map"]
    dut_indx = duts_map[duthost.hostname]

    # Get available ports in PTF
    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {}
    for key in host_interfaces:
        ptf_ports_available_in_topo[host_interfaces[key]] = "eth{}".format(key)

    # Remove acl table since ports in acl table can't be added to portchannel
    duthost.remove_acl_table("EVERFLOW")
    duthost.remove_acl_table("EVERFLOWV6")

    # Create new portchannels for the test
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, len(SOUTHBOUND_PORTCHANNELS))
    pytest_assert(len(ports) == len(SOUTHBOUND_PORTCHANNELS),
                  f"Found {len(ports)} available ports. Needed {len(SOUTHBOUND_PORTCHANNELS)} ports for the test.")

    cmds = []
    bond_port_mapping = {}

    for i in range(len(SOUTHBOUND_PORTCHANNELS)):
        try:
            duthost.shell(f'config vlan member del {vlan_id} {ports[i]}')
            duthost.shell(f'config portchannel add {SOUTHBOUND_PORTCHANNELS[i]}')
            duthost.shell(f"config portchannel member add {SOUTHBOUND_PORTCHANNELS[i]} {ports[i]}")

            # Configure ptf port commands
            port_index = port_indexes[ports[i]]
            port_name = ptf_ports_available_in_topo[port_index]

            bond_port = 'bond{}'.format(port_index)
            cmds.append("ip link add {} type bond".format(bond_port))
            cmds.append("ip link set {} type bond miimon 100 mode 802.3ad".format(bond_port))
            cmds.append("ip link set {} down".format(port_name))
            cmds.append("ip link set {} master {}".format(port_name, bond_port))
            cmds.append("ip link set dev {} up".format(bond_port))
            cmds.append("ifconfig {} mtu 9216 up".format(bond_port))

            bond_port_mapping[bond_port] = port_name
        except Exception as e:
            logger.debug(f"Encountered error while setting up portchannels: {e}")
            continue

    # Execute commands to configure ptf ports
    ptfhost.shell_cmds(cmds=cmds)
    ptfhost.shell("supervisorctl restart ptf_nn_agent")
    time.sleep(5)

    return bond_port_mapping


def cleanup_test_portchannels(duthost, ptfhost, bond_port_mapping):
    """
    Cleanup test portchannels after testing.

    Args:
        duthost: DUT host
        ptfhost: PTF host
        bond_port_mapping: map of bond port name (bond#) to ptf port name (eth#)
    """
    # Notes: portchannels get removed when config_db is restored.

    # Remove bond ports from PTF
    logger.debug("cleanup: Removing ptf bond ports.")
    cmds = []
    for bond_port, port_name in bond_port_mapping.items():
        cmds.append("ip link set {} nomaster".format(bond_port))
        cmds.append("ip link set {} nomaster".format(port_name))
        cmds.append("ip link set {} up".format(port_name))
        cmds.append("ip link del {}".format(bond_port))

    ptfhost.shell_cmds(cmds=cmds)


def set_portchannel_oper_status(duthost, portchannel, status):
    """
    Set portchannel operational status in STATE_DB.

    Args:
        duthost: DUT host
        portchannel: portchannel name
        status: 'up' or 'down'
    """
    cmd = f"sonic-db-cli STATE_DB HSET 'LAG_TABLE|{portchannel}' oper_status {status}"
    duthost.shell(cmd)


def get_link_state_tracker_state_db_entry(duthost, key):
    """
    Get specific entry from LINK_STATE_TRACKER_TABLE in STATE_DB.

    Args:
        duthost: DUT host
        key: the key to retrieve
    """
    cmd = f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{key}'"
    result = duthost.shell(cmd)
    return result['stdout'].strip()


def get_loopback_config_admin_status(duthost):
    """
    Get loopback interface admin status from CONFIG_DB.

    Args:
        duthost: DUT host
    """
    cmd = f"sonic-db-cli CONFIG_DB HGET 'LOOPBACK_INTERFACE|{LOOPBACK_INTERFACE}' admin_status"
    result = duthost.shell(cmd)
    return result['stdout'].strip()


def reset_portchannels_state(duthost):
    """
    Set portchannels to admin up and oper up.

    Args:
        duthost: DUT host
    """
    for portchannel in SOUTHBOUND_PORTCHANNELS:
        duthost.shell(f"config interface startup {portchannel}")
        set_portchannel_oper_status(duthost, portchannel, "up")
    time.sleep(10)  # Allow time for state to propagate


def validate_link_state_tracker_enabled(duthost):
    """
    Test link state tracker functionality when enabled.

    - Test loopback6 is enabled when at least one southbound portchannel is up
    - Test loopback6 is disabled when all southbound portchannels are down
    - Test loopback6 re-enables when portchannel comes back up

    Args:
        duthost: DUT host
    """
    logger.debug("Running link state tracker enabled test.")

    # Make sure portchannels start with admin and oper up
    reset_portchannels_state(duthost)

    # Check link state tracker is enabled in state db
    is_enabled = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SCRIPT_ENABLED_KEY)
    pytest_assert(is_enabled == "yes", "Link state tracker should be enabled")

    # Test loopback6 disabled when all portchannels go down
    for i, portchannel in enumerate(SOUTHBOUND_PORTCHANNELS):
        set_portchannel_oper_status(duthost, portchannel, "down")
        time.sleep(10)  # Allow time for state to propagate

        # Check southbound portchannels status in state db
        southbound_pc_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SOUTHBOUND_PC_STATUS_KEY)
        expected_southbound_status = "down" if i == len(SOUTHBOUND_PORTCHANNELS) - 1 else "up"
        pytest_assert(southbound_pc_status == expected_southbound_status,
                      f"Southbound portchannels status should be {expected_southbound_status} "
                      f"after {i+1} portchannels down")

        # Check loopback status in state db
        loopback_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
        expected_loopback = "disabled" if i == len(SOUTHBOUND_PORTCHANNELS) - 1 else "enabled"
        pytest_assert(loopback_status == expected_loopback,
                      f"Loopback6 status should be {expected_loopback} after {i+1} portchannels down")

        # Check loopback admin status in CONFIG_DB
        config_admin_status = get_loopback_config_admin_status(duthost)
        expected_config_admin = "down" if i == len(SOUTHBOUND_PORTCHANNELS) - 1 else "up"
        pytest_assert(config_admin_status == expected_config_admin,
                      f"Loopback6 CONFIG_DB admin_status should be {expected_config_admin} "
                      f"after {i+1} portchannels down")

    # Test loopback6 enabled when portchannel comes back up
    set_portchannel_oper_status(duthost, SOUTHBOUND_PORTCHANNELS[0], "up")
    time.sleep(10)

    # Check southbound portchannel status is up in state db
    southbound_pc_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SOUTHBOUND_PC_STATUS_KEY)
    pytest_assert(southbound_pc_status == "up", "Southbound portchannel status should be up after portchannel comes up")

    # Check loopback status is enabled in state db
    loopback_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
    pytest_assert(loopback_status == "enabled", "Loopback6 should be enabled after portchannel comes up")

    # Check loopback admin status in CONFIG_DB
    config_admin_status = get_loopback_config_admin_status(duthost)
    pytest_assert(config_admin_status == "up", "Loopback6 admin_status should be up in CONFIG_DB")


def validate_link_state_tracker_disabled(duthost):
    """
    Test behavior when link state tracker is disabled.

    - Test loopback6 status doesn't change when portchannels go down
    - Test state db entries remain unchanged

    Args:
        duthost: DUT host
    """
    logger.debug("Running link state tracker disabled test.")

    # Make sure portchannels start with admin and oper up
    reset_portchannels_state(duthost)

    # Check link state tracker is disabled in state db
    is_enabled = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SCRIPT_ENABLED_KEY)
    pytest_assert(is_enabled == "no", "Link state tracker should be disabled")

    # Get initial state db values
    initial_southbound_pc_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SOUTHBOUND_PC_STATUS_KEY)
    initial_loopback = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
    initial_admin_status = get_loopback_config_admin_status(duthost)

    # Test portchannel shutdown - states should not change when tracker is disabled
    for portchannel in SOUTHBOUND_PORTCHANNELS:
        set_portchannel_oper_status(duthost, portchannel, "down")

    time.sleep(15)  # Allow time for any potential changes

    # Check southbound portchannel status remains unchanged in state db
    southbound_pc_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SOUTHBOUND_PC_STATUS_KEY)
    pytest_assert(southbound_pc_status == initial_southbound_pc_status,
                  "Southbound portchannel status should remain unchanged when tracker is disabled")

    # Check loopback status remains unchanged in state db
    loopback_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
    pytest_assert(loopback_status == initial_loopback,
                  "Loopback6 status should remain unchanged when tracker is disabled")

    # Check loopback admin status remains unchanged in CONFIG_DB
    config_admin_status = get_loopback_config_admin_status(duthost)
    pytest_assert(config_admin_status == initial_admin_status,
                  "Loopback6 admin_status should remain unchanged when tracker is disabled")


def cleanup(duthost, ptfhost, bond_port_mapping):
    """
    Return duthost and ptfhost to original state.

    Args:
        duthost: DUT host
        ptfhost: PTF host
        bond_port_mapping: map of bond port name (bond#) to ptf port name (eth#)
    """
    logger.debug("cleanup: Loading backup config db json.")
    duthost.shell(f"mv {CONFIG_DB_PATH}.bak {CONFIG_DB_PATH}")

    # Cleanup test portchannels
    cleanup_test_portchannels(duthost, ptfhost, bond_port_mapping)

    # Reload to restore configuration
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

    # Remove tmp files
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)
    if os.path.exists(f"/tmp/{duthost.hostname}"):
        shutil.rmtree(f"/tmp/{duthost.hostname}")


@pytest.fixture(scope="function")
def common_setup_and_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, localhost):
    """
    Setup and cleanup entry for tests.

    Args:
        tbinfo: testbed info
        duthosts: DUT hosts
        rand_one_dut_hostname: DUT host name
        ptfhost: PTF host
        localhost: localhost info
    """
    duthost = duthosts[rand_one_dut_hostname]

    # backup config_db.json for cleanup
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    # update device metadata in config_db.json
    enable_session_monitor_container(duthost)
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    time.sleep(10)  # Allow time for config reload to complete

    # Verify session-monitor service is running
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl status {SERVICE_NAME}")

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    logger.debug("setup config_facts: {}".format(config_facts))

    # Setup test portchannels
    bond_port_mapping = setup_test_portchannels(duthost, ptfhost, config_facts, tbinfo)

    # Create loopback interface if it doesn't exist
    duthost.shell(f"config loopback add {LOOPBACK_INTERFACE}", module_ignore_errors=True)

    # Wait for system to stabilize after setup
    time.sleep(15)
    yield duthost

    # Cleanup
    cleanup(duthost, ptfhost, bond_port_mapping)


def test_link_state_tracker(common_setup_and_teardown):
    """
    Entry point for running link state tracker tests.
    """
    duthost = common_setup_and_teardown

    # Run tests
    # Test script works when enabled. Should be enabled by default.
    validate_link_state_tracker_enabled(duthost)

    # Disable link state tracker
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl stop {SERVICE_NAME}")
    time.sleep(10)

    # Test script doesn't do anything when disabled
    validate_link_state_tracker_disabled(duthost)

    # Enable link state tracker
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl start {SERVICE_NAME}")
    time.sleep(10)

    # Test script works when re-enabled
    validate_link_state_tracker_enabled(duthost)


def test_link_state_tracker_rapid_state_changes(common_setup_and_teardown):
    """
    Test link state tracker behavior with rapid portchannel state transitions.
    This test validates that the tracker can handle rapid up/down state changes
    without losing state or creating race conditions
    """
    duthost = common_setup_and_teardown

    # Ensure service is running
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl start {SERVICE_NAME}")
    time.sleep(10)

    # Test rapid up/down transitions
    # Using 5 second intervals to test rapid changes while allowing state propagation
    for i in range(3):
        logger.debug(f"Flapping test iteration {i+1}")

        # Bring all portchannels down
        for pc in SOUTHBOUND_PORTCHANNELS:
            set_portchannel_oper_status(duthost, pc, "down")
        time.sleep(5)

        # Verify loopback disabled
        loopback_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
        pytest_assert(loopback_status == "disabled", f"Loopback6 should be disabled on iteration {i+1}")

        # Bring one portchannel up
        set_portchannel_oper_status(duthost, SOUTHBOUND_PORTCHANNELS[0], "up")
        time.sleep(5)

        # Verify loopback enabled
        loopback_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
        pytest_assert(loopback_status == "enabled", f"Loopback6 should be enabled on iteration {i+1}")


def test_link_state_tracker_service_restart(common_setup_and_teardown):
    """
    Test link state tracker behavior after service restart.
    """
    duthost = common_setup_and_teardown

    # Start with a known state
    reset_portchannels_state(duthost)
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl start {SERVICE_NAME}")
    time.sleep(10)

    # Set specific state - one portchannel down, one up
    set_portchannel_oper_status(duthost, SOUTHBOUND_PORTCHANNELS[0], "up")
    set_portchannel_oper_status(duthost, SOUTHBOUND_PORTCHANNELS[1], "down")
    time.sleep(10)

    # Verify expected state before restart
    loopback_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
    pytest_assert(loopback_status == "enabled", "Loopback6 should be enabled before restart")

    # Restart the service
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl restart {SERVICE_NAME}")
    time.sleep(15)  # Allow more time for service restart and initialization

    # Verify service picks up current state correctly after restart
    is_enabled = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SCRIPT_ENABLED_KEY)
    pytest_assert(is_enabled == "yes", "Link state tracker should be enabled after restart")

    southbound_pc_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_SOUTHBOUND_PC_STATUS_KEY)
    pytest_assert(southbound_pc_status == "up",
                  "southbound portchannel status should be up after restart (one PC is up)")

    loopback_status = get_link_state_tracker_state_db_entry(duthost, STATE_DB_LOOPBACK_STATUS_KEY)
    pytest_assert(loopback_status == "enabled", "Loopback6 should remain enabled after restart")
