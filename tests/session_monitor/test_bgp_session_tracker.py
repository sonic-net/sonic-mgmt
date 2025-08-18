import logging
import json
import os
import shutil
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.config_reload import config_reload
from tests.common.reboot import reboot

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
]

PORT_CHANNEL_NAMES = ['PortChannel1031', 'PortChannel1032']
STATE_DB_TABLE_NAME = 'BGP_SESSION_TRACKER_TABLE'
STATE_DB_INSTANCE_NAME = 'T1toWL'
STATE_DB_SCRIPT_ENABLED_KEY = 'is_session_tracker_enabled'
STATE_DB_INTERFACE_SHUTDOWN_KEY = 'interfaces_are_shutdown'
STATE_DB_BGP_SESSIONS_UP_KEY = 'bgp_sessions_up'
CONFIG_DB_PATH = '/etc/sonic/config_db.json'
TEMP_FILE = "/tmp/config_db_update.json"
DOCKER_CONTAINER_NAME = 'session-monitor'
SERVICE_NAME = 'bgp-session-tracker'

def enable_session_monitor_container(duthost):
    """
    Update DEVICE_METADATA with deployment_id = 26 and enable session-monitor feature.
    """
    duthost.fetch(src=CONFIG_DB_PATH, dest="/tmp/")

    with open(f"/tmp/{duthost.hostname}{CONFIG_DB_PATH}", "r") as config_file:
        data = json.load(config_file)
    data['DEVICE_METADATA']['localhost']['deployment_id'] = "26"
    data['FEATURE'][DOCKER_CONTAINER_NAME]['state'] = "enabled"

    logger.info("Updating DEVICE_METADATA in config_db.json")
    duthost.copy(content=json.dumps(data, indent=2), dest=TEMP_FILE)
    duthost.shell(f"cp {TEMP_FILE} {CONFIG_DB_PATH}")

def validate_bgp_session_tracking_enabled(duthost, t1_bgp_neighbors):
    """
    Test bgp session tracking script.
    - Test southbound portchannels are up if not all northbound T1 bgp sessions are down
    - Test southbound portchannels shutdown when all northbound T1 bgp sessions are down
    - Test southbound portchannels startup when at least 1 northbound T1 bgp session is up

    Args:
        duthost: DUT host
        t1_bgp_neighbors: list of T1 bgp neighbor ips
    """
    logger.debug("Running bgp session tracking enabled test.")

    # Make sure bgp sessions and portchannels start with admin up
    reset_bgp_and_portchannels_state(duthost, t1_bgp_neighbors)

    # Check bgp session tracker is enabled in state db
    is_enabled = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_SCRIPT_ENABLED_KEY}'")
    pytest_assert(is_enabled['stdout'].strip() == "yes")
    
    # Test portchannel shutdown
    for i, neighbor in enumerate(t1_bgp_neighbors):
        duthost.shell(f"config bgp shutdown neighbor {neighbor}")
        time.sleep(20)

        # Check portchannels remain up if not all neighbors are down, and portchannels shutdown after all neighbors shut down.
        # Check bgp sessions up entry in state db
        is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_BGP_SESSIONS_UP_KEY}'")
        pytest_assert(is_bgp_up['stdout'].strip() == "no" if i == len(t1_bgp_neighbors) - 1 else "yes")
        # Check interfaces are shutdown entry in state db
        is_shutdown = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")
        pytest_assert(is_shutdown['stdout'].strip() == "yes" if i == len(t1_bgp_neighbors) - 1 else "no")
        # check portchannel admin status
        intf_stat = [intf for intf in duthost.show_and_parse('show int stat') if intf['interface'] in PORT_CHANNEL_NAMES]
        for intf in intf_stat:
            pytest_assert(intf['admin'] == ('down' if i == len(t1_bgp_neighbors) - 1 else 'up'))

    # Test portchannel startup
    duthost.shell(f"config bgp startup neighbor {t1_bgp_neighbors[0]}")
    time.sleep(20)

    # Check portchannels startup after at least 1 neighbor starts up
    # Check bgp sessions are up in state db
    is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_BGP_SESSIONS_UP_KEY}'")
    pytest_assert(is_bgp_up['stdout'].strip() == "yes")
    # Check interfaces are not shutdown in state db
    is_shutdown = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")
    pytest_assert(is_shutdown['stdout'].strip() == "no")
    # Check PortChannel admin status are up
    intf_stat = [intf for intf in duthost.show_and_parse('show int stat') if intf['interface'] in PORT_CHANNEL_NAMES]
    for intf in intf_stat:
        pytest_assert(intf['admin'] == 'up')

def validate_bgp_session_tracking_disabled(duthost, t1_bgp_neighbors):
    """
    Test behavior without bgp session tracking script.
    - Test southbound portchannels are up even when all northbound T1 bgp sessions are down

    Args:
        duthost: DUT host
        t1_bgp_neighbors: list of T1 bgp neighbor ips
    """
    logger.debug("Running bgp session tracking disabled test.")

    # Make sure bgp sessions and portchannels start with admin up
    reset_bgp_and_portchannels_state(duthost, t1_bgp_neighbors)

    # Check bgp session tracker is disabled in state db
    is_enabled = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_SCRIPT_ENABLED_KEY}'")
    pytest_assert(is_enabled['stdout'].strip() == "no")

    # Get initial state db values
    initial_is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_BGP_SESSIONS_UP_KEY}'")['stdout'].strip()
    initial_is_shutdown = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")['stdout'].strip()

    # Test bgp shutdown, portchannels should remain up
    for neighbor in t1_bgp_neighbors:
        duthost.shell(f"config bgp shutdown neighbor {neighbor}")

    # Check portchannels remain up when all bgp neighbors are down
    time.sleep(20)
    # Check bgp sessions remain up in state db
    is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_BGP_SESSIONS_UP_KEY}'")
    pytest_assert(is_bgp_up['stdout'].strip() == initial_is_bgp_up)
    # Check interfaces are not shutdown in state db
    is_shutdown = duthost.shell(f"sonic-db-cli STATE_DB HGET '{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")
    pytest_assert(is_shutdown['stdout'].strip() == initial_is_shutdown)
    # Check PortChannel admin status are up
    intf_stat = [intf for intf in duthost.show_and_parse('show int stat') if intf['interface'] in PORT_CHANNEL_NAMES]
    for intf in intf_stat:
        pytest_assert(intf['admin'] == 'up')

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

def reset_bgp_and_portchannels_state(duthost, t1_bgp_neighbors):
    """
    Set T1 bgp neighbors and portchannels to admin up.

    Args:
        duthost: DUT host
        t1_bgp_neighbors: list of T1 bgp neighbor ips
    """
    for neighbor in t1_bgp_neighbors:
        duthost.shell(f"config bgp startup neighbor {neighbor}")
    for portchannel in PORT_CHANNEL_NAMES:
        duthost.shell(f"config int startup {portchannel}")
    time.sleep(20)

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

    # Reload to restore configuration
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)

    # Remove bond ports
    logger.debug("cleanup: Removing ptf bond ports.")
    cmds = []
    for bond_port, port_name in bond_port_mapping.items():
        cmds.append("ip link set {} nomaster".format(bond_port))
        cmds.append("ip link set {} nomaster".format(port_name))
        cmds.append("ip link set {} up".format(port_name))
        cmds.append("ip link del {}".format(bond_port))

    ptfhost.shell_cmds(cmds=cmds)

    # Remove tmp files
    if os.path.exists(TEMP_FILE):
        os.remove(TEMP_FILE)
    if os.path.exists(f"/tmp/{duthost.hostname}"):
        shutil.rmtree(f"/tmp/{duthost.hostname}")

@pytest.fixture(scope="module")
def common_setup_and_teardown(tbinfo, duthosts, rand_one_dut_hostname, ptfhost, localhost):
    """
    Setup and cleanup entry for tests.

    Args:
        tbinfo: testbed info
        duthosts: DUT hosts
        rand_one_dut_hostname: DUT host name
        ptfhost: PTF host
    """
    duthost = duthosts[rand_one_dut_hostname]

    # backup config_db.json for cleanup
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    # update device metadata in config_db.json
    enable_session_monitor_container(duthost)
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
    time.sleep(10)

    # verify container and service are running
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl status {SERVICE_NAME}")

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    port_indexes = config_facts['port_index_map']
    duts_map = tbinfo["duts_map"]
    dut_indx = duts_map[duthost.hostname]
    # Get available ports in PTF
    host_interfaces = tbinfo["topo"]["ptf_map"][str(dut_indx)]
    ptf_ports_available_in_topo = {}
    for key in host_interfaces:
        ptf_ports_available_in_topo[host_interfaces[key]] = "eth{}".format(key)

    logger.debug("setup config_facts: {}".format(config_facts))
    logger.debug("setup bgp_neighbors: {}".format(bgp_neighbors))
    logger.debug("setup port index map: {}".format(port_indexes))
    logger.debug("setup ports available in ptf topo: {}".format(ptf_ports_available_in_topo))

    # Remove acl table since ports in acl table can't be added to portchannel
    duthost.remove_acl_table("EVERFLOW")
    duthost.remove_acl_table("EVERFLOWV6")

    # Create new portchannels for the test
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, len(PORT_CHANNEL_NAMES))
    pytest_assert(len(ports) == len(PORT_CHANNEL_NAMES), f"Found {len(ports)} available ports. Needed {len(PORT_CHANNEL_NAMES)} ports for the test.")
    cmds = []
    bond_port_mapping = {}
    for i in range(len(PORT_CHANNEL_NAMES)):
        try:
            # Create portchannel with the right names on dut
            duthost.shell(f'config vlan member del {vlan_id} {ports[i]}')
            duthost.shell(f'config portchannel add {PORT_CHANNEL_NAMES[i]}')
            duthost.shell(f"config portchannel member add {PORT_CHANNEL_NAMES[i]} {ports[i]}")

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

    # Find all T1 bgp sessions.
    t1_bgp_neighbors = []
    for neighbor, value in bgp_neighbors.items():
        if ':' not in neighbor and 'T1' in value['name']:
            t1_bgp_neighbors.append(neighbor)
    pytest_assert(len(t1_bgp_neighbors) > 0, "There are no T1 bgp sessions configured for this test.")

    yield duthost, t1_bgp_neighbors

    # Cleanup
    cleanup(duthost, ptfhost, bond_port_mapping)


def test_bgp_session_tracker(common_setup_and_teardown):
    """
    Entry for running tests.
    """
    duthost, t1_bgp_neighbors = common_setup_and_teardown

    # Run tests
    # Test script works when enabled. Should be enabled by default.
    validate_bgp_session_tracking_enabled(duthost, t1_bgp_neighbors)

    # Disable bgp session tracker
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl stop {SERVICE_NAME}")
    time.sleep(10)

    # Test script doesn't do anything when disabled
    validate_bgp_session_tracking_disabled(duthost, t1_bgp_neighbors)

    # Enable bgp session tracker
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl start {SERVICE_NAME}")
    time.sleep(10)

    # Test script works when re-enabled
    validate_bgp_session_tracking_enabled(duthost, t1_bgp_neighbors)
