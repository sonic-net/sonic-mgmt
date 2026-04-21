from datetime import datetime
import logging
import json
import os
import shutil
import pytest
import time
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("t0"),
]

PORT_CHANNEL_NAMES = ['PortChannel1031', 'PortChannel1032']
GPU_PORTCHANNELS = [f'PortChannel10{i}' for i in range(31, 47)]
GPU_RESOURCE_TYPE = "BMOffnetGPUV2"


STATE_DB_TABLE_NAME = 'BGP_SESSION_TRACKER_TABLE'
STATE_DB_INSTANCE_NAME = 'T1toWL'
STATE_DB_SCRIPT_ENABLED_KEY = 'is_session_tracker_enabled'
STATE_DB_INTERFACE_SHUTDOWN_KEY = 'interfaces_are_shutdown'
STATE_DB_BGP_SESSIONS_UP_KEY = 'bgp_sessions_up'
CONFIG_DB_PATH = '/etc/sonic/config_db.json'
TEMP_FILE = "/tmp/config_db_update.json"
DOCKER_CONTAINER_NAME = 'session-monitor'
SERVICE_NAME = 'bgp-session-tracker'


def enable_session_monitor_container(duthost, resource_type):
    """
    Update DEVICE_METADATA with deployment_id = 26, resource_type (if provided) and enable session-monitor feature.
    """
    duthost.fetch(src=CONFIG_DB_PATH, dest="/tmp/")

    with open(f"/tmp/{duthost.hostname}{CONFIG_DB_PATH}", "r") as config_file:
        data = json.load(config_file)
    data['DEVICE_METADATA']['localhost']['deployment_id'] = "26"
    if resource_type:
        data['DEVICE_METADATA']['localhost']['resource_type'] = resource_type

    data['FEATURE'][DOCKER_CONTAINER_NAME]['state'] = "enabled"

    if resource_type == GPU_RESOURCE_TYPE:
        for neighbor, value in data.get('DEVICE_NEIGHBOR', {}).items():
            if 'T1' in value['name']:
                value['name'] = value['name'].replace('T1', 'T2')

        device_neighbor_metadata_copy = list(data.get('DEVICE_NEIGHBOR_METADATA', {}).items())
        for neighbor, value in device_neighbor_metadata_copy:
            if 'T1' in neighbor:
                new_neighbor = neighbor.replace('T1', 'T2')
                data['DEVICE_NEIGHBOR_METADATA'][new_neighbor] = data['DEVICE_NEIGHBOR_METADATA'].pop(neighbor)

        for _, value in data.get('PORT', {}).items():
            if 'T1' in value['description']:
                value['description'] = value['description'].replace('T1', 'T2')

        for neighbor, value in data.get('BGP_NEIGHBOR', {}).items():
            if ':' not in neighbor and 'T1' in value['name']:
                value['name'] = value['name'].replace('T1', 'T2')

    logger.info("Updating DEVICE_METADATA in config_db.json")
    duthost.copy(content=json.dumps(data, indent=2), dest=TEMP_FILE)
    duthost.shell(f"cp {TEMP_FILE} {CONFIG_DB_PATH}")


def poll_portchannel_status(duthost, portchannels, expected_admin, expected_oper, timeout=100, interval=0.1):
    """
    Poll portchannel status until expected admin and oper status is reached.

    Args:
        duthost: DUT host
        expected_admin: expected admin status
        expected_oper: expected oper status
    """
    start_time = datetime.now()
    while (datetime.now() - start_time).total_seconds() < timeout:
        status_matched = True

        cmd_start_time = time.time()
        parsed_int_stat = duthost.show_and_parse("show int stat")
        cmd_elapsed_time = time.time() - cmd_start_time
        logger.info("Command 'show int stat' completed in %.3f seconds", cmd_elapsed_time)

        intf_stat = [intf for intf in parsed_int_stat if intf['interface'] in portchannels]
        member_stat = [intf for intf in parsed_int_stat if intf['vlan'] in portchannels]
        pytest_assert(len(intf_stat) > 0, "No expected PortChannel interfaces found in show int stat output.")

        for intf in intf_stat:
            if intf['admin'] != expected_admin or intf['oper'] != expected_oper:
                status_matched = False
                break
        else:
            for member in member_stat:
                if member['oper'] != expected_oper:
                    status_matched = False
                    break

        if status_matched:
            logger.info(f"Southbound PortChannels reached expected status "
                        f"admin: {expected_admin}, "
                        f"oper: {expected_oper} in {(datetime.now() - start_time).seconds} seconds.")
            return

        time.sleep(interval)

    pytest_assert(False,
                  f"Southbound PortChannels did not reach expected status "
                  f"admin: {expected_admin}, "
                  f"oper: {expected_oper} within {timeout} seconds.")


def validate_bgp_session_tracking_enabled(duthost, portchannels, target_bgp_neighbors):
    """
    Test bgp session tracking script.
    - Test southbound portchannels are up if not all northbound target bgp sessions are down
    - Test southbound portchannels shutdown when all northbound target bgp sessions are down
    - Test southbound portchannels startup when at least 1 northbound target bgp session is up

    Args:
        duthost: DUT host
        target_bgp_neighbors: list of target bgp neighbor ips
    """
    logger.debug("Running bgp session tracking enabled test.")

    # Make sure bgp sessions and portchannels start with admin up
    reset_bgp_and_portchannels_state(duthost, portchannels, target_bgp_neighbors)

    # Check bgp session tracker is enabled in state db
    is_enabled = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                               f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' "
                               f"'{STATE_DB_SCRIPT_ENABLED_KEY}'")
    pytest_assert(is_enabled['stdout'].strip() == "yes")

    # Test portchannel shutdown
    for i, neighbor in enumerate(target_bgp_neighbors):
        duthost.shell(f"config bgp shutdown neighbor {neighbor}")

        # check portchannel admin status
        poll_portchannel_status(duthost, portchannels,
                                expected_admin='up', expected_oper='up'
                                if i < len(target_bgp_neighbors) - 1 else 'down')

        # Check portchannels remain up if not all neighbors are down,
        # and portchannels shutdown after all neighbors shut down.
        # Check bgp sessions up entry in state db
        is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                                  f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' "
                                  f"'{STATE_DB_BGP_SESSIONS_UP_KEY}'")
        pytest_assert(is_bgp_up['stdout'].strip() == "no" if i == len(target_bgp_neighbors) - 1 else "yes")
        # Check interfaces are shutdown entry in state db
        is_shutdown = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                                    f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' "
                                    f"'{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")
        pytest_assert(is_shutdown['stdout'].strip() == "yes" if i == len(target_bgp_neighbors) - 1 else "no")

    # Test portchannel startup
    duthost.shell(f"config bgp startup neighbor {target_bgp_neighbors[0]}")

    # Wait for the BGP session to establish before checking portchannel
    neighbors_to_check = [target_bgp_neighbors[0]]
    pytest_assert(wait_until(20, 0.1, 0, duthost.check_bgp_session_state, neighbors_to_check),
                  f"BGP session {target_bgp_neighbors[0]} did not establish")

    # Check PortChannel admin and oper status are up
    poll_portchannel_status(duthost, portchannels, expected_admin='up', expected_oper='up')

    # Check portchannels startup after at least 1 neighbor starts up
    # Check bgp sessions are up in state db
    is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                              f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' "
                              f"'{STATE_DB_BGP_SESSIONS_UP_KEY}'")
    pytest_assert(is_bgp_up['stdout'].strip() == "yes")
    # Check interfaces are not shutdown in state db
    is_shutdown = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                                f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' "
                                f"'{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")
    pytest_assert(is_shutdown['stdout'].strip() == "no")


def validate_bgp_session_tracking_disabled(duthost, portchannels, target_bgp_neighbors):
    """
    Test behavior without bgp session tracking script.
    - Test southbound portchannels are up even when all northbound target bgp sessions are down

    Args:
        duthost: DUT host
        target_bgp_neighbors: list of target bgp neighbor ips
    """
    logger.debug("Running bgp session tracking disabled test.")

    # Make sure bgp sessions and portchannels start with admin up
    reset_bgp_and_portchannels_state(duthost, portchannels, target_bgp_neighbors)

    # Check bgp session tracker is disabled in state db
    is_enabled = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                               f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_SCRIPT_ENABLED_KEY}'")
    pytest_assert(is_enabled['stdout'].strip() == "no")

    # Get initial state db values
    initial_is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                                      f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' "
                                      f"'{STATE_DB_BGP_SESSIONS_UP_KEY}'")['stdout'].strip()
    initial_is_shutdown = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                                        f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' "
                                        f"'{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")['stdout'].strip()

    # Test bgp shutdown, portchannels should remain up
    for neighbor in target_bgp_neighbors:
        duthost.shell(f"config bgp shutdown neighbor {neighbor}")

    neighbors_to_check = target_bgp_neighbors
    pytest_assert(wait_until(20, 0.1, 0, duthost.check_bgp_session_state, neighbors_to_check, 'idle'),
                  "Not all BGP sessions went down")

    # Check PortChannel admin and oper status are up
    poll_portchannel_status(duthost, portchannels, expected_admin='up', expected_oper='up')

    # Check bgp sessions remain up in state db
    is_bgp_up = duthost.shell(f"sonic-db-cli STATE_DB HGET "
                              f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_BGP_SESSIONS_UP_KEY}'")
    pytest_assert(is_bgp_up['stdout'].strip() == initial_is_bgp_up)
    # Check interfaces are not shutdown in state db
    is_shutdown = duthost.shell("sonic-db-cli STATE_DB HGET "
                                f"'{STATE_DB_TABLE_NAME}|{STATE_DB_INSTANCE_NAME}' '{STATE_DB_INTERFACE_SHUTDOWN_KEY}'")
    pytest_assert(is_shutdown['stdout'].strip() == initial_is_shutdown)


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


def reset_bgp_and_portchannels_state(duthost, portchannels, target_bgp_neighbors):
    """
    Set target bgp neighbors and portchannels to admin up.

    Args:
        duthost: DUT host
        target_bgp_neighbors: list of target bgp neighbor ips
    """
    for neighbor in target_bgp_neighbors:
        duthost.shell(f"config bgp startup neighbor {neighbor}")
    for portchannel in portchannels:
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


@pytest.fixture(params=["", GPU_RESOURCE_TYPE], ids=["oracle", "gpu"], scope="module")
def resource_type(request):
    resource = request.param
    scenario = "GPU" if resource == GPU_RESOURCE_TYPE else "Oracle"
    logger.info(f"Running BGP session tracker test for {scenario} scenario (resource_type='{resource}')")
    return resource


@pytest.fixture(scope="module")
def southbound_portchannels(resource_type):
    return GPU_PORTCHANNELS if resource_type == GPU_RESOURCE_TYPE else PORT_CHANNEL_NAMES


@pytest.fixture(scope="module")
def common_setup_and_teardown(request, tbinfo, duthosts,
                              rand_one_dut_hostname, ptfhost, localhost,
                              resource_type, southbound_portchannels):
    """
    Setup and cleanup entry for tests.

    Args:
        request: pytest request object
        tbinfo: testbed info
        duthosts: DUT hosts
        rand_one_dut_hostname: DUT host name
        ptfhost: PTF host
    """
    duthost = duthosts[rand_one_dut_hostname]
    bond_port_mapping = {}

    def teardown_cleanup():
        cleanup(duthost, ptfhost, bond_port_mapping)

    # Register the cleanup to run regardless of setup failures
    request.addfinalizer(teardown_cleanup)

    # backup config_db.json for cleanup
    duthost.shell(f"cp {CONFIG_DB_PATH} {CONFIG_DB_PATH}.bak")

    # update device metadata in config_db.json
    enable_session_monitor_container(duthost, resource_type)
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
    vlan_id, ports = get_available_vlan_id_and_ports(config_facts, len(southbound_portchannels))
    pytest_assert(len(ports) == len(southbound_portchannels),
                  f"Found {len(ports)} available ports. Needed {len(southbound_portchannels)} ports for the test.")
    cmds = []
    bond_port_mapping = {}
    for i in range(len(southbound_portchannels)):
        try:
            # Create portchannel with the right names on dut
            duthost.shell(f'config vlan member del {vlan_id} {ports[i]}')
            duthost.shell(f'config portchannel add {southbound_portchannels[i]}')
            duthost.shell(f"config portchannel member add {southbound_portchannels[i]} {ports[i]}")

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

    target_bgp_name = 'T2' if resource_type == GPU_RESOURCE_TYPE else 'T1'

    # Find all target bgp sessions.
    target_bgp_neighbors = []
    for neighbor, value in bgp_neighbors.items():
        if ':' not in neighbor and target_bgp_name in value['name']:
            target_bgp_neighbors.append(neighbor)
    pytest_assert(len(target_bgp_neighbors) > 0,
                  f"There are no {target_bgp_name} bgp sessions configured for this test.")

    yield duthost, southbound_portchannels, target_bgp_neighbors


def test_bgp_session_tracker(common_setup_and_teardown):
    """
    Entry for running tests.
    """
    duthost, southbound_portchannels, target_bgp_neighbors = common_setup_and_teardown

    # Run tests
    # Test script works when enabled. Should be enabled by default.
    validate_bgp_session_tracking_enabled(duthost, southbound_portchannels, target_bgp_neighbors)

    # Disable bgp session tracker
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl stop {SERVICE_NAME}")
    time.sleep(10)

    # Test script doesn't do anything when disabled
    validate_bgp_session_tracking_disabled(duthost, southbound_portchannels, target_bgp_neighbors)

    # Enable bgp session tracker
    duthost.shell(f"docker exec {DOCKER_CONTAINER_NAME} supervisorctl start {SERVICE_NAME}")
    time.sleep(10)

    # Test script works when re-enabled
    validate_bgp_session_tracking_enabled(duthost, southbound_portchannels, target_bgp_neighbors)
