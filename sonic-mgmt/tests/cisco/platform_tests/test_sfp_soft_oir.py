"""
Cisco specific sfp soft OIR tests
"""
import time
import logging
import pytest
import random
from tests.platform_tests.sfp.util import get_dev_conn
from tests.platform_tests.conftest import xcvr_skip_list
from tests.cisco.common.utils import skip_if_sim_for_frontend_hostname


# Base command for SFP OIR operations
BASE_CMD_SFP_OIR = "sudo /opt/cisco/bin/sfp-OIR.py"

# Commands with placeholders for action and port
CMD_SFP_REMOVAL = "{} out -p {{phy_port}}".format(BASE_CMD_SFP_OIR)
CMD_SFP_INSERTION = "{} in -p {{phy_port}}".format(BASE_CMD_SFP_OIR)
CMD_SFP_OIR = "{} out-in -p {{phy_port}}".format(BASE_CMD_SFP_OIR)

SFP_PRESENT = "Present"
SFP_NOT_PRESENT = "Not present"

CMD_SFP_PRESENCE = "show interface trans presence"
WAIT_TIME_AFTER_SFP_REMOVAL = 10
WAIT_TIME_AFTER_SFP_INSERTION = 10
EXTRA_WAIT_TIME_AFTER_EACH_ROUND = 20

# Number of ports to test per asic, 0 for all available ports
NUM_OF_PORTS_TO_TEST = 1

# TODO: To change to all topology once sfp-OIR.py is supported on all platforms
pytestmark = [
    pytest.mark.topology('t2')
]

def get_sfp_presence(duthost, portname_to_phy_port):
    """
    @summary: Get SFP presence status
    @param duthost: DUT host object
    @param portname_to_phy_port: Port mapping from port name to physical port number
    @return: Returns result in a dictionary, where key is physical port number and
    value is presence status, True for present, False for not present
    """
    sfp_presence = duthost.command(CMD_SFP_PRESENCE)
    return parse_sfp_presence(sfp_presence, portname_to_phy_port)

def parse_sfp_presence(output_lines, portname_to_phy_port):
    """
    @summary: Parse the SFP presence information from command output
    @param output_lines: Command output lines
    @param portname_to_phy_port: Port mapping from port name to physical port number
    @return: Returns result in a dictionary, where key is physical port number and
    value is presence status, True for present, False for not present

    Example output of CMD_SFP_PRESENCE:
    Port        Presence
    ----        --------
    Ethernet0   Present
    Ethernet4   Not present
    """
    output_lines = output_lines["stdout_lines"][2:]
    res = {}
    for line in output_lines:
        fields = line.split()
        if not (2 <= len(fields) <= 3):
            continue
        intf = fields[0]
        if intf not in portname_to_phy_port:
            continue
        phy_port = portname_to_phy_port[intf]
        res[phy_port] = " ".join(fields[1:]) == SFP_PRESENT
    return res

def check_interface_status_for_ports(duthost, interfaces, expected_status_up):
    """
    @summary: Check interface status for a list of interfaces
    @param duthost: DUT host object
    @param interfaces: List of logical interfaces to check
    @param expected_status_up: True for expecting status up, False for expecting status down
    """
    # Check interface status
    intf_facts = duthost.interface_facts(up_ports=interfaces)["ansible_facts"]
    down_ports = intf_facts["ansible_interface_link_down_ports"]
    if expected_status_up:
        assert len(down_ports) == 0, "Some interfaces are down: {}".format(down_ports)
    else:
        assert len(down_ports) == len(interfaces), \
            "Not all interfaces are down: {}".format(down_ports)

def get_bidirectional_port_maps_per_asic(duthost, conn_graph_facts, enum_frontend_asic_index):
    portmap, dev_conn = get_dev_conn(duthost, conn_graph_facts, enum_frontend_asic_index)
    portname_to_phy_port = {intf: portmap[intf][0] for intf in dev_conn}
    phy_port_to_portname = {}
    for intf in dev_conn:
        phy_port = portmap[intf][0]
        if phy_port not in phy_port_to_portname:
            phy_port_to_portname[phy_port] = []
        phy_port_to_portname[phy_port].append(intf)
    return portname_to_phy_port, phy_port_to_portname

def get_phy_ports_to_test(duthost, portname_to_phy_port, phy_port_to_portname, xcvr_skip_list):
    """
    @summary: Get a few physical ports to test
    @return: Returns a dictionary, where key is physical port number and
    value is a list of port names per physical port
    """
    phy_ports_to_test = {}
    # Ignore the ports in xcvr_skip_list
    phy_ports_interested = set(
        phy_port for intf, phy_port in portname_to_phy_port.items()
        if intf not in xcvr_skip_list[duthost.hostname]
    )
    
    logging.info("Check sfp presence to determine which ports to test")
    sfp_presence = get_sfp_presence(duthost, portname_to_phy_port)
    phy_ports_with_sfp = set(phy_port for phy_port, is_present in sfp_presence.items() if is_present)
    phy_ports_with_sfp = phy_ports_interested & phy_ports_with_sfp
    num_of_ports_to_test = len(phy_ports_with_sfp) if NUM_OF_PORTS_TO_TEST == 0 else NUM_OF_PORTS_TO_TEST
    if num_of_ports_to_test > len(phy_ports_with_sfp):
        logging.info("Not enough SFPs to test (need={}, available={}), skipping the test, available SFPs: {}".format(
            num_of_ports_to_test,
            len(phy_ports_with_sfp),
            phy_ports_with_sfp))
        return phy_ports_to_test
    # Randomly select a few ports to test
    phy_ports_to_test = {
        phy_port: phy_port_to_portname[phy_port]
        for phy_port in sorted(random.sample(phy_ports_with_sfp, num_of_ports_to_test))
    }
    logging.info("Selected {} physical ports to test: {}".format(
        num_of_ports_to_test, phy_ports_to_test))
    return phy_ports_to_test

def run_sfp_soft_oir_test(duthost, portname_to_phy_port, phy_ports_to_test, is_sfp_removal):
    """
    @summary: Run SFP removal or insertion test
    @param duthost: DUT host object
    @param portname_to_phy_port: Port mapping from port name to physical port number
    @param phy_ports_to_test: Dict of physical ports to test
    @param is_sfp_removal: True for SFP removal, False for SFP insertion
    """
    operation_str = "removal" if is_sfp_removal else "insertion"
    sfp_cmd = CMD_SFP_REMOVAL if is_sfp_removal else CMD_SFP_INSERTION
    wait_time_after_operation = (WAIT_TIME_AFTER_SFP_REMOVAL 
                                 if is_sfp_removal 
                                 else WAIT_TIME_AFTER_SFP_INSERTION)
    expected_present = False if is_sfp_removal else True
    expected_status_up = False if is_sfp_removal else True
    expected_status_up_for_pre_check = not expected_status_up
    interfaces_to_check = [intf for port_list in phy_ports_to_test.values() for intf in port_list]

    logging.info("Check interface status before SFP {} for {}".format(operation_str, interfaces_to_check))
    check_interface_status_for_ports(duthost, interfaces_to_check, expected_status_up_for_pre_check)

    for phy_port in phy_ports_to_test:
        logging.info("doing SFP soft {} on physical port {}".format(operation_str, phy_port))
        sfp_cmd_full = sfp_cmd.format(phy_port=phy_port)
        result = duthost.command(sfp_cmd_full)
        assert result["rc"] == 0, "'{}' failed".format(sfp_cmd_full)
        logging.info("Wait {} secs after SFP {} for physical port {}".format(
            wait_time_after_operation, operation_str, phy_port))
        time.sleep(wait_time_after_operation)

    logging.info("Wait extra {} secs after SFP {} for all ports on this asic".format(
        EXTRA_WAIT_TIME_AFTER_EACH_ROUND, operation_str))
    time.sleep(EXTRA_WAIT_TIME_AFTER_EACH_ROUND)

    logging.info("Check sfp presence after {}".format(operation_str))
    sfp_presence = get_sfp_presence(duthost, portname_to_phy_port)

    for phy_port in phy_ports_to_test:
        assert phy_port in sfp_presence, "Physical port {} is not in output of '{}'".format(
            phy_port, CMD_SFP_PRESENCE)
        assert sfp_presence[phy_port] == expected_present, "Physical port {} presence is not '{}'".format(
            phy_port, expected_present)

    logging.info("Check interface status after SFP {} for {}".format(operation_str, interfaces_to_check))
    check_interface_status_for_ports(duthost, interfaces_to_check, expected_status_up)

def test_sfp_soft_oir(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                     enum_frontend_asic_index, conn_graph_facts,
                     tbinfo, xcvr_skip_list, skip_if_sim_for_frontend_hostname):
    """
    @summary: Test SFP removal and insertion
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    global ans_host
    ans_host = duthost
    portname_to_phy_port, phy_port_to_portname = get_bidirectional_port_maps_per_asic(
        duthost, conn_graph_facts, enum_frontend_asic_index)

    phy_ports_to_test = get_phy_ports_to_test(
        duthost, portname_to_phy_port, phy_port_to_portname, xcvr_skip_list
    )
    if not phy_ports_to_test:
        return

    # SFP removal
    run_sfp_soft_oir_test(duthost, portname_to_phy_port, phy_ports_to_test, True)

    # SFP insertion
    run_sfp_soft_oir_test(duthost, portname_to_phy_port, phy_ports_to_test, False)
