"""
A helper module for PTF tests.
"""

import pytest
import random
import os
import logging

from ipaddress import ip_address, IPv4Address
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


# ============================================================================
# Helper Functions for PTF Port Mapping and Interface Selection
# ============================================================================

def get_dut_to_ptf_port_mapping(duthost, tbinfo):
    """
    Get mapping of DUT interfaces/PortChannels to PTF ports.
    Only includes interfaces or PortChannels that have IP addresses configured.

    Args:
        duthost: DUT host object
        tbinfo: Testbed info

    Returns:
        dict: {interface_name: ptf_index} for interfaces with IP
              {portchannel_name: -1} for PortChannels with IP
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    all_indices = mg_facts.get('minigraph_ptf_indices', {})
    mapping = {}

    # Add interfaces with IP addresses
    for intf in mg_facts.get('minigraph_interfaces', []):
        interface_name = intf.get('attachto')
        if interface_name and intf.get('addr'):
            ptf_index = all_indices.get(interface_name)
            if ptf_index is not None:
                mapping[interface_name] = ptf_index

    # Add PortChannels with IP addresses (PTF index = -1)
    for intf in mg_facts.get('minigraph_portchannel_interfaces', []):
        portchannel_name = intf.get('attachto')
        if portchannel_name and intf.get('addr'):
            mapping[portchannel_name] = -1

    return mapping


def get_interface_ip_address(interface_name, mg_facts):
    """
    Get IP address for an interface from minigraph facts.

    Args:
        interface_name: Interface or PortChannel name
        mg_facts: Minigraph facts dictionary

    Returns:
        str: IP address or None if not found
    """
    # Check in minigraph_interfaces
    for intf in mg_facts.get('minigraph_interfaces', []):
        if intf.get('attachto') == interface_name and intf.get('addr'):
            return str(intf['addr'])

    # Check in minigraph_portchannel_interfaces
    for intf in mg_facts.get('minigraph_portchannel_interfaces', []):
        if intf.get('attachto') == interface_name and intf.get('addr'):
            return str(intf['addr'])

    return None


def select_test_interface_and_ptf_port(duthost, tbinfo):
    """
    Select a random test interface/PortChannel and its corresponding PTF port.

    Args:
        duthost: DUT host object
        tbinfo: Testbed info

    Returns:
        tuple: (interface_name, ptf_index) for interfaces
               (portchannel_name, -1) for PortChannels
               (None, None) if not found
    """
    dut_to_ptf_mapping = get_dut_to_ptf_port_mapping(duthost, tbinfo)
    if not dut_to_ptf_mapping:
        return None, None

    interface_name = random.choice(list(dut_to_ptf_mapping.keys()))
    ptf_port_index = dut_to_ptf_mapping[interface_name]

    logger.info("Selected: {} (PTF port: {})".format(interface_name, ptf_port_index))
    return interface_name, ptf_port_index


def detect_portchannel_egress_member(duthost, tbinfo, ptf_adapter, portchannel_name, test_packet):
    """
    Detect which PortChannel member interface is actually used for egress traffic.

    Args:
        duthost: DUT host object
        tbinfo: Testbed info
        ptf_adapter: PTF adapter object
        portchannel_name: PortChannel name
        test_packet: Test packet to send

    Returns:
        tuple: (member_interface, ptf_port) or (None, None)
    """
    import ptf.testutils as testutils

    logger.info("Detecting egress member for {}".format(portchannel_name))

    # Get PortChannel members
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    portchannels = mg_facts.get('minigraph_portchannels', {})

    if portchannel_name not in portchannels:
        return None, None

    members = portchannels[portchannel_name].get('members', [])
    if not members:
        return None, None

    # Get PTF ports for members
    ptf_indices = mg_facts.get('minigraph_ptf_indices', {})
    member_ptf_ports = [(m, ptf_indices[m]) for m in members if m in ptf_indices]

    if not member_ptf_ports:
        return None, None

    # Try each member port
    num_test_packets = 100
    timeout = 10.0

    for member_name, member_ptf_port in member_ptf_ports:
        logger.info("Trying {} (PTF port {})".format(member_name, member_ptf_port))
        ptf_adapter.dataplane.flush()

        # Send test packets
        for i in range(num_test_packets):
            testutils.send_packet(ptf_adapter, member_ptf_port, test_packet)

        # Check if packets received
        packets_received = 0

        def check_packets_received():
            nonlocal packets_received
            while True:
                result = testutils.dp_poll(ptf_adapter, device_number=0, timeout=0.1)
                if isinstance(result, ptf_adapter.dataplane.PollSuccess):
                    if result.port == member_ptf_port:
                        packets_received += 1
                else:
                    break
            return packets_received >= num_test_packets

        if wait_until(timeout=timeout, interval=1, delay=1, condition=check_packets_received):
            logger.info("Found egress member: {} (PTF port {})".format(member_name, member_ptf_port))
            ptf_adapter.dataplane.flush()
            return member_name, member_ptf_port

    # No working member found
    ptf_adapter.dataplane.flush()
    return None, None


@pytest.fixture(scope="module")
def downstream_links(rand_selected_dut, tbinfo, nbrhosts):
    """
    Returns a dictionary of all the links that are downstream from the DUT.

    Args:
        rand_selected_dut: DUT fixture
        tbinfo: testbed information fixture
        nbrhosts: neighbor host fixture
    Returns:
        links: Dictionary of links downstream from the DUT
    """
    links = dict()
    duthost = rand_selected_dut

    def filter(interface, neighbor, mg_facts, tbinfo):
        port = mg_facts["minigraph_neighbors"][interface]["port"]
        ptf_port_id = mg_facts["minigraph_ptf_indices"][interface]
        if tbinfo["topo"]["type"] == "t1" and "T0" in neighbor["name"]:
            # Search for BGP neighbor information
            local_ipv4_addr = None
            peer_ipv4_addr = None
            for item in mg_facts["minigraph_bgp"]:
                if item["name"] == neighbor["name"]:
                    if isinstance(ip_address(item["addr"]), IPv4Address):
                        # The address of neighbor device
                        local_ipv4_addr = item["addr"]
                        # The address of DUT
                        peer_ipv4_addr = item["peer_addr"]
                        break
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": ptf_port_id,
                "local_ipv4_addr": local_ipv4_addr,
                "peer_ipv4_addr": peer_ipv4_addr,
                "downstream_port": port,
                "host": nbrhosts[neighbor["name"]]["host"]
            }
        elif tbinfo["topo"]["type"] == "t0" and "Server" in neighbor["name"]:
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": ptf_port_id,
                "downstream_port": port
            }

    find_links(duthost, tbinfo, filter)
    return links


@pytest.fixture(scope="module")
def upstream_links(rand_selected_dut, tbinfo, nbrhosts):
    """
    Returns a dictionary of all the links that are upstream from the DUT.

    Args:
        rand_selected_dut: DUT fixture
        tbinfo: testbed information fixture
        nbrhosts: neighbor host fixture
    Returns:
        links: Dictionary of links upstream from the DUT
    """
    links = dict()
    duthost = rand_selected_dut

    def filter(interface, neighbor, mg_facts, tbinfo):
        if ((tbinfo["topo"]["type"] == "t0" and ("T1" in neighbor["name"] or "PT0" in neighbor["name"]))
                or (tbinfo["topo"]["type"] == "t1" and "T2" in neighbor["name"])):
            local_ipv4_addr = None
            peer_ipv4_addr = None
            for item in mg_facts["minigraph_bgp"]:
                if item["name"] == neighbor["name"]:
                    if isinstance(ip_address(item["addr"]), IPv4Address):
                        # The address of neighbor device
                        local_ipv4_addr = item["addr"]
                        # The address of DUT
                        peer_ipv4_addr = item["peer_addr"]
                        break
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "local_ipv4_addr": local_ipv4_addr,
                "peer_ipv4_addr": peer_ipv4_addr,
                "upstream_port": port,
                "host": nbrhosts[neighbor["name"]]["host"]
            }

    find_links(duthost, tbinfo, filter)
    return links


@pytest.fixture(scope="module")
def peer_links(rand_selected_dut, tbinfo, nbrhosts):
    """
    Returns a dictionary of all the links that are service ports from the DUT.

    Args:
        rand_selected_dut: DUT fixture
        tbinfo: testbed information fixture
        nbrhosts: neighbor host fixture
    Returns:
        links: Dictionary of service links from the DUT
    """
    links = dict()
    duthost = rand_selected_dut

    def filter(interface, neighbor, mg_facts, tbinfo):
        if "PT0" in neighbor["name"]:
            local_ipv4_addr = None
            peer_ipv4_addr = None
            for item in mg_facts["minigraph_bgp"]:
                if item["name"] == neighbor["name"]:
                    if isinstance(ip_address(item["addr"]), IPv4Address):
                        # The address of neighbor device
                        local_ipv4_addr = item["addr"]
                        # The address of DUT
                        peer_ipv4_addr = item["peer_addr"]
                        break
            port = mg_facts["minigraph_neighbors"][interface]["port"]
            links[interface] = {
                "name": neighbor["name"],
                "ptf_port_id": mg_facts["minigraph_ptf_indices"][interface],
                "local_ipv4_addr": local_ipv4_addr,
                "peer_ipv4_addr": peer_ipv4_addr,
                "service_port": port,
                "host": nbrhosts[neighbor["name"]]["host"]
            }

    find_links(duthost, tbinfo, filter)
    return links


def apply_dscp_cfg_setup(duthost, dscp_mode, loganalyzer):
    """
    Applies the DSCP decap configuration to the DUT.

    Args:
        duthost: DUT fixture
        dscp_mode: DSCP mode to apply
    """

    default_decap_mode = duthost.shell("redis-cli -n 0 hget 'TUNNEL_DECAP_TABLE:IPINIP_TUNNEL' 'dscp_mode'")["stdout"]
    logger.info("Current DSCP decap mode: {}".format(default_decap_mode))

    if default_decap_mode == dscp_mode:
        logger.info("Current DSCP decap mode: {} matches required decap mode - no reload required"
                    .format(default_decap_mode))
        return

    for asic_id in duthost.get_frontend_asic_ids():
        swss = "swss{}".format(asic_id if asic_id is not None else '')
        logger.info("DSCP decap mode required to be changed to {} on asic {}".format(dscp_mode, asic_id))
        cmds = ["docker exec {} cp /usr/share/sonic/templates/ipinip.json.j2 ".format(swss) +
                "/usr/share/sonic/templates/ipinip.json.j2.tmp",
                "docker exec {} sed -i 's/\"dscp_mode\":\"{}\"/\"dscp_mode\":\"{}\"/g\' ".
                format(swss, default_decap_mode, dscp_mode) + "/usr/share/sonic/templates/ipinip.json.j2"]
        # sed -i 's/"dscp_mode":"uniform"/"dscp_mode":"pipe"/g' ipinip.json.j2 - this is the command to change
        duthost.shell_cmds(cmds=cmds)
        logger.info("DSCP decap mode changed from {} to {} on asic {}".format(default_decap_mode, dscp_mode, asic_id))

    logger.info("SETUP: Reload required for dscp decap mode changes to take effect.")
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True,
                  ignore_loganalyzer=loganalyzer)


def apply_dscp_cfg_teardown(duthost, loganalyzer):
    """
    Removes the previously applied DSCP decap configuration from the DUT.

    Args:
        duthost: DUT fixture
    """
    reload_required = False
    for asic_id in duthost.get_frontend_asic_ids():
        swss = 'swss{}'.format(asic_id if asic_id is not None else '')
        try:
            file_out = duthost.shell("docker exec {} ls /usr/share/sonic/templates/ipinip.json.j2.tmp".format(swss))
        except Exception:
            continue
        if file_out["rc"] == 0:
            cmd1 = "docker exec {} cp /usr/share/sonic/templates/ipinip.json.j2.tmp ".format(swss) + \
                "/usr/share/sonic/templates/ipinip.json.j2"
            reload_required = True
            logger.info("DSCP decap mode required to be changed to default on asic {}".format(asic_id))
            duthost.shell(cmd1)

    if reload_required:
        logger.info("TEARDOWN: Reload required for dscp decap mode changes to take effect.")
        config_reload(duthost, safe_reload=True, ignore_loganalyzer=loganalyzer)


def find_links(duthost, tbinfo, filter):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for interface, neighbor in list(mg_facts["minigraph_neighbors"].items()):
        filter(interface, neighbor, mg_facts, tbinfo)


def select_random_link(links):
    """
    Selects a random link from the links dictionary.

    Args:
        links: Dictionary of links
    Returns:
        link: Random link
    """
    if not links:
        return None
    link = random.choice(list(links.values()))
    return link


def get_stream_ptf_ports(stream_links):
    """
    Returns a list of upstream/downstream PTF ports.

    Args:
        stream_links: Dictionary of upstream/downstream links
    Returns:
        ports: List of upstream PTF ports
    """
    ports = []
    for link in list(stream_links.values()):
        if "ptf_port_id" in link:
            ports.append(link.get("ptf_port_id"))
    return ports


def get_dut_pair_port_from_ptf_port(duthost, tbinfo, ptf_port_id):
    """
    Given a ptf port ID, find the corresponding port name on the DUT ex. Ethernet0
    """
    ext_minig_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for dut_port, ptf_port in ext_minig_facts['minigraph_ptf_indices'].items():
        if ptf_port == int(ptf_port_id):
            return dut_port

    return None


def fetch_test_logs_ptf(ptfhost, ptf_location, dest_dir):
    """
    Fetch test logs from ptfhost after individual test run
    """
    log_dir = ptf_location
    curr_dir = os.getcwd()
    logFiles = {'src': log_dir, 'dest': curr_dir + dest_dir, 'flat': True, 'fail_on_missing': False}
    ptfhost.fetch(**logFiles)

    return logFiles['dest']
