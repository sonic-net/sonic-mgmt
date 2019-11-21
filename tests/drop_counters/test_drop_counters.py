import pytest
import ptf.testutils as testutils
import logging
import pprint
import random
import time
import scapy
import yaml
import re
import os
import json

pytestmark = [
    pytest.mark.disable_loganalyzer  # disable automatic loganalyzer
]

logger = logging.getLogger(__name__)

IP_DST = "10.0.0.59"
IP_SRC = "1.1.1.1"
TCP_SPORT = 1234
TCP_DPORT = 4321
PKT_NUMBER = 1000

# Discard key from 'portstat -j' CLI command output
L2_DISCARD_KEY = "RX_DRP"
L3_DISCARD_KEY = "RX_ERR"
# CLI commands to obtain drop counters
GET_L2_COUNTERS = "portstat -j"
GET_L3_COUNTERS = "intfstat -j"


@pytest.fixture(scope="module")
def setup(duthost, testbed):
    """
    Setup fixture for collecting PortChannel, VLAN and RIF port members.
    @return: Dictionary with keys:
        port_channel_members, vlan_members, rif_members, dut_to_ptf_port_map, combined_drop_counter
        Note: if 'combined_drop_counter' is True, platform has common counter for L2 and L3 discards.
              To get this counter - call 'show interfaces counters' CLI comamnd and check 'RX_DRP' column for
              specified port.
    """
    port_channel_members = {}
    vlan_members = {}
    rif_members = []
    combined_drop_counter = False

    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    for port_channel, interfaces in mg_facts['minigraph_portchannels'].items():
        for iface in interfaces["members"]:
            port_channel_members[iface] = port_channel

    for vlan_id in mg_facts["minigraph_vlans"]:
        for iface in mg_facts["minigraph_vlans"][vlan_id]["members"]:
            vlan_members[iface] = vlan_id

    rif_members = {item["attachto"]: item["attachto"] for item in mg_facts["minigraph_interfaces"]}

    # Get info whether L2 and L3 drop counters are linked
    base_dir = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(base_dir, "combined_drop_counters.yml")) as stream:
        regexps = yaml.safe_load(stream)
        if regexps:
            for item in regexps:
                if re.match(item, duthost.facts["platform"]):
                    combined_drop_counter = True
                    break

    setup_information = {
        "port_channel_members": port_channel_members,
        "vlan_members": vlan_members,
        "rif_members": rif_members,
        "dut_to_ptf_port_map": mg_facts["minigraph_port_indices"],
        "combined_drop_counter": combined_drop_counter
    }

    return setup_information


@pytest.fixture(params=["port_channel_members", "vlan_members", "rif_members"])
def tx_dut_ports(request, setup):
    """ Fixture for getting port members of specific port group """
    return setup[request.param] if setup[request.param] else pytest.skip("No {} available".format(request.param))


@pytest.fixture(autouse=True, scope="module")
def enable_counters(duthost):
    """ Fixture which enables RIF and L2 counters """
    cmd_list = ["intfstat -D", "counterpoll port enable", "counterpoll rif enable", "sonic-clear counters",
                "sonic-clear rifcounters"]
    for cmd in cmd_list:
        duthost.command(cmd)


def get_pkt_drops(duthost, cli_cmd):
    """
    @summary: Parse output of "portstat" or "intfstat" commands and convert it to the dictionary.
    @param module: The AnsibleModule object
    @param cli_cmd: one of supported CLI commands - "portstat -j" or "intfstat -j"
    @return: Return dictionary of parsed counters
    """
    stdout = duthost.command(cli_cmd)
    if stdout["rc"] != 0:
        raise Exception(stdout["stdout"] + stdout["stderr"])
    stdout = stdout["stdout"]

    match = re.search("Last cached time was.*\n", stdout)
    if match:
        stdout = re.sub("Last cached time was.*\n", "", stdout)

    try:
        return json.loads(stdout)
    except Exception as err:
        raise Exception("Failed to parse output of '{}', err={}".format(cli_cmd, str(err)))


def get_dut_iface_mac(duthost, iface_name):
    """ Fixture for getting MAC address of specified interface """
    for iface, iface_info in duthost.setup()['ansible_facts'].items():
        if iface_name in iface:
            return iface_info["macaddress"]


def get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports):
    """
    Return:
        dut_iface - DUT interface name expected to receive packtes from PTF
        ptf_tx_port_id - Port ID used by PTF for sending packets from expected PTF interface
        dst_mac - DUT interface destination MAC address
        src_mac - PTF interface source MAC address
    """
    dut_iface = random.choice(tx_dut_ports.keys())
    ptf_tx_port_id = setup["dut_to_ptf_port_map"][dut_iface]
    dst_mac = get_dut_iface_mac(duthost, dut_iface)
    src_mac = ptfadapter.dataplane.ports[(0, ptf_tx_port_id)].mac()
    return dut_iface, ptf_tx_port_id, dst_mac, src_mac


def is_arp_req(pkt, dst_ip):
    """ Check whether packet is ARP request """
    arp_request = 1
    scapy_pkt = scapy.layers.l2.Ether(pkt)

    if scapy_pkt.haslayer(scapy.layers.l2.ARP):
        if scapy_pkt[scapy.layers.l2.ARP].op == arp_request:
            if scapy_pkt[scapy.layers.l2.ARP].pdst == dst_ip:
                return True
    return False


def match_packet_fields(pkt, eth_dst=None, eth_src=None, eth_type=None, ip_dst=None, ip_src=None, tcp_sport=None,
                        tcp_dport=None):
    """
    Verify whether packet fields matches specified fields. Return True for match of all fields, false vise versa

    @param eth_dst - String representation of Ethernet destination MAC address. Template example - "xx:xx:xx:xx:xx:xx"
    @param eth_src - String representation of Ethernet source MAC address. Template example - "xx:xx:xx:xx:xx:xx"
    @param eth_type - Hex representation of Ethernet type. Example - '0x800'
    @param ip_dst - String representation of IP destenation address. Template example - "xxx.xxx.xxx.xxx"
    @param ip_src - String representation of IP source address. Template example - "xxx.xxx.xxx.xxx"
    @param tcp_sport - TCP source port (int)
    @param tcp_dport - TCP destination port (int)
    """
    scapy_pkt = scapy.layers.l2.Ether(pkt)
    match_list = []

    # Check Ethernet layer fields
    if scapy_pkt.haslayer(scapy.layers.l2.Ether):
        if eth_dst and scapy_pkt[scapy.layers.l2.Ether].dst != eth_dst:
            match_list.append(False)
        if eth_src and scapy_pkt[scapy.layers.l2.Ether].src != eth_src:
            match_list.append(False)
        if eth_type and scapy_pkt[scapy.layers.l2.Ether].type != eth_type:
            match_list.append(False)
    # Check IP layer fields
    if scapy_pkt.haslayer(scapy.layers.inet.IP):
        if ip_dst and scapy_pkt[scapy.layers.inet.IP].dst != ip_dst:
            match_list.append(False)
        if ip_src and scapy_pkt[scapy.layers.inet.IP].src != ip_src:
            match_list.append(False)
    # Check TCP layer fields
    if scapy_pkt.haslayer(scapy.layers.inet.TCP):
        if tcp_sport and scapy_pkt[scapy.layers.inet.TCP].sport != tcp_sport:
            match_list.append(False)
        if tcp_dport and scapy_pkt[scapy.layers.inet.TCP].dport != tcp_dport:
            match_list.append(False)

    if match_list:
        if all(match_list):
            return True
    return False


def verify_no_packet_egressed(ptfadapter, eth_dst=None, eth_src=None, ip_dst=None, ip_src=None, eth_type=None, tcp_sport=None,
                                tcp_dport=None):
    """ Checks whether packet with specified fields was egressed from DUT """
    pkts = {}
    arp_observed = False
    msg = ""

    for port, pkt, timestamp in ptfadapter.dataplane.packets(0):
        if match_packet_fields(pkt=pkt, eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_src=ip_src, eth_type=eth_type,
                                tcp_sport=tcp_sport, tcp_dport=tcp_dport):
            if port not in pkts:
                pkts[port] = {"count": 0, "pkt": pkt} # Add packet in readable format
            pkts[port]["count"] += 1
        if is_arp_req(pkt=pkt, dst_ip=ip_dst):
            arp_observed = True

    if pkts:
        msg_template = "Port - {}; Captured packets - {}; Packet - {}\n" # Write dict info here
        for port, value in pkts.items():
            scapy_pkt = scapy.layers.l2.Ether(value["pkt"])
            msg += msg_template.format(port, value["count"], scapy_pkt.sprintf("eth_dst=%dst% eth_src=%src% ip_dst=%IP.dst% ip_src=%IP.src%"))

    if arp_observed:
        msg += "\nFound ARP request for packet which must be dropped with DST IP == {}\n".format(ip_dst)

    if msg:
        pytest.fail("Found packets which must be dropped by DUT:\n{}".format(msg))


def log_pkt_params(dut_iface, mac_dst, mac_src, ip_dst, ip_src):
    """ Displays information about packet fields used in test case: mac_dst, mac_src, ip_dst, ip_src """
    logger.info("Selected TX interface on DUT - {}".format(dut_iface))
    logger.info("Packet DST MAC - {}".format(mac_dst))
    logger.info("Packet SRC MAC - {}".format(mac_src))
    logger.info("Packet IP DST - {}".format(ip_dst))
    logger.info("Packet IP SRC - {}".format(ip_src))


def base_verification(discard_group, pkt, ptfadapter, duthost, combined_counter, ptf_tx_port_id, dut_iface):
    """
    Base test function for verification of L2 or L3 packet drops. Verification type depends on 'discard_group' value.
    Supported 'discard_group' values: 'L2', 'L3'
    """
    # Clear SONiC counters
    duthost.command("sonic-clear counters")
    duthost.command("sonic-clear rifcounters")

    # Clear packets buffer on PTF
    ptfadapter.dataplane.flush()
    time.sleep(1)

    # Send packets
    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=PKT_NUMBER)
    time.sleep(1)

    if discard_group == "L2":
        # Verify drop counter incremented on specific interface
        intf_l2_counters = get_pkt_drops(duthost, GET_L2_COUNTERS)
        if int(intf_l2_counters[dut_iface][L2_DISCARD_KEY]) != PKT_NUMBER:
            fail_msg = "'{}' drop counter was not incremented on iface {}. DUT {} == {}; Sent == {}".format(
                L2_DISCARD_KEY, dut_iface, L2_DISCARD_KEY,
                int(intf_l2_counters[dut_iface][L2_DISCARD_KEY]), PKT_NUMBER
            )
            pytest.fail(fail_msg)

        # Skip L3 discards verification for platform with linked L2 and L3 drop counters
        if not combined_counter:
            # Verify other drop counters were not incremented
            intf_l3_counters = get_pkt_drops(duthost, GET_L3_COUNTERS)
            unexpected_drops = {}
            for iface, value in intf_l3_counters.items():
                if int(value[L3_DISCARD_KEY]) != 0:
                    unexpected_drops[iface] = int(value[L3_DISCARD_KEY])
            if unexpected_drops:
                pytest.fail("L3 'RX_ERR' was incremented for the following interfaces:\n{}".format(unexpected_drops))
    elif discard_group == "L3":
        # Verify L3 drop counter incremented on specific interface
        l3_drops = get_pkt_drops(duthost, GET_L3_COUNTERS)[dut_iface][L3_DISCARD_KEY]
        l3_drops = int("".join(l3_drops.split(",")))

        if l3_drops != PKT_NUMBER:
            fail_msg = "RX_ERR drop counter was not incremented on iface {}. DUT RX_ERR == {}; Sent pkts == {}".format(
                dut_iface, l3_drops, PKT_NUMBER
            )
            pytest.fail(fail_msg)

        # Skip L2 discards verification for platform with linked L2 and L3 drop counters
        if not combined_counter:
            # Verify L2 drop counters were not incremented
            intf_l2_counters = get_pkt_drops(duthost, GET_L2_COUNTERS)
            unexpected_drops = {}
            for iface, value in intf_l2_counters.items():
                if int(value[L2_DISCARD_KEY]) != 0:
                    unexpected_drops[iface] = int(value[L2_DISCARD_KEY])
            if unexpected_drops:
                pytest.fail("L2 'RX_DRP' was incremented for the following interfaces:\n{}".format(unexpected_drops))
    else:
        pytest.fail("Incorrect 'discard_group' specified. Supported values: 'L2' or 'L3'")


def test_equal_smac_dmac_drop(ptfadapter, duthost, setup, tx_dut_ports):
    """
    @summary: Verify that packet with equal SMAC and DMAC is dropped and L2 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, dst_mac, IP_DST, IP_SRC)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=dst_mac, # PTF port
        ip_src=IP_SRC, # PTF source
        ip_dst=IP_DST, # DUT source
        tcp_sport=TCP_SPORT,
        tcp_dport=TCP_DPORT)

    base_verification("L2", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    verify_no_packet_egressed(ptfadapter, ip_dst=IP_DST, ip_src=IP_SRC, tcp_sport=TCP_SPORT, tcp_dport=TCP_DPORT)


def test_dst_ip_is_loopback_addr(ptfadapter, duthost, setup, tx_dut_ports):
    """
    @summary: Verify that packet with loopback destination IP adress is dropped and L3 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_dst = "127.0.0.1"

    log_pkt_params(dut_iface, dst_mac, src_mac, ip_dst, IP_SRC)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=IP_SRC, # PTF source
        ip_dst=ip_dst, # DUT source
        tcp_sport=TCP_SPORT,
        tcp_dport=TCP_DPORT)

    base_verification("L3", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    verify_no_packet_egressed(ptfadapter, ip_dst=ip_dst, ip_src=IP_SRC, tcp_sport=TCP_SPORT, tcp_dport=TCP_DPORT)


def test_src_ip_is_loopback_addr(ptfadapter, duthost, setup, tx_dut_ports):
    """
    @summary: Verify that packet with loopback source IP adress is dropped and L3 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_src = "127.0.0.1"

    log_pkt_params(dut_iface, dst_mac, src_mac, IP_DST, ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=ip_src, # PTF source
        ip_dst=IP_DST, # DUT source
        tcp_sport=TCP_SPORT,
        tcp_dport=TCP_DPORT)

    base_verification("L3", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    verify_no_packet_egressed(ptfadapter, ip_dst=IP_DST, ip_src=ip_src, tcp_sport=TCP_SPORT, tcp_dport=TCP_DPORT)


def test_dst_ip_absent(ptfadapter, duthost, setup, tx_dut_ports):
    """
    @summary: Verify that packet with absent destination IP address is dropped and L3 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, src_mac, "", IP_SRC)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=IP_SRC, # PTF source
        ip_dst="", # DUT source
        tcp_sport=TCP_SPORT,
        tcp_dport=TCP_DPORT)

    base_verification("L3", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    verify_no_packet_egressed(ptfadapter, ip_dst="", ip_src=IP_SRC, tcp_sport=TCP_SPORT, tcp_dport=TCP_DPORT)
