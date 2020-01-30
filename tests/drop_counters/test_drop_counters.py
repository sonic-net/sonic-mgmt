import pytest
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import logging
import importlib
import pprint
import random
import time
import scapy
import yaml
import re
import os
import json


logger = logging.getLogger(__name__)

PKT_NUMBER = 1000

# Discard key from 'portstat -j' CLI command output
L2_DISCARD_KEY = "RX_DRP"
L3_DISCARD_KEY = "RX_ERR"
# CLI commands to obtain drop counters
GET_L2_COUNTERS = "portstat -j"
GET_L3_COUNTERS = "intfstat -j"


@pytest.fixture(scope="module")
def pkt_fields(duthost):
    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    test_pkt_data = {
        "ip_dst": mg_facts["minigraph_bgp"][0]["addr"],
        "ip_src": "1.1.1.1",
        "tcp_sport": 1234,
        "tcp_dport": 4321
        }
    return test_pkt_data


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

    if testbed["topo"] == "ptf32":
        pytest.skip("Unsupported topology {}".format(testbed["topo"]))

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

    # Compose list of sniff ports
    neighbor_sniff_ports = []
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        neighbor_sniff_ports.append(mg_facts['minigraph_port_indices'][dut_port])

    setup_information = {
        "port_channel_members": port_channel_members,
        "vlan_members": vlan_members,
        "rif_members": rif_members,
        "dut_to_ptf_port_map": mg_facts["minigraph_port_indices"],
        "combined_drop_counter": combined_drop_counter,
        "neighbor_sniff_ports": neighbor_sniff_ports
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
    cmd_get_cnt_status = "redis-cli -n 4 HGET \"FLEX_COUNTER_TABLE|{}\" \"FLEX_COUNTER_STATUS\""

    previous_cnt_status = {item: duthost.command(cmd_get_cnt_status.format(item.upper()))["stdout"] for item in ["port", "rif"]}

    for cmd in cmd_list:
        duthost.command(cmd)
    yield
    for port, status in previous_cnt_status.items():
        if status == "disable":
            logger.info("Restoring counter '{}' state to disable".format(port))
            duthost.command("counterpoll {} disable".format(port))


@pytest.fixture
def fanouthost(request, testbed_devices):
    """
    Fixture that allows to update Fanout configuration if there is a need to send incorrect packets.
    Added possibility to create vendor specific logic to handle fanout configuration.
    If vendor need to update Fanout configuration, 'fanouthost' fixture should load and return appropriate instance.
    This instance can be used inside test case to handle fanout configuration in vendor specific section.
    By default 'fanouthost' fixture will not instantiate any instance so it will return None, and in such case
    'fanouthost' instance should not be used in test case logic.
    """
    dut = testbed_devices["dut"]
    fanout = None
    # Check that class to handle fanout config is implemented
    if "mellanox" == dut.facts["asic_type"]:
        for file_name in os.listdir(os.path.join(os.path.dirname(__file__), "fanout")):
            # Import fanout configuration handler based on vendor name
            if "mellanox" in file_name:
                module = importlib.import_module("fanout.{0}.{0}_fanout".format(file_name.strip(".py")))
                fanout = module.FanoutHandler(testbed_devices)
                break
    try:
        yield fanout
    finally:
        if fanout is not None:
            fanout.restore_config()


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


def expected_packet_mask(pkt):
    """ Return mask for sniffing packet """

    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
    return exp_pkt


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


def test_equal_smac_dmac_drop(ptfadapter, fanouthost, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with equal SMAC and DMAC is dropped and L2 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    src_mac = dst_mac

    log_pkt_params(dut_iface, dst_mac, dst_mac, pkt_fields["ip_dst"], pkt_fields["ip_src"])

    if "mellanox" == duthost.facts["asic_type"]:
        src_mac = "00:00:00:00:00:11"
        # Prepare openflow rule
        fanouthost.update_config(template_path=os.path.join(os.path.dirname(__file__),
                                    "fanout/mellanox/mlnx_update_smac.j2"), match_mac=src_mac, set_mac=dst_mac)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ip_src"], # PTF source
        ip_dst=pkt_fields["ip_dst"], # DUT source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L2", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, dut_iface)

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_dst_ip_is_loopback_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with loopback destination IP adress is dropped and L3 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_dst = "127.0.0.1"

    log_pkt_params(dut_iface, dst_mac, src_mac, ip_dst, pkt_fields["ip_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ip_src"], # PTF source
        ip_dst=ip_dst, # DUT source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L3", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_src_ip_is_loopback_addr(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with loopback source IP adress is dropped and L3 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)
    ip_src = "127.0.0.1"

    log_pkt_params(dut_iface, dst_mac, src_mac, pkt_fields["ip_dst"], ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=ip_src, # PTF source
        ip_dst=pkt_fields["ip_dst"], # DUT source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L3", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])


def test_dst_ip_absent(ptfadapter, duthost, setup, tx_dut_ports, pkt_fields):
    """
    @summary: Verify that packet with absent destination IP address is dropped and L3 drop cunter incremented
    """
    dut_iface, ptf_tx_port_id, dst_mac, src_mac = get_test_ports_info(ptfadapter, duthost, setup, tx_dut_ports)

    log_pkt_params(dut_iface, dst_mac, src_mac, "", pkt_fields["ip_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=dst_mac, # DUT port
        eth_src=src_mac, # PTF port
        ip_src=pkt_fields["ip_src"], # PTF source
        ip_dst="", # DUT source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    base_verification("L3", pkt, ptfadapter, duthost, setup["combined_drop_counter"], ptf_tx_port_id, tx_dut_ports[dut_iface])

    # Verify packets were not egresed the DUT
    exp_pkt = expected_packet_mask(pkt)
    testutils.verify_no_packet_any(ptfadapter, exp_pkt, ports=setup["neighbor_sniff_ports"])
