import logging
import os
import importlib
import netaddr
import pytest
import time

import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet

from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.device_utils import fanout_switch_port_lookup

RX_DRP = "RX_DRP"
RX_ERR = "RX_ERR"
L2_COL_KEY = RX_DRP
L3_COL_KEY = RX_ERR

pytest.SKIP_COUNTERS_FOR_MLNX = False
MELLANOX_MAC_UPDATE_SCRIPT = os.path.join(os.path.dirname(__file__), "fanout/mellanox/mlnx_update_mac.j2")

LOG_EXPECT_PORT_OPER_DOWN_RE = ".*Port {} oper state set from up to down.*"
LOG_EXPECT_PORT_OPER_UP_RE = ".*Port {} oper state set from down to up.*"

logger = logging.getLogger(__name__)


@pytest.fixture
def fanouthost(request, duthost, localhost):
    """
    Fixture that allows to update Fanout configuration if there is a need to send incorrect packets.
    Added possibility to create vendor specific logic to handle fanout configuration.
    If vendor need to update Fanout configuration, 'fanouthost' fixture should load and return appropriate instance.
    This instance can be used inside test case to handle fanout configuration in vendor specific section.
    By default 'fanouthost' fixture will not instantiate any instance so it will return None, and in such case
    'fanouthost' instance should not be used in test case logic.
    """
    fanout = None
    # Check that class to handle fanout config is implemented
    if "mellanox" == duthost.facts["asic_type"]:
        for file_name in os.listdir(os.path.join(os.path.dirname(__file__), "fanout")):
            # Import fanout configuration handler based on vendor name
            if "mellanox" in file_name:
                module = importlib.import_module("fanout.{0}.{0}_fanout".format(file_name.strip(".py")))
                fanout = module.FanoutHandler(duthost, localhost)
                break

    yield fanout

    if fanout is not None:
        fanout.restore_config()


@pytest.fixture(scope="module")
def pkt_fields(duthost):
    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    ipv4_addr = None
    ipv6_addr = None

    for item in mg_facts["minigraph_bgp"]:
        if item["name"] == mg_facts["minigraph_bgp"][0]["name"]:
            if netaddr.valid_ipv4(item["addr"]):
                ipv4_addr = item["addr"]
            else:
                ipv6_addr = item["addr"]

    class Collector(dict):
        def __getitem__(self, key):
            value = super(Collector, self).__getitem__(key)
            if key == "ipv4_dst" and value is None:
                pytest.skip("IPv4 address is not defined")
            elif key == "ipv6_dst" and value is None:
                pytest.skip("IPv6 address is not defined")
            return value

    test_pkt_data = Collector({
        "ipv4_dst": ipv4_addr,
        "ipv4_src": "1.1.1.1",
        "ipv6_dst": ipv6_addr,
        "ipv6_src": "ffff::101:101",
        "tcp_sport": 1234,
        "tcp_dport": 4321
        })
    return test_pkt_data


def expected_packet_mask(pkt):
    """ Return mask for sniffing packet """
    exp_pkt = pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'ttl')
    exp_pkt.set_do_not_care_scapy(packet.IP, 'chksum')
    return exp_pkt


@pytest.fixture(scope="module")
def setup(duthost, tbinfo):
    """
    Setup fixture for collecting PortChannel, VLAN and RIF port members.
    @return: Dictionary with keys:
        port_channel_members, vlan_members, rif_members, dut_to_ptf_port_map, neighbor_sniff_ports, vlans, mg_facts
    """
    port_channel_members = {}
    vlan_members = {}
    configured_vlans = []
    rif_members = []

    if tbinfo["topo"]["type"] == "ptf":
        pytest.skip("Unsupported topology {}".format(tbinfo["topo"]))

    # Gather ansible facts
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']

    for port_channel, interfaces in mg_facts['minigraph_portchannels'].items():
        for iface in interfaces["members"]:
            port_channel_members[iface] = port_channel

    for vlan_id in mg_facts["minigraph_vlans"]:
        for iface in mg_facts["minigraph_vlans"][vlan_id]["members"]:
            vlan_members[iface] = vlan_id

    rif_members = {item["attachto"]: item["attachto"] for item in mg_facts["minigraph_interfaces"]}

    # Compose list of sniff ports
    neighbor_sniff_ports = []
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        neighbor_sniff_ports.append(mg_facts['minigraph_port_indices'][dut_port])

    for vlan_name, vlans_data in mg_facts["minigraph_vlans"].items():
        configured_vlans.append(int(vlans_data["vlanid"]))

    setup_information = {
        "port_channel_members": port_channel_members,
        "vlan_members": vlan_members,
        "rif_members": rif_members,
        "dut_to_ptf_port_map": mg_facts["minigraph_port_indices"],
        "neighbor_sniff_ports": neighbor_sniff_ports,
        "vlans": configured_vlans,
        "mg_facts": mg_facts
    }
    return setup_information


@pytest.fixture
def rif_port_down(duthost, setup, fanouthosts, loganalyzer):
    """Shut RIF interface and return neighbor IP address attached to this interface.

    The RIF member is shut from the fanout side so that the ARP entry remains in
    place on the DUT."""
    wait_after_ports_up = 30

    if not setup["rif_members"]:
        pytest.skip("RIF interface is absent")
    rif_member_iface = setup["rif_members"].keys()[0]

    vm_name = setup["mg_facts"]["minigraph_neighbors"][rif_member_iface].get("name", None)
    pytest_assert(vm_name, 'Neighbor not found for RIF member "{}"'.format(rif_member_iface))

    ip_dst = None
    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name and netaddr.valid_ipv4(item["addr"]):
            ip_dst = item["addr"]
            break
    pytest_assert(ip_dst, 'Unable to find IP address for neighbor "{}"'.format(vm_name))

    fanout_neighbor, fanout_intf = fanout_switch_port_lookup(fanouthosts, rif_member_iface)

    loganalyzer.expect_regex = [LOG_EXPECT_PORT_OPER_DOWN_RE.format(rif_member_iface)]
    with loganalyzer as _:
        fanout_neighbor.shutdown(fanout_intf)

    time.sleep(1)

    yield ip_dst

    loganalyzer.expect_regex = [LOG_EXPECT_PORT_OPER_UP_RE.format(rif_member_iface)]
    with loganalyzer as _:
        fanout_neighbor.no_shutdown(fanout_intf)
        time.sleep(wait_after_ports_up)


@pytest.fixture(params=["port_channel_members", "vlan_members", "rif_members"])
def tx_dut_ports(request, setup):
    """ Fixture for getting port members of specific port group """
    return setup[request.param] if setup[request.param] else pytest.skip("No {} available".format(request.param))


@pytest.fixture
def ports_info(ptfadapter, duthost, setup, tx_dut_ports):
    """
    Return:
        dut_iface - DUT interface name expected to receive packtes from PTF
        ptf_tx_port_id - Port ID used by PTF for sending packets from expected PTF interface
        dst_mac - DUT interface destination MAC address
        src_mac - PTF interface source MAC address
    """
    data = {}
    data["dut_iface"] = random.choice(tx_dut_ports.keys())
    data["ptf_tx_port_id"] = setup["dut_to_ptf_port_map"][data["dut_iface"]]
    data["dst_mac"] = duthost.get_dut_iface_mac(data["dut_iface"])
    data["src_mac"] = ptfadapter.dataplane.ports[(0, data["ptf_tx_port_id"])].mac()
    return data


def log_pkt_params(dut_iface, mac_dst, mac_src, ip_dst, ip_src):
    """ Displays information about packet fields used in test case: mac_dst, mac_src, ip_dst, ip_src """
    logger.info("Selected TX interface on DUT - {}".format(dut_iface))
    logger.info("Packet DST MAC - {}".format(mac_dst))
    logger.info("Packet SRC MAC - {}".format(mac_src))
    logger.info("Packet IP DST - {}".format(ip_dst))
    logger.info("Packet IP SRC - {}".format(ip_src))


def send_packets(pkt, duthost, ptfadapter, ptf_tx_port_id, num_packets=1):
    # Clear packets buffer on PTF
    ptfadapter.dataplane.flush()
    time.sleep(1)

    # Send packets
    testutils.send(ptfadapter, ptf_tx_port_id, pkt, count=num_packets)
    time.sleep(1)


def test_equal_smac_dmac_drop(do_test, ptfadapter, duthost, setup, fanouthost, pkt_fields, ports_info):
    """
    @summary: Create a packet with equal SMAC and DMAC.
    """
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["dst_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
    src_mac = ports_info["dst_mac"]

    if "mellanox" == duthost.facts["asic_type"]:
        pytest.SKIP_COUNTERS_FOR_MLNX = True
        src_mac = "00:00:00:00:00:11"
        # Prepare openflow rule
        fanouthost.update_config(template_path=MELLANOX_MAC_UPDATE_SCRIPT, match_mac=src_mac, set_mac=ports_info["dst_mac"], eth_field="eth_src")

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=src_mac,  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    comparable_pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["dst_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    do_test("L2", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], comparable_pkt=comparable_pkt)


def test_multicast_smac_drop(do_test, ptfadapter, duthost, setup, fanouthost, pkt_fields, ports_info):
    """
    @summary: Create a packet with multicast SMAC.
    """
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    multicast_smac = "01:00:5e:00:01:02"
    src_mac = multicast_smac

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], multicast_smac, pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    if "mellanox" == duthost.facts["asic_type"]:
        pytest.SKIP_COUNTERS_FOR_MLNX = True
        src_mac = "00:00:00:00:00:11"
        # Prepare openflow rule
        fanouthost.update_config(template_path=MELLANOX_MAC_UPDATE_SCRIPT, match_mac=src_mac, set_mac=multicast_smac, eth_field="eth_src")

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=src_mac,
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    comparable_pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=multicast_smac,
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
    )

    do_test("L2", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], comparable_pkt=comparable_pkt)


def test_not_expected_vlan_tag_drop(do_test, ptfadapter, duthost, setup, pkt_fields, ports_info):
    """
    @summary: Create a VLAN tagged packet which VLAN ID does not match ingress port VLAN ID.
    """

    start_vlan_id = 2
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])
    max_vlan_id = 1000
    upper_bound = max(setup["vlans"]) if setup["vlans"] else max_vlan_id
    for interim in range(start_vlan_id, upper_bound):
        if interim not in setup["vlans"]:
            vlan_id = interim
            break
    else:
        pytest.fail("Unable to generate unique not yet existed VLAN ID. Already configured VLANs range {}-{}".format(start_vlan_id,
            upper_bound))

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        dl_vlan_enable=True,
        vlan_vid=vlan_id,
        )

    do_test("L2", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"])


def test_dst_ip_is_loopback_addr(do_test, ptfadapter, duthost, setup, pkt_fields, tx_dut_ports, ports_info):
    """
    @summary: Create a packet with loopback destination IP adress.
    """

    ip_dst = "127.0.0.1"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=ip_dst,  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_src_ip_is_loopback_addr(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with loopback source IP adress.
    """

    ip_src = "127.0.0.1"

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_src)

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=ip_src,  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_dst_ip_absent(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with absent destination IP address.
    """

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], "", pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst="", # VM source
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("ip_addr", ["ipv4", "ipv6"])
def test_src_ip_is_multicast_addr(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ip_addr, ports_info):
    """
    @summary: Create a packet with multicast source IP adress.
    """

    ip_src = None

    if ip_addr == "ipv4":
        ip_src = "224.0.0.5"
        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ip_src=ip_src,
            ip_dst=pkt_fields["ipv4_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    elif ip_addr == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        ip_src = "FF02:AAAA:FEE5::1:3"
        pkt = testutils.simple_tcpv6_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ipv6_src=ip_src,
            ipv6_dst=pkt_fields["ipv6_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])
    else:
        pytest.fail("Incorrect value specified for 'ip_addr' test parameter. Supported parameters: 'ipv4' and 'ipv6'")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], ip_src)

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_src_ip_is_class_e(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with source IP address in class E.
    """

    ip_list = ["240.0.0.1", "255.255.255.254"]

    for ip_class_e in ip_list:
        log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                        ip_class_e)

        pkt = testutils.simple_tcp_packet(
            eth_dst=ports_info["dst_mac"],  # DUT port
            eth_src=ports_info["src_mac"],  # PTF port
            ip_src=ip_class_e,
            ip_dst=pkt_fields["ipv4_dst"],  # VM source
            tcp_sport=pkt_fields["tcp_sport"],
            tcp_dport=pkt_fields["tcp_dport"])

        do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("addr_type, addr_direction", [("ipv4", "src"), ("ipv6", "src"), ("ipv4", "dst"),
                                                        ("ipv6", "dst")])
def test_ip_is_zero_addr(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, addr_type, addr_direction, ports_info):
    """
    @summary: Create a packet with "0.0.0.0" source or destination IP address.
    """

    zero_ipv4 = "0.0.0.0"
    zero_ipv6 = "::0"

    pkt_params = {
        "eth_dst": ports_info["dst_mac"],  # DUT port
        "eth_src": ports_info["src_mac"],  # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
        }

    if addr_type == "ipv4":
        if addr_direction == "src":
            pkt_params["ip_src"] = zero_ipv4
            pkt_params["ip_dst"] = pkt_fields["ipv4_dst"]  # VM source
        elif addr_direction == "dst":
            pkt_params["ip_src"] = pkt_fields["ipv4_src"]  # VM source
            pkt_params["ip_dst"] = zero_ipv4
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcp_packet(**pkt_params)
    elif addr_type == "ipv6":
        if not pkt_fields["ipv6_dst"]:
            pytest.skip("BGP neighbour with IPv6 addr was not found")
        if addr_direction == "src":
            pkt_params["ipv6_src"] = zero_ipv6
            pkt_params["ipv6_dst"] = pkt_fields["ipv6_dst"]  # VM source
        elif addr_direction == "dst":
            pkt_params["ipv6_src"] = pkt_fields["ipv6_src"]  # VM source
            pkt_params["ipv6_dst"] = zero_ipv6
        else:
            pytest.fail("Incorrect value specified for 'addr_direction'. Supported parameters: 'src' and 'dst'")
        pkt = testutils.simple_tcpv6_packet(**pkt_params)
    else:
        pytest.fail("Incorrect value specified for 'addr_type' test parameter. Supported parameters: 'ipv4' or 'ipv6'")

    logger.info(pkt_params)

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["dut_to_ptf_port_map"].values(), tx_dut_ports)


def test_dst_ip_link_local(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet with link-local address "169.254.0.0/16".
    """

    link_local_ip = "169.254.10.125"

    pkt_params = {
        "eth_dst": ports_info["dst_mac"],  # DUT port
        "eth_src": ports_info["src_mac"],  # PTF port
        "tcp_sport": pkt_fields["tcp_sport"],
        "tcp_dport": pkt_fields["tcp_dport"]
    }
    pkt_params["ip_src"] = pkt_fields["ipv4_src"]  # VM source
    pkt_params["ip_dst"] = link_local_ip
    pkt = testutils.simple_tcp_packet(**pkt_params)

    logger.info(pkt_params)
    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


# Test case is skipped, because SONiC does not have a control to adjust loop-back filter settings.
# Default SONiC behaviour is to forward the traffic, so loop-back filter does not triggers for IP packets.
# All router interfaces has attribute "sx_interface_attributes_t.loopback_enable" - enabled.
# To enable loop-back filter drops - need to disable that attribute when create RIF.
# To do this can be used SAI attribute SAI_ROUTER_INTERFACE_ATTR_LOOPBACK_PACKET_ACTION, which is not exposed to SONiC
@pytest.mark.skip(reason="SONiC can't enable loop-back filter feature")
def test_loopback_filter(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create a packet drops by loopback-filter. Loop-back filter means that route to the host
              with DST IP of received packet exists on received interface
    """

    ip_dst = None
    vm_name = setup["mg_facts"]["minigraph_neighbors"][ports_info["dut_iface"]]["name"]

    for item in setup["mg_facts"]["minigraph_bgp"]:
        if item["name"] == vm_name:
            ip_dst = item["addr"]
            break
    if ip_dst is None:
        pytest.skip("Testcase is not supported on current interface")

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], ip_dst, pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=ip_dst,
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"])

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_ip_pkt_with_expired_ttl(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create an IP packet with TTL=0.
    """

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                    pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],  # VM IP address
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"],
        ip_ttl=0)

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("pkt_field, value", [("version", 1), ("chksum", 10), ("ihl", 1)])
def test_broken_ip_header(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, pkt_field, value, ports_info):
    """
    @summary: Create a packet with broken IP header.
    """

    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"],  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    setattr(pkt[testutils.scapy.scapy.all.IP], pkt_field, value)

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


def test_absent_ip_header(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, ports_info):
    """
    @summary: Create packets with absent IP header.
    """
    log_pkt_params(ports_info["dut_iface"], ports_info["dst_mac"], ports_info["src_mac"], pkt_fields["ipv4_dst"],
                    pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=ports_info["dst_mac"], # DUT port
        eth_src=ports_info["src_mac"], # PTF port
        ip_src=pkt_fields["ipv4_src"], # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )
    tcp = pkt[testutils.scapy.scapy.all.TCP]
    del pkt[testutils.scapy.scapy.all.IP]
    pkt.type = 0x800
    pkt = pkt/tcp

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("eth_dst", ["01:00:5e:00:01:02", "ff:ff:ff:ff:ff:ff"])
def test_unicast_ip_incorrect_eth_dst(do_test, ptfadapter, duthost, setup, tx_dut_ports, pkt_fields, eth_dst, ports_info):
    """
    @summary: Create packets with multicast/broadcast ethernet dst.
    """

    if  "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower():
        pytest.skip("Test case is not supported on VLAN interface")

    log_pkt_params(ports_info["dut_iface"], eth_dst, ports_info["src_mac"], pkt_fields["ipv4_dst"], pkt_fields["ipv4_src"])

    pkt = testutils.simple_tcp_packet(
        eth_dst=eth_dst,  # DUT port
        eth_src=ports_info["src_mac"],  # PTF port
        ip_src=pkt_fields["ipv4_src"],  # PTF source
        ip_dst=pkt_fields["ipv4_dst"],
        tcp_sport=pkt_fields["tcp_sport"],
        tcp_dport=pkt_fields["tcp_dport"]
        )

    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["neighbor_sniff_ports"], tx_dut_ports)


@pytest.mark.parametrize("igmp_version,msg_type", [("v1", "general_query"), ("v3", "general_query"), ("v1", "membership_report"),
("v2", "membership_report"), ("v3", "membership_report"), ("v2", "leave_group")])
def test_non_routable_igmp_pkts(do_test, ptfadapter, duthost, setup, fanouthost, tx_dut_ports, pkt_fields, igmp_version, msg_type, ports_info):
    """
    @summary: Create an IGMP non-routable packets.
    """
    # IGMP Types:
    # 0x11 = Membership Query
    # 0x12 = Version 1 Membership Report
    # 0x16 = Version 2 Membership Report
    # 0x17 = Leave Group

    # IP destination address according to the RFC 2236:
    # Message Type                  Destination Group
    # ------------                  -----------------
    # General Query                 ALL-SYSTEMS (224.0.0.1)
    # Group-Specific Query          The group being queried
    # Membership Report             The group being reported
    # Leave Message                 ALL-ROUTERS (224.0.0.2)

    # TODO: fix this workaround as of now current PTF and Scapy versions do not support creation of IGMP packets
    # Temporaly created hex of IGMP packet layer by using scapy version 2.4.3.
    # Example how to get HEX of specific IGMP packets:
    # v3_membership_query = IGMPv3(type=0x11, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mq(gaddr="224.0.0.1",
    # srcaddrs=["172.16.11.1", "10.0.0.59"], qrv=1, qqic=125, numsrc=2)
    # gr_obj = scapy.contrib.igmpv3.IGMPv3gr(rtype=1, auxdlen=0, maddr="224.2.2.4", numsrc=2, srcaddrs=["172.16.11.1",
    # "10.0.0.59"]).build()
    # v3_membership_report = IGMPv3(type=0x22, mrcode=0, chksum=None)/scapy.contrib.igmpv3.IGMPv3mr(res2=0x00, numgrp=1,
    # records=[gr_obj]).build()
    # The rest packets are build like "simple_igmp_packet" function from PTF testutils.py

    # FIXME: Need some sort of configuration for EOS and SONiC fanout hosts to
    # not drop IGMP packets before they reach the DUT
    if not fanouthost:
        pytest.skip("Test case requires explicit fanout support")

    from scapy.contrib.igmp import IGMP
    Ether = testutils.scapy.Ether
    IP = testutils.scapy.IP

    if "vlan" in tx_dut_ports[ports_info["dut_iface"]].lower() and msg_type == "membership_report":
        pytest.skip("Test case is not supported on VLAN interface")

    igmp_proto = 0x02
    multicast_group_addr = "224.1.1.1"
    ethernet_dst = "01:00:5e:01:01:01"
    ip_dst = {"general_query": "224.0.0.1",
              "membership_report": multicast_group_addr}
    igmp_types = {"v1": {"general_query": IGMP(type=0x11, gaddr="224.0.0.1"),
                         "membership_report": IGMP(type=0x12, gaddr=multicast_group_addr)},
                  "v2": {"membership_report": IGMP(type=0x16, gaddr=multicast_group_addr),
                         "leave_group": IGMP(type=0x17, gaddr=multicast_group_addr)},
                  "v3": {"general_query": "\x11\x00L2\xe0\x00\x00\x01\x01}\x00\x02\xac\x10\x0b\x01\n\x00\x00;",
                         "membership_report": "\"\x009\xa9\x00\x00\x00\x01\x01\x00\x00\x02\xe0\x02\x02\x04\xac\x10\x0b\x01\n\x00\x00;"}
    }

    if igmp_version == "v3":
        pkt = testutils.simple_ip_packet(
            eth_dst=ethernet_dst,
            eth_src=ports_info["src_mac"],
            ip_src=pkt_fields["ipv4_src"],
            ip_dst=ip_dst[msg_type],
            ip_ttl=1,
            ip_proto=igmp_proto
        )
        del pkt["Raw"]
        pkt = pkt / igmp_types[igmp_version][msg_type]
    else:
        eth_layer = Ether(src=ports_info["src_mac"], dst=ethernet_dst)
        ip_layer = IP(src=pkt_fields["ipv4_src"], )
        igmp_layer = igmp_types[igmp_version][msg_type]
        assert igmp_layer.igmpize(ip=ip_layer, ether=eth_layer), "Can't create IGMP packet"
        pkt = eth_layer/ip_layer/igmp_layer

    log_pkt_params(ports_info["dut_iface"], ethernet_dst, ports_info["src_mac"], pkt.getlayer("IP").dst, pkt_fields["ipv4_src"])
    do_test("L3", pkt, ptfadapter, duthost, ports_info, setup["dut_to_ptf_port_map"].values(), tx_dut_ports)
