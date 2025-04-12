import pytest
import logging
import time
import ptf.testutils as testutils
import ptf.packet as packet

from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.helpers.assertions import pytest_assert
from ptf.mask import Mask


pytestmark = [
    pytest.mark.topology("t1", "t1-64-lag", "t1-56-lag", "t1-lag"),
    pytest.mark.disable_loganalyzer
]


DESTINATION_PREFIX = 150
ENDPOINT_PREFIX = 100
VNI = 10000
VXLAN_DST_PORT = 4789
OUTER_IP_HEADER_SIZE = len(packet.Ether()) + len(packet.IP())
OUTER_IPV6_HEADER_SIZE = len(packet.Ether()) + len(packet.IPv6())
VXLAN_HEADER_SIZE = len(packet.Ether()) + len(packet.IP()) + len(packet.UDP()) + len(packet.VXLAN())
VXLANV6_HEADER_SIZE = len(packet.Ether()) + len(packet.IPv6()) + len(packet.UDP()) + len(packet.VXLAN())


Logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


def find_ptf_dest_port(duthost, minigraph_facts, except_interfaces=[]):
    """
    Finds an Ethernet port that is operationally UP and does not appear in except_interfaces
    and also is not a member of any PortChannel interface that appears in except_interfaces.
    Returns the PTF index of that Ethernet port (if such port is found).
    """
    dut_interfaces = duthost.get_interfaces_status()
    ptf_indices = minigraph_facts["minigraph_ptf_indices"]
    except_ports = ecmp_utils.get_ethernet_ports(except_interfaces, minigraph_facts)
    for intf_name, intf_info in dut_interfaces.items():
        if intf_info["oper"] == "up" and intf_name.startswith("Ethernet") and intf_name not in except_ports:
            return ptf_indices[intf_name]
    pytest.skip("No suitable Ethernet port could be found on the DUT for receiving packets from PTF.")
    return -1


@pytest.fixture(scope="module", params=[4, 6], ids=["inner_ipv4", "inner_ipv6"])
def inner_ip_version(request):
    return request.param


@pytest.fixture(scope="module", params=[4, 6], ids=["outer_ipv4", "outer_ipv6"])
def outer_ip_version(request):
    return request.param


@pytest.fixture
def setup(request, duthosts, rand_one_dut_hostname, tbinfo, inner_ip_version, outer_ip_version):
    """
    Creates a VXLAN tunnel, a VNET, and one VNET route (with a single endpoint). Also finds an appropriate
    Ethernet port for sending the IP-in-IP packet to the DUT.
    Yields test configuration and data.
    """
    duthost = duthosts[rand_one_dut_hostname]
    asic_type = duthost.facts["asic_type"]
    if asic_type not in ["cisco-8000", "mellanox"]:
        pytest.skip("The VNET decap test will only run on Cisco-8000 and Mellanox ASICs.")
    platform = duthost.facts["platform"]
    if platform in ['x86_64-mlnx_msn2700-r0', 'x86_64-mlnx_msn2700a1-r0']:
        pytest.skip("Mellanox msn2700 switches do not support VNET decapsulation.")

    # Should I keep the temporary files copied to DUT?
    ecmp_utils.Constants["KEEP_TEMP_FILES"] = request.config.option.keep_temp_files
    # Is debugging going on, or is it a production run? If it is a
    # production run, use time-stamped file names for temp files.
    ecmp_utils.Constants["DEBUG"] = request.config.option.debug_enabled
    # The host id in the ip addresses for DUT. It can be anything,
    # but helps to keep as a single number that is easy to identify
    # as DUT.
    ecmp_utils.Constants["DUT_HOSTID"] = request.config.option.dut_hostid

    # Setup
    router_mac = duthost.facts["router_mac"]
    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=VXLAN_DST_PORT, dutmac=router_mac)
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    outer_ip_version_str = f"v{outer_ip_version}"
    vnet_interface = ecmp_utils.select_required_interfaces(duthost, 1, minigraph_facts, outer_ip_version_str)[0]
    vxlan_tunnel = ecmp_utils.create_vxlan_tunnel(duthost, minigraph_facts, outer_ip_version_str)
    inner_ip_version_str = f"v{inner_ip_version}"
    encap_type = f"{inner_ip_version_str}_in_{outer_ip_version_str}"
    vnet = next(iter(ecmp_utils.create_vnets(duthost, vxlan_tunnel,
                                             vnet_count=1,     # default scope can take only one vnet.
                                             vnet_name_prefix=f"Vnet_{encap_type}", scope="default", vni_base=VNI)))
    vnet_dest_to_endpoint_map = ecmp_utils.create_vnet_routes(duthost, [vnet], nhs_per_destination=1,
                                                              number_of_available_nexthops=1,
                                                              number_of_ecmp_nhs=1, dest_af=inner_ip_version_str,
                                                              dest_net_prefix=DESTINATION_PREFIX,
                                                              nexthop_prefix=ENDPOINT_PREFIX,
                                                              nh_af=outer_ip_version_str)
    ptf_port_index = find_ptf_dest_port(duthost, minigraph_facts, except_interfaces=[vnet_interface])
    data = {}  # test data
    data["router_mac"] = router_mac
    data["outer_ip_version"] = outer_ip_version
    data["inner_ip_version"] = inner_ip_version
    data["vxlan_src_ip"] = ecmp_utils.get_dut_loopback_address(duthost, minigraph_facts, outer_ip_version_str)
    data["vnet_dest"] = next(iter(vnet_dest_to_endpoint_map[vnet].keys()))
    data["vnet_endpoint"] = vnet_dest_to_endpoint_map[vnet][data["vnet_dest"]][0]
    data["ptf_port_index"] = ptf_port_index
    data["all_ptf_port_indices"] = list(minigraph_facts["minigraph_ptf_indices"].values())
    yield data

    # Clean-up
    # Deleting Vnet routes
    ecmp_utils.set_routes_in_dut(duthost, vnet_dest_to_endpoint_map, inner_ip_version_str, "DEL")
    # Deleting the VNet
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL \"VNET|{vnet}\"")
    time.sleep(5)
    # Deleting the VxLAN tunnel
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL \"VXLAN_TUNNEL|{vxlan_tunnel}\"")


def get_inner_ip_packet(vnet_dest, inner_ip_version):
    if inner_ip_version == 4:
        return testutils.simple_udp_packet(ip_dst=vnet_dest).getlayer(packet.IP)
    else:
        return testutils.simple_udpv6_packet(ipv6_dst=vnet_dest).getlayer(packet.IPv6)


def get_outer_packet(ptf_mac, router_mac, vxlan_src_ip, inner_ip_pkt, outer_ip_version):
    if outer_ip_version == 4:
        return testutils.simple_ipv4ip_packet(eth_src=ptf_mac, eth_dst=router_mac,
                                              ip_dst=vxlan_src_ip, inner_frame=inner_ip_pkt)
    else:
        return testutils.simple_ipv6ip_packet(eth_src=ptf_mac, eth_dst=router_mac,
                                              ipv6_dst=vxlan_src_ip, inner_frame=inner_ip_pkt)


def get_expected_vxlanv4_packet(router_mac, vxlan_src_ip, vnet_endpoint, inner_frame):
    exp_pkt = testutils.simple_vxlan_packet(eth_src=router_mac, ip_src=vxlan_src_ip,
                                            ip_dst=vnet_endpoint, udp_dport=VXLAN_DST_PORT,
                                            vxlan_vni=VNI, inner_frame=inner_frame)
    exp_pkt_mask = Mask(exp_pkt)
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "ihl")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "tos")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "id")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "flags")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "ttl")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "chksum")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "sport")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "chksum")
    # inner_frame will be checked later
    exp_pkt_mask.set_do_not_care(VXLAN_HEADER_SIZE * 8, len(inner_frame) * 8)
    return exp_pkt_mask


def get_expected_vxlanv6_packet(router_mac, vxlan_src_ip, vnet_endpoint, inner_frame):
    exp_pkt = testutils.simple_vxlanv6_packet(eth_src=router_mac, ipv6_src=vxlan_src_ip,
                                              ipv6_dst=vnet_endpoint, udp_dport=VXLAN_DST_PORT,
                                              vxlan_vni=VNI, inner_frame=inner_frame)
    exp_pkt_mask = Mask(exp_pkt)
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "fl")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "tc")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "hlim")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "sport")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "chksum")
    # inner_frame will be checked later
    exp_pkt_mask.set_do_not_care(VXLANV6_HEADER_SIZE * 8, len(inner_frame) * 8)
    return exp_pkt_mask


def get_expected_vxlan_packet(outer_ip_version, router_mac, vxlan_src_ip, vnet_endpoint, inner_ip_pkt):
    """
    Returns the (mask of) expected VXLAN packet that is sent out by the DUT.
    """
    # The DUT will add an Ethernet header to the inner IP packet before encapsulating it in a VXLAN packet
    # and sending it out
    inner_frame = packet.Ether(dst=router_mac, src=router_mac) / inner_ip_pkt
    if outer_ip_version == 4:
        return get_expected_vxlanv4_packet(router_mac, vxlan_src_ip, vnet_endpoint, inner_frame)
    else:
        return get_expected_vxlanv6_packet(router_mac, vxlan_src_ip, vnet_endpoint, inner_frame)


def extract_payload(outer_pkt, header_size):
    pytest_assert(len(outer_pkt) >= header_size,
                  f"Received an incomplete packet. Expected at least {header_size} header bytes.")
    return packet.Ether(outer_pkt[header_size:])


def get_expected_inner_frame_ipv4(inner_frame):
    inner_frame["IP"].ttl -= 1
    exp_inner_frame = Mask(inner_frame)
    exp_inner_frame.set_do_not_care_packet(packet.Ether, "dst")
    exp_inner_frame.set_do_not_care_packet(packet.IP, "ihl")
    exp_inner_frame.set_do_not_care_packet(packet.IP, "tos")
    exp_inner_frame.set_do_not_care_packet(packet.IP, "flags")
    exp_inner_frame.set_do_not_care_packet(packet.IP, "chksum")
    return exp_inner_frame


def get_expected_inner_frame_ipv6(inner_frame):
    inner_frame["IPv6"].hlim -= 1
    exp_inner_frame = Mask(inner_frame)
    exp_inner_frame.set_do_not_care_packet(packet.Ether, "dst")
    exp_inner_frame.set_do_not_care_packet(packet.IPv6, "fl")
    exp_inner_frame.set_do_not_care_packet(packet.IPv6, "tc")
    return exp_inner_frame


def get_expected_inner_frame(inner_ip_pkt, inner_ip_version, router_mac):
    """
    Returns the (mask of) expected Ethernet frame that should be encapsulated in the VXLAN packet that is sent out.
    """
    inner_frame = packet.Ether(dst=router_mac, src=router_mac) / inner_ip_pkt
    if inner_ip_version == 4:
        return get_expected_inner_frame_ipv4(inner_frame)
    else:
        return get_expected_inner_frame_ipv6(inner_frame)


def extract_inner_ip_pkt(outer_pkt, inner_ip_version, outer_ip_version):
    """
    Returns the inner IP packet of the given IP-in-IP packet 'outer_pkt'.
    """
    outer_ip_header_size = OUTER_IP_HEADER_SIZE if outer_ip_version == 4 else OUTER_IPV6_HEADER_SIZE
    outer_pkt_bytes = bytes(outer_pkt)
    if inner_ip_version == 4:
        return packet.IP(outer_pkt_bytes[outer_ip_header_size:])
    else:
        return packet.IPv6(outer_pkt_bytes[outer_ip_header_size:])


def test_vnet_decap(setup, ptfadapter):
    """
    We send an IP-in-IP packet to the DUT:
        Outer IP packet is from an arbitrary address to the VXLAN tunnel's src IP.
        Inner IP packet is from an arbitrary address to the VNET route's dest IP.
    The DUT is expected to decapsulate the IP-in-IP packet, add an Ethernet header to
    the inner IP packet, and then encapsulate it in a VXLAN packet and send it out.
    The VXLAN packet should be from the VXLAN tunnel's src IP to the VNET route's endpoint.
    """
    data = setup
    router_mac = data["router_mac"]
    outer_ip_version = data["outer_ip_version"]
    inner_ip_version = data["inner_ip_version"]
    vxlan_src_ip = data["vxlan_src_ip"]
    vnet_dest = data["vnet_dest"]
    vnet_endpoint = data["vnet_endpoint"]
    ptf_port_index = data["ptf_port_index"]
    all_ptf_port_indices = data["all_ptf_port_indices"]

    inner_ip_pkt = get_inner_ip_packet(vnet_dest, inner_ip_version)  # Does not have the Ethernet header
    ptf_mac = ptfadapter.dataplane.get_mac(0, ptf_port_index)
    test_pkt = get_outer_packet(ptf_mac, router_mac, vxlan_src_ip, inner_ip_pkt, outer_ip_version)
    expected_pkt = get_expected_vxlan_packet(outer_ip_version, router_mac, vxlan_src_ip, vnet_endpoint, inner_ip_pkt)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_port_index, test_pkt)
    # Verify that the expected VXLAN packet is captured on any port
    _, received_pkt = testutils.verify_packet_any_port(ptfadapter, expected_pkt, all_ptf_port_indices)
    # Verify that the payload of the captured VXLAN packet is correct
    # testutils.send updates the payload of test_pkt and then sends it.
    # So we need to extract inner_ip_pkt from the new test_pkt.
    inner_ip_pkt = extract_inner_ip_pkt(test_pkt, inner_ip_version, outer_ip_version)
    vxlan_header_size = VXLAN_HEADER_SIZE if outer_ip_version == 4 else VXLANV6_HEADER_SIZE
    received_inner_frame = extract_payload(received_pkt, vxlan_header_size)
    expected_inner_frame = get_expected_inner_frame(inner_ip_pkt, inner_ip_version, router_mac)
    pytest_assert(expected_inner_frame.pkt_match(received_inner_frame),
                  "Received an incorrect VXLAN-encapsulated frame.")
