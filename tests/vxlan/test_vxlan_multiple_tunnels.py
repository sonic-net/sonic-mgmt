import pytest
import logging
import ptf.testutils as testutils
import ptf.packet as packet

from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from ptf.mask import Mask


pytestmark = [
    pytest.mark.topology("t1", "t1-64-lag", "t1-56-lag", "t1-lag"),
    pytest.mark.disable_loganalyzer
]

DESTINATION_PREFIX = 150
ENDPOINT_PREFIX = 100
VNI = 8000
VXLAN_DST_PORT = 4789
LOOPBACK = "loopback"
LOOPBACK_V4 = LOOPBACK + "_v4"
LOOPBACK_V6 = LOOPBACK + "_v6"
SPECIAL = "special"
SPECIAL_V4 = SPECIAL + "_v4"
SPECIAL_V6 = SPECIAL + "_v6"
VXLAN_HEADER_SIZE = len(packet.Ether()) + len(packet.IP()) + len(packet.UDP()) + len(packet.VXLAN())
VXLANV6_HEADER_SIZE = len(packet.Ether()) + len(packet.IPv6()) + len(packet.UDP()) + len(packet.VXLAN())

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


@pytest.fixture(scope="module", autouse=True)
def setup_ecmp_utils():
    # Need to set these constants before calling any ecmp_utils function.
    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True
    ecmp_utils.Constants["DUT_HOSTID"] = 1


@pytest.fixture(scope="module")
def configure_vxlan_global(duthost):
    """
        Fixture to configure global VxLAN parameters before a test and restore previous values after the test.
    """
    logger.info("Configuring global VxLAN parameters...")
    prev_vxlan_port = duthost.shell("sonic-db-cli APPL_DB HGET 'SWITCH_TABLE:switch' 'vxlan_port'")["stdout"].strip()
    prev_vxlan_router_mac = \
        duthost.shell("sonic-db-cli APPL_DB HGET 'SWITCH_TABLE:switch' 'vxlan_router_mac'")["stdout"].strip()
    router_mac = duthost.facts["router_mac"]
    ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=VXLAN_DST_PORT, dutmac=router_mac)
    yield
    if prev_vxlan_port:
        ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=int(prev_vxlan_port), dutmac=prev_vxlan_router_mac)
    else:
        ecmp_utils.configure_vxlan_switch(duthost, dutmac=prev_vxlan_router_mac)
        duthost.shell("sonic-db-cli APPL_DB HDEL 'SWITCH_TABLE:switch' 'vxlan_port'")
    if not prev_vxlan_router_mac:
        duthost.shell("sonic-db-cli APPL_DB HDEL 'SWITCH_TABLE:switch' 'vxlan_router_mac'")


def are_all_vxlan_tunnels_in_app_db(duthost, vxlan_tunnels, check_exist=True):
    """
        If check_exist is True, checks if all VxLAN tunnels in vxlan_tunnels are present in APP DB.
        If check_exist is False, checks if none of the VxLAN tunnels in vxlan_tunnels are present in APP DB.
    """
    for vxlan_tunnel in vxlan_tunnels:
        result = duthost.shell(f"sonic-db-cli APPL_DB KEYS 'VXLAN_TUNNEL_TABLE:{vxlan_tunnel}'")["stdout"].strip()
        if check_exist ^ bool(result):
            return False
    return True


def are_vxlan_tunnels_in_asic_db(duthost, count):
    """
        Function to check if at least <count> VxLAN tunnels are present in ASIC DB.
    """
    tunnel_keys = duthost.shell("sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL:oid*'")["stdout_lines"]
    matched = 0
    for key in tunnel_keys:
        tunnel_type = duthost.shell(f"sonic-db-cli ASIC_DB HGET '{key}' 'SAI_TUNNEL_ATTR_TYPE'")["stdout"].strip()
        if tunnel_type == "SAI_TUNNEL_TYPE_VXLAN":
            matched += 1
    return matched >= count


def is_no_vxlan_tunnel_in_asic_db(duthost):
    """
        Function to check if no VxLAN tunnel is present in ASIC DB.
    """
    tunnel_keys = duthost.shell("sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL:oid*'")["stdout_lines"]
    for key in tunnel_keys:
        tunnel_type = duthost.shell(f"sonic-db-cli ASIC_DB HGET '{key}' 'SAI_TUNNEL_ATTR_TYPE'")["stdout"].strip()
        if tunnel_type == "SAI_TUNNEL_TYPE_VXLAN":
            return False
    return True


def are_vnet_routes_in_asic_db(duthost, dests, check_exist=True):
    '''
        If check_exist is True, check if a VNET route to each dest in dests is present in ASIC DB.
        If check_exist is False, check if no VNET route to any dest in dests is present in ASIC DB.
    '''
    for dest in dests:
        result = duthost.shell(f"sonic-db-cli ASIC_DB KEYS \
                               'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY*{dest}*'")["stdout_lines"]  # noqa: E231
        if check_exist ^ bool(result):
            return False
    return True


def create_loopback_vxlan_tunnel(duthost, mg_facts, ip_version):
    loopback_ip = ecmp_utils.get_dut_loopback_address(duthost, mg_facts, ip_version)
    ecmp_utils.create_vxlan_tunnel(duthost, mg_facts, ip_version,
                                   tunnel_name=f"{LOOPBACK}_{ip_version}", src_ip=loopback_ip)
    return loopback_ip


@pytest.fixture(scope="module")
def create_vxlan_tunnels(duthost, tbinfo, configure_vxlan_global):  # noqa F811
    """
        Fixture to configure 2 IPv4 and 2 IPv6 VxLAN tunnels before a test and remove them after the test.
    """
    logger.info("Creating VxLAN tunnels...")
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    tunnels = {}  # From tunnel name to src IP

    loopback_ipv4 = create_loopback_vxlan_tunnel(duthost, minigraph_facts, "v4")
    tunnels[LOOPBACK_V4] = loopback_ipv4

    loopback_ipv4_parts = loopback_ipv4.split('.')
    # Create a second IPv4 tunnel with a slightly different source IP
    if loopback_ipv4_parts[-1] == "100":
        loopback_ipv4_parts[-1] = "101"
    else:
        loopback_ipv4_parts[-1] = "100"
    special_ipv4 = '.'.join(loopback_ipv4_parts)
    ecmp_utils.create_vxlan_tunnel(duthost, minigraph_facts, "v4",
                                   tunnel_name=SPECIAL_V4, src_ip=special_ipv4)
    tunnels[SPECIAL_V4] = special_ipv4

    # We will not configure IPv6 VxLAN tunnels on Mellanox devices due to a known issue.
    if duthost.facts["asic_type"] != "mellanox":
        loopback_ipv6 = create_loopback_vxlan_tunnel(duthost, minigraph_facts, "v6")
        tunnels[LOOPBACK_V6] = loopback_ipv6
        # Create a second IPv6 tunnel with a slightly different source IP
        loopback_ipv6_parts = loopback_ipv6.split(':')
        if loopback_ipv6_parts[-1] == "100":
            loopback_ipv6_parts[-1] = "101"
        else:
            loopback_ipv6_parts[-1] = "100"
        special_ipv6 = ':'.join(loopback_ipv6_parts)
        ecmp_utils.create_vxlan_tunnel(duthost, minigraph_facts, "v6",
                                       tunnel_name=SPECIAL_V6, src_ip=special_ipv6)
        tunnels[SPECIAL_V6] = special_ipv6

    pytest_assert(wait_until(10, 2, 0, are_all_vxlan_tunnels_in_app_db, duthost, tunnels.keys(), True),
                  "VxLAN tunnels are not created in APP DB.")
    yield tunnels
    # Clean-up
    for vxlan_tunnel in tunnels.keys():
        duthost.shell(f"sonic-db-cli CONFIG_DB DEL \"VXLAN_TUNNEL|{vxlan_tunnel}\"")
    pytest_assert(wait_until(10, 2, 0, are_all_vxlan_tunnels_in_app_db, duthost, tunnels.keys(), False),
                  "VxLAN tunnels are not removed from APP DB.")


@pytest.fixture(scope="module")
def create_vnets(duthost, create_vxlan_tunnels):  # noqa F811
    """
        Fixture to configure one VNet for each VxLAN tunnel before a test and remove them after the test.
    """
    logger.info("Creating VNets...")
    vnets = {}

    vnet_dict = ecmp_utils.create_vnets(duthost, LOOPBACK_V4, vnet_count=1, scope="default",
                                        vni_base=VNI, vnet_name_prefix=LOOPBACK_V4)
    vnets[LOOPBACK_V4] = next(iter(vnet_dict))

    vnet_dict = ecmp_utils.create_vnets(duthost, SPECIAL_V4, vnet_count=1, scope="default",
                                        vni_base=VNI, vnet_name_prefix=SPECIAL_V4)
    vnets[SPECIAL_V4] = next(iter(vnet_dict))

    if duthost.facts["asic_type"] != "mellanox":
        vnet_dict = ecmp_utils.create_vnets(duthost, LOOPBACK_V6, vnet_count=1, scope="default",
                                            vni_base=VNI, vnet_name_prefix=LOOPBACK_V6)
        vnets[LOOPBACK_V6] = next(iter(vnet_dict))

        vnet_dict = ecmp_utils.create_vnets(duthost, SPECIAL_V6, vnet_count=1, scope="default",
                                            vni_base=VNI, vnet_name_prefix=SPECIAL_V6)
        vnets[SPECIAL_V6] = next(iter(vnet_dict))

    pytest_assert(wait_until(10, 2, 0, are_vxlan_tunnels_in_asic_db, duthost, 4),
                  "VxLAN tunnels are not created in ASIC DB.")
    yield vnets
    # Clean-up
    for vnet in vnets.values():
        duthost.shell(f"sonic-db-cli CONFIG_DB DEL \"VNET|{vnet}\"")
    pytest_assert(wait_until(10, 2, 0, is_no_vxlan_tunnel_in_asic_db, duthost),
                  "VxLAN tunnels are not removed from ASIC DB.")


@pytest.fixture(scope="module")
def create_vnet_routes(duthost, create_vnets):
    """
        Fixture to create 2 VNet routes for each loopback VNet (4 routes in total) before a test
        and remove them after the test.
        For each loopback VNet, 2 routes are created: One with an IPv4 dest and one with an IPv6 dest.
        Each route has one endpoint (nexthop).
    """
    logger.info("Creating VNet routes...")
    vnets = create_vnets
    # route_map = {LOOPBACK_V4: {"v4": {dest_v4_1: [nh_v4_1]}, "v6": {dest_v6_1: [nh_v4_2]}},
    #              LOOPBACK_V6: {"v4": {dest_v4_2: [nh_v6_1]}, "v6": {dest_v6_2: [nh_v6_2]}}
    route_map = {}
    route_map[LOOPBACK_V4] = {}
    dests = []
    vnet_route_map_v4_v4 = ecmp_utils.create_vnet_routes(duthost, [vnets[LOOPBACK_V4]], nhs_per_destination=1,
                                                         number_of_available_nexthops=1,
                                                         number_of_ecmp_nhs=1, dest_af="v4",
                                                         dest_net_prefix=DESTINATION_PREFIX,
                                                         nexthop_prefix=ENDPOINT_PREFIX,
                                                         nh_af="v4")
    route_map[LOOPBACK_V4]["v4"] = vnet_route_map_v4_v4[vnets[LOOPBACK_V4]]
    dests.append(next(iter(route_map[LOOPBACK_V4]["v4"])))

    vnet_route_map_v6_v4 = ecmp_utils.create_vnet_routes(duthost, [vnets[LOOPBACK_V4]], nhs_per_destination=1,
                                                         number_of_available_nexthops=1,
                                                         number_of_ecmp_nhs=1, dest_af="v6",
                                                         dest_net_prefix=DESTINATION_PREFIX,
                                                         nexthop_prefix=ENDPOINT_PREFIX,
                                                         nh_af="v4")
    route_map[LOOPBACK_V4]["v6"] = vnet_route_map_v6_v4[vnets[LOOPBACK_V4]]
    dests.append(next(iter(route_map[LOOPBACK_V4]["v6"])))

    if duthost.facts["asic_type"] != "mellanox":
        route_map[LOOPBACK_V6] = {}
        vnet_route_map_v4_v6 = ecmp_utils.create_vnet_routes(duthost, [vnets[LOOPBACK_V6]], nhs_per_destination=1,
                                                             number_of_available_nexthops=1,
                                                             number_of_ecmp_nhs=1, dest_af="v4",
                                                             dest_net_prefix=DESTINATION_PREFIX,
                                                             nexthop_prefix=ENDPOINT_PREFIX,
                                                             nh_af="v6")
        route_map[LOOPBACK_V6]["v4"] = vnet_route_map_v4_v6[vnets[LOOPBACK_V6]]
        dests.append(next(iter(route_map[LOOPBACK_V6]["v4"])))

        vnet_route_map_v6_v6 = ecmp_utils.create_vnet_routes(duthost, [vnets[LOOPBACK_V6]], nhs_per_destination=1,
                                                             number_of_available_nexthops=1,
                                                             number_of_ecmp_nhs=1, dest_af="v6",
                                                             dest_net_prefix=DESTINATION_PREFIX,
                                                             nexthop_prefix=ENDPOINT_PREFIX,
                                                             nh_af="v6")
        route_map[LOOPBACK_V6]["v6"] = vnet_route_map_v6_v6[vnets[LOOPBACK_V6]]
        dests.append(next(iter(route_map[LOOPBACK_V6]["v6"])))

    pytest_assert(wait_until(10, 2, 0, are_vnet_routes_in_asic_db, duthost, dests, True),
                  "VNet routes are not created in ASIC DB.")
    yield route_map
    # Clean-up
    ecmp_utils.set_routes_in_dut(duthost, vnet_route_map_v4_v4, "v4", "DEL")
    ecmp_utils.set_routes_in_dut(duthost, vnet_route_map_v6_v4, "v6", "DEL")
    if duthost.facts["asic_type"] != "mellanox":
        ecmp_utils.set_routes_in_dut(duthost, vnet_route_map_v4_v6, "v4", "DEL")
        ecmp_utils.set_routes_in_dut(duthost, vnet_route_map_v6_v6, "v6", "DEL")
    pytest_assert(wait_until(10, 2, 0, are_vnet_routes_in_asic_db, duthost, dests, False),
                  "VNet routes are not removed from ASIC DB.")


def select_ingress_port(duthost):
    """
        Returns the name of an oper UP Ethernet interface to be used as ingress port in tests.
    """
    interfaces_status = duthost.show_interface(command="status")["ansible_facts"]["int_status"]
    for intf, info in interfaces_status.items():
        if info["oper_state"].lower() == "up" and intf.startswith("Ethernet"):
            logger.info(f"Selected {intf} as ingress port.")
            return intf
    pytest.skip("No oper UP Ethernet interface found on the DUT to be used as ingress port.")


def get_inner_packet(ip_version, dst_ip):
    if ip_version == "v4":
        return testutils.simple_udp_packet(ip_dst=dst_ip)
    else:
        return testutils.simple_udpv6_packet(ipv6_dst=dst_ip)


def get_outer_packet(dst_mac, src_mac, ip_version, dst_ip, inner_frame):
    if ip_version == "v4":
        return testutils.simple_vxlan_packet(eth_dst=dst_mac, eth_src=src_mac, ip_dst=dst_ip,
                                             udp_dport=VXLAN_DST_PORT, vxlan_vni=VNI, inner_frame=inner_frame)
    else:
        return testutils.simple_vxlanv6_packet(eth_dst=dst_mac, eth_src=src_mac, ipv6_dst=dst_ip,
                                               udp_dport=VXLAN_DST_PORT, vxlan_vni=VNI, inner_frame=inner_frame)


def get_expected_outer_packet_mask_ipv4(src_mac, src_ip, dst_ip, inner_frame):
    exp_pkt = testutils.simple_vxlan_packet(eth_src=src_mac, ip_dst=dst_ip, ip_src=src_ip,
                                            udp_dport=VXLAN_DST_PORT, vxlan_vni=VNI, inner_frame=inner_frame.copy())
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
    # inner_frame will be checked separately
    exp_pkt_mask.set_do_not_care(VXLAN_HEADER_SIZE * 8, len(inner_frame) * 8)
    return exp_pkt_mask


def get_expected_outer_packet_mask_ipv6(src_mac, src_ipv6, dst_ipv6, inner_frame):
    exp_pkt = testutils.simple_vxlanv6_packet(eth_src=src_mac, ipv6_dst=dst_ipv6, ipv6_src=src_ipv6,
                                              udp_dport=VXLAN_DST_PORT, vxlan_vni=VNI, inner_frame=inner_frame.copy())
    exp_pkt_mask = Mask(exp_pkt)
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "tc")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "fl")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "hlim")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "sport")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "chksum")
    # inner_frame will be checked separately
    exp_pkt_mask.set_do_not_care(VXLANV6_HEADER_SIZE * 8, len(inner_frame) * 8)
    return exp_pkt_mask


def get_expected_outer_packet_mask(outer_ip_version, src_mac, src_ip, dst_ip, inner_frame):
    if outer_ip_version == "v4":
        return get_expected_outer_packet_mask_ipv4(src_mac, src_ip, dst_ip, inner_frame)
    else:
        return get_expected_outer_packet_mask_ipv6(src_mac, src_ip, dst_ip, inner_frame)


def extract_payload(outer_pkt_bytes, outer_ip_version):
    outer_header_size = VXLAN_HEADER_SIZE if outer_ip_version == "v4" else VXLANV6_HEADER_SIZE
    inner_frame_bytes = outer_pkt_bytes[outer_header_size:]
    return packet.Ether(inner_frame_bytes)


def get_expected_inner_packet_mask_ipv4(original_inner_pkt, new_src_mac):
    exp_inner_pkt = original_inner_pkt.copy()
    exp_inner_pkt["Ether"].src = new_src_mac
    exp_inner_pkt["IP"].ttl -= 1

    exp_inner_pkt_mask = Mask(exp_inner_pkt)
    exp_inner_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_inner_pkt_mask.set_do_not_care_packet(packet.IP, "ihl")
    exp_inner_pkt_mask.set_do_not_care_packet(packet.IP, "tos")
    exp_inner_pkt_mask.set_do_not_care_packet(packet.IP, "id")
    exp_inner_pkt_mask.set_do_not_care_packet(packet.IP, "flags")
    exp_inner_pkt_mask.set_do_not_care_packet(packet.IP, "chksum")
    return exp_inner_pkt_mask


def get_expected_inner_packet_mask_ipv6(original_inner_pkt, new_src_mac):
    exp_inner_pkt = original_inner_pkt.copy()
    exp_inner_pkt["Ether"].src = new_src_mac
    exp_inner_pkt["IPv6"].hlim -= 1

    exp_inner_pkt_mask = Mask(exp_inner_pkt)
    exp_inner_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_inner_pkt_mask.set_do_not_care_packet(packet.IPv6, "tc")
    exp_inner_pkt_mask.set_do_not_care_packet(packet.IPv6, "fl")
    return exp_inner_pkt_mask


def get_expected_inner_packet_mask(original_inner_pkt, ip_version, new_src_mac):
    if ip_version == "v4":
        return get_expected_inner_packet_mask_ipv4(original_inner_pkt, new_src_mac)
    else:
        return get_expected_inner_packet_mask_ipv6(original_inner_pkt, new_src_mac)


@pytest.fixture(params=[LOOPBACK_V4, LOOPBACK_V6], ids=[f"route_{LOOPBACK_V4}", f"route_{LOOPBACK_V6}"])
def inner_pkt_vnet_route_vxlan(request):
    """
        The inner packet will be crafted to match one of the two VNET routes for this VxLAN tunnel.
        The VNET route is chosen based on the inner packet's IP version (inner_ip_version).
    """
    return request.param


@pytest.fixture(params=[LOOPBACK_V4, LOOPBACK_V6, SPECIAL_V4, SPECIAL_V6],
                ids=[f"outer_{LOOPBACK_V4}", f"outer_{LOOPBACK_V6}", f"outer_{SPECIAL_V4}", f"outer_{SPECIAL_V6}"])
def outer_pkt_vxlan(request):
    """
        The outer packet will be crafted to match this VxLAN tunnel.
    """
    return request.param


@pytest.fixture(params=["v4", "v6"], ids=["inner_ipv4", "inner_ipv6"])
def inner_ip_version(request):
    return request.param


def test_vxlan_multiple_tunnels(duthost, tbinfo, ptfadapter, create_vxlan_tunnels, create_vnet_routes,
                                inner_pkt_vnet_route_vxlan, outer_pkt_vxlan, inner_ip_version):
    """
        In this test, we send a VxLAN-encapsulated packet to the DUT:
            - Outer packet is from an arbitrary IP to one of the DUT's VxLAN src IPs.
            - Inner packet is from an arbitrary IP to one of the DUT's VNET route destinations.
        We expect the DUT to decapsulate the packet and then send out a new VxLAN packet in which:
            - Outer packet is from the VxLAN src IP (that is associated with the original inner packet's VNET route)
              to the VNET route's endpoint (nexthop) IP.
            - Inner packet is essentially the same as the original inner packet
              (except for fields such as IP TTL, src MAC, IP checksum, etc.).
    """
    outer_ip_version = outer_pkt_vxlan[-2:]  # "v4" or "v6"
    if duthost.facts["asic_type"] == "mellanox" and outer_ip_version == "v6":
        pytest.skip("Outer IPv6 tests are skipped on Mellanox.")

    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    port_to_ptf_index = minigraph_facts["minigraph_port_indices"]
    ingress_port = select_ingress_port(duthost)
    ptf_src_mac = ptfadapter.dataplane.get_mac(0, port_to_ptf_index[ingress_port])
    router_mac = duthost.facts["router_mac"]
    tunnel_to_src_ip = create_vxlan_tunnels
    route_dest_to_nh = create_vnet_routes
    vnet_route_dst_ip = next(iter(route_dest_to_nh[inner_pkt_vnet_route_vxlan][inner_ip_version]))
    vnet_route_endpoint = route_dest_to_nh[inner_pkt_vnet_route_vxlan][inner_ip_version][vnet_route_dst_ip][0]
    vxlan_tunnel_src_ip = tunnel_to_src_ip[outer_pkt_vxlan]

    inner_pkt = get_inner_packet(ip_version=inner_ip_version, dst_ip=vnet_route_dst_ip)
    outer_pkt = get_outer_packet(dst_mac=router_mac, src_mac=ptf_src_mac, ip_version=outer_ip_version,
                                 dst_ip=vxlan_tunnel_src_ip, inner_frame=inner_pkt)

    # The new outer packet has the same IP version as the src IP of the VNET route's associated VxLAN.
    exp_outer_ip_version = inner_pkt_vnet_route_vxlan[-2:]
    exp_outer_src_ip = tunnel_to_src_ip[inner_pkt_vnet_route_vxlan]
    exp_outer_pkt_mask = get_expected_outer_packet_mask(exp_outer_ip_version, src_mac=router_mac,
                                                        src_ip=exp_outer_src_ip, dst_ip=vnet_route_endpoint,
                                                        inner_frame=inner_pkt)

    all_ptf_indices = list(port_to_ptf_index.values())
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, port_to_ptf_index[ingress_port], outer_pkt)

    # Verify that the expected VxLAN packet is captured on any port
    _, received_pkt = testutils.verify_packet_any_port(ptfadapter, exp_outer_pkt_mask, all_ptf_indices)
    logger.info(f"Received packet: \n{packet.Ether(received_pkt)}\n")

    # Verify that the payload of the captured VxLAN packet is correct
    captured_inner_pkt = extract_payload(received_pkt, exp_outer_ip_version)
    # testutils.send updates the payload of outer_pkt and then sends it.
    # So we need to extract the inner packet from the modified outer_pkt.
    original_inner_pkt = extract_payload(bytes(outer_pkt), outer_ip_version)
    exp_inner_pkt_mask = get_expected_inner_packet_mask(original_inner_pkt, inner_ip_version, new_src_mac=router_mac)
    pytest_assert(exp_inner_pkt_mask.pkt_match(captured_inner_pkt),
                  "The captured inner packet is not as expected.")
