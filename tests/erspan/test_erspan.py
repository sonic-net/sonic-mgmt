'''
Test ERSPAN packet mirroring
Note: The tests are not designed to be run on T2 switches.
'''

import pytest
import ptf.testutils as testutils
import time
import ptf.packet as packet
import binascii
import logging

from ptf.mask import Mask
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)


# Parameters used to setup and test an ERSPAN mirroring session.
# src_ip and dst_ip are used in the outer IP header in GRE packets, while tx_dst_ip is used as the destination IP
# of the ICMP packets for TX tests.
session_params = {"src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "dscp": 8, "ttl": 4, "queue": 0,
                  "src_ipv6": "fc00::1:1:1:1", "dst_ipv6": "fc00::2:2:2:2", "tx_dst_ip": "3.3.3.3"}

# DUT's hardware information are stored here so that we avoid retrieving them
# over and over again and passing them around as arguments.
asic_type = ""
platform_asic = ""
hwsku = ""

# Size of the header of the IPv4 encapsulated packet
TOTAL_HEADER_SIZE = len(packet.Ether()) + len(packet.IP()) + len(packet.GRE())
# Size of the header of the IPv6 encapsulated packet
TOTAL_HEADER_SIZE_V6 = len(packet.Ether()) + len(packet.IPv6()) + len(packet.GRE())


def get_hardware_info(duthost):
    global asic_type, platform_asic, hwsku
    asic_type = duthost.facts["asic_type"]
    platform_asic = duthost.facts.get("platform_asic")
    hwsku = duthost.facts["hwsku"]
    logger.info(f"asic_type={asic_type}, platform_asic={platform_asic}, hwsku={hwsku}")


def select_tx_src_port(intfs_status, except_ports=[]):
    """
    Returns an Ethernet port that is operationally up and is not a member of except_ports.
    """
    src_port = ""
    for port, info in intfs_status.items():
        if info["oper"] == "up" and port.startswith("Ethernet") and port not in except_ports:
            src_port = port
            break
    return src_port


def select_ip_ethernet(ip_intfs, ipv6_intfs, except_ports=[]):
    """
    Finds an Ethernet port with an IP address that is operationally up, is connected to a
    neighbor with both IPv4 and IPv6 addresses, and is not included in except_ports.
    Returns the port's name and its neighbor's IPv4 and IPv6 addresses.
    """
    selected_port = ""
    ipv4 = ""
    ipv6 = ""
    for intf, info in ip_intfs.items():
        if info["oper_state"] == "up" and info["peer_ipv4"] != "N/A" \
           and ipv6_intfs[intf]["neighbor ip"] != "N/A" \
           and intf.startswith("Ethernet") \
           and intf not in except_ports:
            selected_port = intf
            ipv4 = info["peer_ipv4"]
            ipv6 = ipv6_intfs[intf]["neighbor ip"]
            break
    return (selected_port, ipv4, ipv6)


def select_portchannel(ip_intfs, ipv6_intfs, portchannel_table, except_ports=[]):
    """
    Finds a PortChannel interface with an IP address that is operationally up, is connected to a
    neighbor with both IPv4 and IPv6 addresses and does not have any port in except_ports as its member.
    Returns the interface's name and its neighbor's IPv4 and IPv6 addresses.
    """
    selected_intf = ""
    ipv4 = ""
    ipv6 = ""
    except_ports = set(except_ports)
    for intf, info in ip_intfs.items():
        if info["oper_state"] == "up" and info["peer_ipv4"] != "N/A" \
           and ipv6_intfs[intf]["neighbor ip"] != "N/A" \
           and intf.startswith("PortChannel") \
           and not (set(portchannel_table[intf]["ports"]) & except_ports):
            selected_intf = intf
            ipv4 = info["peer_ipv4"]
            ipv6 = ipv6_intfs[intf]["neighbor ip"]
            break
    return (selected_intf, ipv4, ipv6)


def select_monitor_ports(ip_intfs, ipv6_intfs, portchannel_table, except_ports=[]):
    """
    Finds a suitable list of monitor ports. The ERSPAN sessions and the routing table will
    be configured such that mirrored packets will be sent on one of these monitor ports.
    Returns the list of monitor ports along with their neighbor's IPv4 and IPv6 addresses.
    """
    selected_intf, ipv4, ipv6 = select_ip_ethernet(ip_intfs, ipv6_intfs, except_ports)
    if selected_intf:
        return ([selected_intf], ipv4, ipv6)
    else:
        selected_intf, ipv4, ipv6 = select_portchannel(ip_intfs, ipv6_intfs, portchannel_table, except_ports)
        if not selected_intf:
            return ([], "", "")
        member_ports = portchannel_table[selected_intf]["ports"]
        return (member_ports, ipv4, ipv6)


def select_mirrored_ports(ip_intfs, ipv6_intfs, portchannel_table, intfs_status):
    """
    Finds a suitable mirrored interface on the DUT, which will be used for both RX and TX tests.
    Returns the mirrored interface's operationally UP member ports and the IPv4 address of its neighbor.
    """
    selected_intf, ipv4, _ = select_ip_ethernet(ip_intfs, ipv6_intfs)
    if selected_intf:
        return ([selected_intf], ipv4)
    else:
        selected_intf, ipv4, _ = select_portchannel(ip_intfs, ipv6_intfs, portchannel_table)
        if not selected_intf:
            return ([], "")
        member_ports = portchannel_table[selected_intf]["ports"]
        up_ports = []
        for port in member_ports:
            if intfs_status[port]["oper"] == "up":
                up_ports.append(port)
        assert len(up_ports) >= 1  # At least one member port must be UP (otherwise, the PortChannel would be down).
        return (up_ports, ipv4)


@pytest.fixture(scope="module")
def get_erspan_session_info(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Computes all parameters used to establish ERSPAN sessions and stores them in session_params.
    """
    duthost = duthosts[rand_one_dut_hostname]
    ptf_indices = duthost.get_extended_minigraph_facts(tbinfo)["minigraph_ptf_indices"]
    intfs_status = duthost.get_interfaces_status()
    ip_intfs = duthost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
    ipv6_intfs = duthost.show_ipv6_interfaces()
    portchannel_table = duthost.show_interfaces_portchannel()

    get_hardware_info(duthost)
    if asic_type == "mellanox":
        session_params["gre_proto"] = 0x8949
    elif asic_type == "barefoot":
        session_params["gre_proto"] = 0x22eb
    else:
        session_params["gre_proto"] = 0x88be

    mirrored_ports, mirrored_neigh_ip = select_mirrored_ports(ip_intfs, ipv6_intfs, portchannel_table, intfs_status)
    logger.info(f"Mirrored ports: {mirrored_ports}")
    if not mirrored_ports:
        pytest.skip("No suitable mirrored port could be found on the DUT.")
    session_params["mirrored_ports"] = mirrored_ports
    session_params["mirrored_ports_indices"] = [ptf_indices[port] for port in mirrored_ports]
    session_params["mirrored_neigh_ip"] = mirrored_neigh_ip
    used_ports = mirrored_ports[:]

    tx_src_port = select_tx_src_port(intfs_status, except_ports=used_ports)
    logger.info(f"src port used in TX tests: {tx_src_port}")
    # TX tests will be skipped later if no suitable tx_src_port could be found.
    if tx_src_port:
        session_params["tx_src_port"] = tx_src_port
        session_params["tx_src_port_idx"] = ptf_indices[tx_src_port]
        used_ports.append(tx_src_port)

    session_params["router_mac"] = duthost.facts["router_mac"]

    monitor_ports, monitor_neigh_ip, monitor_neigh_ipv6 = select_monitor_ports(ip_intfs, ipv6_intfs,
                                                                               portchannel_table,
                                                                               except_ports=used_ports)
    logger.info(f"Monitor ports: {monitor_ports}")
    if not monitor_ports:
        pytest.skip("No suitable neighbor found to route mirrored packets through.")
    session_params["monitor_ports_indices"] = [ptf_indices[monitor_port] for monitor_port in monitor_ports]
    session_params["monitor_neigh_ipv4"] = monitor_neigh_ip
    session_params["monitor_neigh_ipv6"] = monitor_neigh_ipv6


@pytest.fixture(scope="module")
def shutdown_bgp(duthosts, rand_one_dut_hostname):
    """
    Shuts down BGP so that only the static routes that we add are considered.
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command("sudo config bgp shutdown all")
    time.sleep(60)
    yield
    duthost.command("sudo config bgp startup all")
    time.sleep(60)


@pytest.fixture(scope="module")
def add_static_tx_route(duthosts, rand_one_dut_hostname, get_erspan_session_info, shutdown_bgp):  # noqa 811
    """
    Adds a static route to session_params['tx_dst_ip'] to ensure that each ICMP packet is
    forwarded on one of the mirrored ports (for TX tests).
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command(f"sudo config route add prefix {session_params['tx_dst_ip']}/32 nexthop \
                      {session_params['mirrored_neigh_ip']}")
    yield
    duthost.command(f"sudo config route del prefix {session_params['tx_dst_ip']}/32 nexthop \
                      {session_params['mirrored_neigh_ip']}")


@pytest.fixture(scope="module")
def add_static_mirror_route_ipv4(duthosts, rand_one_dut_hostname, add_static_tx_route):  # noqa F811
    """
    Adds a static route to session_params['dst_ip'] to ensure that each encapsulated packet
    containing the mirrored packet is sent out on one of the monitor ports.
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command(f"sudo config route add prefix {session_params['dst_ip']}/32 nexthop \
                      {session_params['monitor_neigh_ipv4']}")
    yield
    duthost.command(f"sudo config route del prefix {session_params['dst_ip']}/32 nexthop \
                      {session_params['monitor_neigh_ipv4']}")


@pytest.fixture(scope="module")
def add_static_mirror_route_ipv6(duthosts, rand_one_dut_hostname, add_static_tx_route):  # noqa F811
    """
    Adds a static route to session_params['dst_ip'] to ensure that each encapsulated packet
    containing the mirrored packet is sent out on one of the monitor ports.
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command(f"sudo config route add prefix {session_params['dst_ipv6']}/128 nexthop \
                      {session_params['monitor_neigh_ipv6']}")
    yield
    duthost.command(f"sudo config route del prefix {session_params['dst_ipv6']}/128 nexthop \
                      {session_params['monitor_neigh_ipv6']}")


@pytest.fixture
def setup_erspan_ipv4(request, duthosts, rand_one_dut_hostname, add_static_mirror_route_ipv4):  # noqa F811
    """
    Sets up an IPv4 ERSPAN mirroring session.
    """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command(f"sudo config mirror_session erspan add erspan_test {session_params['src_ip']} \
                    {session_params['dst_ip']} {session_params['dscp']} {session_params['ttl']} \
                    {session_params['gre_proto']} {session_params['queue']} \
                    {','.join(session_params['mirrored_ports'])} {request.param}")
    time.sleep(10)  # Wait for the session to become active
    yield request.param
    duthost.command("sudo config mirror_session remove erspan_test")


@pytest.fixture
def setup_erspan_ipv6(request, duthosts, rand_one_dut_hostname, add_static_mirror_route_ipv6):  # noqa F811
    """
    Sets up an IPv6 ERSPAN mirroring session.
    """
    if asic_type == "broadcom":
        pytest.skip("Broadcom does not support IPv6 ERSPAN mirroring.")
    duthost = duthosts[rand_one_dut_hostname]
    # Directly add the ERSPAN session to CONFIG_DB since "sudo config mirror_session erspan" currently does not
    # accept IPv6 addresses.
    duthost.command(f"sonic-db-cli CONFIG_DB HSET 'MIRROR_SESSION|erspan_test6' \
                      'direction' '{request.param.upper()}' 'dscp' '{session_params['dscp']}' \
                      'dst_ip' '{session_params['dst_ipv6']}' 'gre_type' '{session_params['gre_proto']}' \
                      'queue' '{session_params['queue']}' 'src_ip' '{session_params['src_ipv6']}' \
                      'src_port' '{','.join(session_params['mirrored_ports'])}' \
                      'ttl' '{session_params['ttl']}' 'type' 'ERSPAN'")
    time.sleep(10)  # Wait for the session to become active
    yield request.param
    duthost.command("sonic-db-cli CONFIG_DB DEL 'MIRROR_SESSION|erspan_test6'")


def get_vendor_specific_padding():
    """
    Returns the vendor-specific padding that is added to the mirroed packet (payload) inside the GRE packet.
    """
    if asic_type == "mellanox":
        return 22
    elif (asic_type in ["barefoot", "cisco-8000", "marvell-teralynx"]
          or platform_asic == "broadcom-dnx"
          or hwsku in ["rd98DX35xx", "rd98DX35xx_cn9131", "Nokia-7215-A1"]):
        return 12
    else:
        return 0


def copy_and_pad(pkt):
    payload = pkt.copy()
    # Add vendor-specific padding to the packet
    padding_len = get_vendor_specific_padding()
    payload = binascii.unhexlify("0" * (padding_len * 2)) + bytes(payload)
    return payload


def get_expected_encapsulated_packet_ipv4(pkt):
    """
    Returns the expected GRE packet containing the mirror of pkt.
    Note: The payload of the GRE packet (i.e., the mirror of pkt) is masked because we will check it separately.
    """
    payload = copy_and_pad(pkt)

    expected_encap_pkt = testutils.simple_gre_packet(
        ip_src=session_params["src_ip"],
        ip_dst=session_params["dst_ip"],
        ip_dscp=session_params["dscp"],
        ip_id=0,
        ip_ttl=session_params["ttl"],
        inner_frame=payload
    )

    expected_encap_pkt["GRE"].proto = session_params["gre_proto"]
    expected_encap_pkt["Ether"].src = session_params["router_mac"]

    expected_encap_pkt = Mask(expected_encap_pkt)
    expected_encap_pkt.set_do_not_care_packet(packet.Ether, "dst")
    expected_encap_pkt.set_do_not_care_packet(packet.IP, "ihl")
    expected_encap_pkt.set_do_not_care_packet(packet.IP, "len")
    expected_encap_pkt.set_do_not_care_packet(packet.IP, "flags")
    expected_encap_pkt.set_do_not_care_packet(packet.IP, "chksum")
    if asic_type == 'marvell':
        expected_encap_pkt.set_do_not_care_packet(packet.IP, "id")
    # The fanout switch may modify "tos" en route to PTF, so we should ignore it even
    # though the session does have a DSCP specified.
    expected_encap_pkt.set_do_not_care_packet(packet.IP, "tos")

    if (asic_type in ["marvell", "cisco-8000", "marvell-teralynx"] or platform_asic == "broadcom-dnx"):
        expected_encap_pkt.set_do_not_care_packet(packet.GRE, "seqnum_present")

    # Mask the payload (we will check it later)
    expected_encap_pkt.set_do_not_care(TOTAL_HEADER_SIZE * 8, len(payload) * 8)

    return expected_encap_pkt


def get_expected_encapsulated_packet_ipv6(pkt):
    """
    Returns the expected GREv6 packet containing the mirror of pkt.
    Note: The payload of the GREv6 packet (i.e., the mirror of pkt) is masked because we will check it separately.
    """
    payload = copy_and_pad(pkt)

    expected_encap_pkt = testutils.simple_grev6_packet(
        ipv6_src=session_params["src_ipv6"],
        ipv6_dst=session_params["dst_ipv6"],
        ipv6_dscp=session_params["dscp"],
        ipv6_hlim=session_params["ttl"],
        inner_frame=payload
    )

    expected_encap_pkt["GRE"].proto = session_params["gre_proto"]
    expected_encap_pkt["Ether"].src = session_params["router_mac"]

    expected_encap_pkt = Mask(expected_encap_pkt)
    expected_encap_pkt.set_do_not_care_packet(packet.Ether, "dst")
    expected_encap_pkt.set_do_not_care_packet(packet.IPv6, "fl")
    expected_encap_pkt.set_do_not_care_packet(packet.IPv6, "plen")
    # The fanout switch may modify "tc" en route to PTF, so we should ignore it even
    # though the session does have a DSCP specified.
    expected_encap_pkt.set_do_not_care_packet(packet.IPv6, "tc")

    if (asic_type in ["marvell", "cisco-8000", "marvell-teralynx"] or platform_asic == "broadcom-dnx"):
        expected_encap_pkt.set_do_not_care_packet(packet.GRE, "seqnum_present")

    # Mask the payload (we will check it later)
    expected_encap_pkt.set_do_not_care(TOTAL_HEADER_SIZE_V6 * 8, len(payload) * 8)

    return expected_encap_pkt


def get_expected_encapsulated_packet(pkt, ipv6):
    if ipv6:
        return get_expected_encapsulated_packet_ipv6(pkt)
    else:
        return get_expected_encapsulated_packet_ipv4(pkt)


def extract_payload(encapsulated_pkt, total_header_len):
    """
    Extracts the inner packet inside the GRE(v6) packet.
    """
    pytest_assert(len(encapsulated_pkt) >= total_header_len,
                  f"Incomplete packet, expected at least {total_header_len} header bytes")
    padding_len = get_vendor_specific_padding()
    inner_frame = encapsulated_pkt[total_header_len + padding_len:]
    return packet.Ether(inner_frame)


def get_expected_mirror_packet(pkt, direction):
    """
    Returns the expected mirror packet mask.
    @param direction Can be "RX" or "TX"
    """
    if direction == "RX":
        # Received packet must be mirrored exactly.
        return Mask(pkt)
    elif direction == "TX":
        expected_pkt = pkt.copy()
        expected_pkt["Ether"].src = session_params["router_mac"]
        expected_pkt["IP"].ttl = pkt["IP"].ttl - 1
        expected_pkt = Mask(expected_pkt)
        expected_pkt.set_do_not_care_packet(packet.Ether, "dst")
        expected_pkt.set_do_not_care_packet(packet.IP, "ihl")
        expected_pkt.set_do_not_care_packet(packet.IP, "tos")
        expected_pkt.set_do_not_care_packet(packet.IP, "len")
        expected_pkt.set_do_not_care_packet(packet.IP, "id")
        expected_pkt.set_do_not_care_packet(packet.IP, "flags")
        expected_pkt.set_do_not_care_packet(packet.IP, "chksum")
        expected_pkt.set_do_not_care_packet(packet.ICMP, "chksum")
        return expected_pkt


def verify_encapsulated_packet(ptfadapter, pkt, direction, ipv6):
    """
    Verifies that the correct GRE(v6) packet is received on one of the monitor ports and
    that its inner packet matches pkt.
    @param direction Can be "RX" or "TX"
    """
    total_header_size = TOTAL_HEADER_SIZE if not ipv6 else TOTAL_HEADER_SIZE_V6
    gre = "GRE" if not ipv6 else "GREv6"

    logger.info(f"Original ICMP packet({direction}):\n{packet.hexdump(pkt, dump=True)}\n")
    expected_encap_pkt = get_expected_encapsulated_packet(pkt, ipv6)
    logger.info(f"Expected {gre} packet:\n{expected_encap_pkt}\n")
    _, encapsulated_pkt = testutils.verify_packet_any_port(ptfadapter, expected_encap_pkt,
                                                           ports=session_params["monitor_ports_indices"])
    logger.info(f"Captured {gre} packet:\n{packet.hexdump(encapsulated_pkt, dump=True)}\n")
    mirror_pkt = extract_payload(encapsulated_pkt, total_header_size)
    logger.info(f"Captured mirror packet:\n{packet.hexdump(mirror_pkt, dump=True)}\n")
    expected_mirror_pkt = get_expected_mirror_packet(pkt, direction)
    logger.info(f"Expected mirror packet:\n{expected_mirror_pkt}\n")
    pytest_assert(expected_mirror_pkt.pkt_match(mirror_pkt),
                  f"Mirror packet does not match the original {direction} packet.")


def run_test_erspan(ptfadapter, direction, ipv6):
    """
    @param direction Can be "rx", "tx", or "both"
    """
    if direction != "tx":
        # Testing RX mirroring
        src_mac = ptfadapter.dataplane.get_mac(0, session_params["mirrored_ports_indices"][0])
        pkt = testutils.simple_icmp_packet(eth_src=src_mac, eth_dst=session_params["router_mac"])
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, session_params["mirrored_ports_indices"][0], pkt)
        verify_encapsulated_packet(ptfadapter, pkt, "RX", ipv6)

    if direction != "rx":
        # Testing TX mirroring
        if "tx_src_port" not in session_params.keys():
            pytest.skip("No suitable source port could be found on the DUT for TX tests.")
        src_mac = ptfadapter.dataplane.get_mac(0, session_params["tx_src_port_idx"])
        pkt = testutils.simple_icmp_packet(eth_src=src_mac, eth_dst=session_params["router_mac"],
                                           ip_dst=session_params["tx_dst_ip"])
        ptfadapter.dataplane.flush()
        testutils.send(ptfadapter, session_params["tx_src_port_idx"], pkt)
        verify_encapsulated_packet(ptfadapter, pkt, "TX", ipv6)


@pytest.mark.parametrize("setup_erspan_ipv4", ["rx", "tx", "both"], indirect=True)
def test_erspan_ipv4(ptfadapter, setup_erspan_ipv4):
    direction = setup_erspan_ipv4
    run_test_erspan(ptfadapter, direction, ipv6=False)


@pytest.mark.parametrize("setup_erspan_ipv6", ["rx", "tx", "both"], indirect=True)
def test_erspan_ipv6(ptfadapter, setup_erspan_ipv6):
    direction = setup_erspan_ipv6
    run_test_erspan(ptfadapter, direction, ipv6=True)
