import pytest
import logging
import ptf.testutils as testutils
import ptf.packet as packet

from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from ptf.mask import Mask


pytestmark = [
    pytest.mark.topology("t0", "t1"),
    pytest.mark.disable_loganalyzer
]

VNI = 8000
VXLAN_DST_PORT = 4789
INNER_TTL = 2
OUTER_TTL = 64
# Create the VxLAN tunnel without ttl_mode, as the REST API does, so the platform's default decap TTL mode applies.
TTL_MODE_DEFAULT = "default"

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


@pytest.fixture(scope="module", params=["v4", "v6"])
def inner_ip_version(request):
    return request.param


@pytest.fixture(scope="module", params=["v4", "v6"])
def outer_ip_version(request):
    return request.param


@pytest.fixture(scope="module", params=["pipe", TTL_MODE_DEFAULT])
def decap_ttl_mode(request):
    return request.param


@pytest.fixture(scope="module", autouse=True)
def setup_ecmp_utils():
    # Need to set these constants before calling any ecmp_utils function.
    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True
    ecmp_utils.Constants["DUT_HOSTID"] = 1


@pytest.fixture
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


def is_vxlan_tunnel_in_app_db(duthost, vxlan_tunnel):
    """
        Function to check if VXLAN_TUNNEL_TABLE:<vxlan_tunnel> exists in APP DB.
    """
    result = duthost.shell(f"sonic-db-cli APPL_DB KEYS 'VXLAN_TUNNEL_TABLE:{vxlan_tunnel}'")["stdout"]
    return bool(result)


def is_a_vxlan_tunnel_in_asic_db(duthost):
    """
        Function to check if at least one VxLAN tunnel is present in ASIC DB.
    """
    tunnel_keys = duthost.shell("sonic-db-cli ASIC_DB KEYS 'ASIC_STATE:SAI_OBJECT_TYPE_TUNNEL:oid*'")["stdout_lines"]
    for key in tunnel_keys:
        tunnel_type = duthost.shell(f"sonic-db-cli ASIC_DB HGET '{key}' 'SAI_TUNNEL_ATTR_TYPE'")["stdout"].strip()
        if tunnel_type == "SAI_TUNNEL_TYPE_VXLAN":
            return True
    return False


@pytest.fixture
def create_vxlan_tunnel(duthost, tbinfo, outer_ip_version, decap_ttl_mode, configure_vxlan_global):  # noqa F811
    """
        Fixture to configure a VxLAN tunnel before a test and remove it after the test.
    """
    logger.info(f"Creating a VxLAN tunnel with decap TTL mode '{decap_ttl_mode}'...")
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    # An empty ttl_mode makes create_vxlan_tunnel() leave ttl_mode out of VXLAN_TUNNEL on every platform.
    ttl_mode = "" if decap_ttl_mode == TTL_MODE_DEFAULT else decap_ttl_mode
    vxlan_tunnel = ecmp_utils.create_vxlan_tunnel(duthost, minigraph_facts, outer_ip_version, ttl_mode=ttl_mode)
    pytest_assert(wait_until(10, 2, 0, is_vxlan_tunnel_in_app_db, duthost, vxlan_tunnel),
                  "The VxLAN tunnel is not created in APP DB.")
    yield vxlan_tunnel
    # Clean-up
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL \"VXLAN_TUNNEL|{vxlan_tunnel}\"")
    pytest_assert(wait_until(10, 2, 0, lambda: not is_vxlan_tunnel_in_app_db(duthost, vxlan_tunnel)),
                  "The VxLAN tunnel is not removed from APP DB.")


@pytest.fixture
def create_vnet(duthost, create_vxlan_tunnel):
    """
        Fixture to configure a VNet before a test and remove it after the test.
    """
    logger.info("Creating a VNet...")
    vxlan_tunnel = create_vxlan_tunnel
    vnet_dict = ecmp_utils.create_vnets(duthost, vxlan_tunnel, vnet_count=1, scope="default", vni_base=VNI)
    vnet = next(iter(vnet_dict))
    pytest_assert(wait_until(10, 2, 0, is_a_vxlan_tunnel_in_asic_db, duthost),
                  "The VxLAN tunnel is not created in ASIC DB.")
    yield vnet
    # Clean-up
    duthost.shell(f"sonic-db-cli CONFIG_DB DEL \"VNET|{vnet}\"")
    pytest_assert(wait_until(10, 2, 0, lambda: not is_a_vxlan_tunnel_in_asic_db(duthost)),
                  "The VxLAN tunnel is not removed from ASIC DB.")


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


def get_dest_mac(duthost, tbinfo, minigraph_facts, ingress_intf, router_mac):
    """
        Returns the destination MAC the outer VxLAN packet must carry to be L3-terminated
        (and therefore decapsulated) when it ingresses on 'ingress_intf'.

        On t1 the server/downlink ports are routed (L3) interfaces, so the global router MAC
        is the termination MAC. On t0/dualtor the server ports are VLAN member ports; routing
        for that subnet is done by the VLAN SVI, whose MAC may differ from the router MAC
        (on dualtor it is the shared gateway MAC). Using the router MAC on such a port leaves
        the frame at L2 and it gets flooded in the VLAN instead of being decapsulated.
    """
    if tbinfo["topo"]["type"] == "t0" and ingress_intf is not None:
        for vlan_name, vlan_info in minigraph_facts.get("minigraph_vlans", {}).items():
            if ingress_intf in vlan_info.get("members", []):
                return duthost.get_dut_iface_mac(vlan_name)
    return router_mac


def select_egress_ip_and_ports(duthost, minigraph_facts, inner_ip_version, exclude_ports=[]):
    """
        Returns a tuple of (egress_ip, egress_port_list) to be used in tests.
        Ports in exclude_ports are not considered for selection.
        If the DUT has an Ethernet or PortChannel interface that is
            1. oper UP, and
            2. has a neighbor with a 'inner_ip_version' IP address,
        then we return that interface's members and its neighbor IP as (egress_ip, egress_port_list).
    """
    portchannel_info = minigraph_facts["minigraph_portchannels"]
    if inner_ip_version == "v4":
        ip_interfaces = duthost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
    else:
        ip_interfaces = duthost.show_ipv6_interfaces()
    for intf, info in ip_interfaces.items():
        if not (intf.startswith("Ethernet") or intf.startswith("PortChannel")):
            continue
        if intf.startswith("PortChannel"):
            members = portchannel_info[intf]["members"]
        else:
            members = [intf]
        # On t1 the ingress port is a PortChannel member, so also skip the PortChannel it belongs to.
        if intf in exclude_ports or any(member in exclude_ports for member in members):
            continue
        if inner_ip_version == "v4":
            if info["oper_state"].lower() != "up":
                continue
            neigh_ip = info.get("peer_ipv4", "")
            if not neigh_ip or neigh_ip.lower() == "n/a":
                continue
        else:
            if info["oper"].lower() != "up":
                continue
            neigh_ip = info.get("neighbor ip", "")
            if not neigh_ip or neigh_ip.lower() == "n/a":
                continue

        logger.info(f"Selected egress packet's dest IP '{neigh_ip}' and egress interface '{intf}'.")
        return (neigh_ip, members)
    pytest.skip("No suitable egress interface found on the DUT.")


def get_inner_packet(dst_mac, src_mac, ip_version, dst_ip, ttl):
    if ip_version == "v4":
        return testutils.simple_udp_packet(eth_dst=dst_mac, eth_src=src_mac, ip_dst=dst_ip, ip_ttl=ttl)
    else:
        return testutils.simple_udpv6_packet(eth_dst=dst_mac, eth_src=src_mac, ipv6_dst=dst_ip, ipv6_hlim=ttl)


def get_outer_packet(eth_dst, eth_src, ip_version, ip_dst, inner_pkt, ttl=OUTER_TTL):
    if ip_version == "v4":
        return testutils.simple_vxlan_packet(eth_dst=eth_dst, eth_src=eth_src, ip_dst=ip_dst, ip_ttl=ttl,
                                             udp_dport=VXLAN_DST_PORT, vxlan_vni=VNI, inner_frame=inner_pkt)
    else:
        return testutils.simple_vxlanv6_packet(eth_dst=eth_dst, eth_src=eth_src, ipv6_dst=ip_dst, ipv6_hlim=ttl,
                                               udp_dport=VXLAN_DST_PORT, vxlan_vni=VNI, inner_frame=inner_pkt)


def get_expected_packet_mask_ipv4(inner_pkt):
    exp_pkt = inner_pkt.copy()
    exp_pkt["IP"].ttl -= 1
    exp_pkt_mask = Mask(exp_pkt)
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "src")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "ihl")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "tos")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "id")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "flags")
    exp_pkt_mask.set_do_not_care_packet(packet.IP, "chksum")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "chksum")
    return exp_pkt_mask


def get_expected_packet_mask_ipv6(inner_pkt):
    exp_pkt = inner_pkt.copy()
    exp_pkt["IPv6"].hlim -= 1
    exp_pkt_mask = Mask(exp_pkt)
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "dst")
    exp_pkt_mask.set_do_not_care_packet(packet.Ether, "src")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "tc")
    exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "fl")
    exp_pkt_mask.set_do_not_care_packet(packet.UDP, "chksum")
    return exp_pkt_mask


def get_expected_packet_mask(inner_pkt, inner_ip_version, ignore_ttl=False):
    """
        Returns the mask of the decapsulated packet, whose TTL/Hop limit is the inner one minus 1 (pipe model).
        With ignore_ttl the TTL/Hop limit is not compared, so that the caller can check it separately.
    """
    if inner_ip_version == "v4":
        exp_pkt_mask = get_expected_packet_mask_ipv4(inner_pkt)
        if ignore_ttl:
            exp_pkt_mask.set_do_not_care_packet(packet.IP, "ttl")
    else:
        exp_pkt_mask = get_expected_packet_mask_ipv6(inner_pkt)
        if ignore_ttl:
            exp_pkt_mask.set_do_not_care_packet(packet.IPv6, "hlim")
    return exp_pkt_mask


def get_ttl(pkt, ip_version):
    """
        Returns the TTL (IPv4) or Hop limit (IPv6) of a received packet.
    """
    pkt = packet.Ether(pkt)
    return pkt[packet.IP].ttl if ip_version == "v4" else pkt[packet.IPv6].hlim


@pytest.mark.dualtor_active_standby_toggle_to_upper_tor
@pytest.mark.dualtor_active_active_setup_standby_on_lower_tor
def test_vxlan_decap_ttl(duthost, tbinfo, ptfadapter, create_vnet, outer_ip_version, inner_ip_version,  # noqa F811
                         decap_ttl_mode):
    """
        In this test, the DUT acts as a VNET endpoint and decapulates VxLAN packets sent to it that match
        the VNI of the VNET configured on it.
        With decap TTL mode "pipe", the test verifies that TTL/Hop limit of the egress packet is set correctly
        (i.e., to the TTL/Hop limit of the inner ingress packet minus 1).
        With the default decap TTL mode (the VxLAN tunnel is created without ttl_mode, as the REST API does),
        the test verifies that the packet is decapsulated and forwarded, and that its TTL/Hop limit follows
        either the pipe model (inner minus 1) or the uniform model (outer minus 1).
    """
    minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)
    router_mac = duthost.facts["router_mac"]
    vnet_endpoint = ecmp_utils.get_dut_loopback_address(duthost, minigraph_facts, outer_ip_version)
    ptf_indices = minigraph_facts["minigraph_ptf_indices"]
    ingress_port = select_ingress_port(duthost)
    inner_dst_ip, egress_ports = select_egress_ip_and_ports(duthost, minigraph_facts,
                                                            inner_ip_version, exclude_ports=[ingress_port])
    egress_port_indices = [ptf_indices[port] for port in egress_ports]
    ptf_src_mac = ptfadapter.dataplane.get_mac(0, ptf_indices[ingress_port])

    # On t0/dualtor the ingress port may be a VLAN member, in which case the outer packet must be
    # addressed to the VLAN SVI MAC (the L3 termination MAC) to be decapsulated rather than flooded.
    # The inner frame's dst MAC stays the router MAC, which is the configured vxlan_router_mac.
    outer_dst_mac = get_dest_mac(duthost, tbinfo, minigraph_facts, ingress_port, router_mac)

    inner_pkt = get_inner_packet(dst_mac=router_mac, src_mac=ptf_src_mac, ip_version=inner_ip_version,
                                 dst_ip=inner_dst_ip, ttl=INNER_TTL)
    outer_pkt = get_outer_packet(eth_dst=outer_dst_mac, eth_src=ptf_src_mac, ip_version=outer_ip_version,
                                 ip_dst=vnet_endpoint, inner_pkt=inner_pkt, ttl=OUTER_TTL)

    # The TTL/Hop limit model of the default decap TTL mode is platform specific; it is checked separately below.
    default_mode = decap_ttl_mode == TTL_MODE_DEFAULT
    exp_pkt_mask = get_expected_packet_mask(inner_pkt, inner_ip_version, ignore_ttl=default_mode)
    ptfadapter.dataplane.flush()
    testutils.send(ptfadapter, ptf_indices[ingress_port], outer_pkt)
    _, received_pkt = testutils.verify_packet_any_port(ptfadapter, exp_pkt_mask, egress_port_indices)
    logger.info(f"Received packet: \n{packet.Ether(received_pkt)}\n")

    if default_mode:
        ttl_models = {INNER_TTL - 1: "pipe", OUTER_TTL - 1: "uniform"}
        received_ttl = get_ttl(received_pkt, inner_ip_version)
        pytest_assert(received_ttl in ttl_models,
                      f"Unexpected TTL/Hop limit {received_ttl} after decap with the default decap TTL mode, "
                      f"expected {INNER_TTL - 1} (pipe model) or {OUTER_TTL - 1} (uniform model).")
        logger.info(f"The default decap TTL mode follows the {ttl_models[received_ttl]} model.")
