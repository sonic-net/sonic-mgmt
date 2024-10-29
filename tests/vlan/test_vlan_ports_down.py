import pytest
import logging
import ptf.testutils as testutils
import ptf.mask as mask
import time

from netaddr import IPNetwork, NOHOST
from tests.common.helpers.assertions import pytest_assert
from scapy.all import IP, Ether

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]


@pytest.fixture(scope='module')
def vlan_ports_setup(duthosts, rand_one_dut_hostname):
    """
    Setup:      Brings down all member ports of a VLAN.
    Teardown:   Restores (starts up) all member ports of the VLAN selected in the Setup phase.
    """
    duthost = duthosts[rand_one_dut_hostname]
    vlan_brief = duthost.get_vlan_brief()
    if not vlan_brief:
        pytest.skip("The testbed does not have any VLANs.")
    # Selecting the first VLAN in 'vlan_brief'
    vlan_name = next(iter(vlan_brief))
    vlan_members = vlan_brief[vlan_name]["members"]
    for vlan_port in vlan_members:
        duthost.shell(f"sudo config interface shutdown {vlan_port}")
    time.sleep(5)  # Sleep for 5 seconds to ensure T1 switches update their routing table
    yield vlan_name
    for vlan_port in vlan_members:
        duthost.shell(f"sudo config interface startup {vlan_port}")


def ipv6_interface_info(host, interface_name):
    """
    Only returns the IPv6 subnet and the operational state of the interface.
    """
    command = f"show ipv6 interfaces | grep \"{interface_name}\""
    info = host.shell(command)["stdout"]
    info = info.split()
    if len(info) < 5:
        pytest.skip(f"Incomplete interface information for {interface_name}.")
    ret = {}
    ret["subnet"] = info[1]
    ret["oper_state"] = info[2].split('/')[1]
    return ret


def test_vlan_ports_down(vlan_ports_setup, duthosts, rand_one_dut_hostname, nbrhosts, tbinfo, ptfadapter):
    """
    Asserts the following conditions when all member ports of a VLAN interface are down:
        1. The VLAN interface's oper status remains Up.
        2. The VLAN's subnet IP is advertised to the T1 neighbors.
        3. The IP decapsulation feature works for packets that are sent to the VLAN interfaces's IP address.
    """
    duthost = duthosts[rand_one_dut_hostname]
    vlan_name = vlan_ports_setup
    ip_interfaces = duthost.show_ip_interface()["ansible_facts"]["ip_interfaces"]
    vlan_info = ip_interfaces[vlan_name]
    # check if the VLAN interface is operationally Up (IPv4)
    pytest_assert(vlan_info["oper_state"] == "up", f"{vlan_name} is operationally down.")
    vlan_info_ipv6 = ipv6_interface_info(duthost, vlan_name)
    # check if the VLAN interface is operationally Up (IPv6)
    pytest_assert(vlan_info_ipv6["oper_state"] == "up", f"{vlan_name} is operationally down.")
    vlan_subnet = str(IPNetwork(f"{vlan_info['ipv4']}/{vlan_info['prefix_len']}", flags=NOHOST))
    vlan_subnet_ipv6 = str(IPNetwork(vlan_info_ipv6["subnet"], flags=NOHOST))
    nbrcount = 0
    for nbrname, nbrhost in nbrhosts.items():
        nbrhost = nbrhost["host"]
        # check IPv4 routes on nbrhost
        try:
            vlan_route = nbrhost.get_route(vlan_subnet)["vrfs"]["default"]
        except Exception:
            # nbrhost might be unreachable. Skip it.
            continue
        pytest_assert(vlan_route["bgpRouteEntries"],
                      f"{vlan_name}'s IPv4 subnet is not advertised to the T1 neighbor {nbrname}.")
        # check IPv6 routes on nbrhost
        try:
            vlan_route_ipv6 = nbrhost.get_route(vlan_subnet_ipv6)["vrfs"]["default"]
        except Exception:
            # nbrhost might be unreachable. Skip it.
            continue
        pytest_assert(vlan_route_ipv6["bgpRouteEntries"],
                      f"{vlan_name}'s IPv6 subnet is not advertised to the T1 neighbor {nbrname}.")
        nbrcount += 1
    if nbrcount == 0:
        pytest.skip("Could not get routing info from any T1 neighbors.")
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    # Use the first Ethernet port associated with the first portchannel to send test packets to the DUT
    portchannel_info = next(iter(mg_facts["minigraph_portchannels"].values()))
    ptf_src_port = portchannel_info["members"][0]
    ptf_src_port_index = mg_facts["minigraph_ptf_indices"][ptf_src_port]
    ptf_dst_port_indices = list(mg_facts["minigraph_ptf_indices"].values())
    # Test IPv4 in IPv4 decapsulation.
    # Outer IP packet:
    #   src: 1.1.1.1
    #   dst: VLAN interface's IPv4 address
    # Inner IP packet:
    #   src: 2.2.2.2
    #   dst: 3.3.3.3
    # Expectation: The T0 switch (DUT) decapsulates the outer IP packet and sends
    # the inner IP packet to the default gateway (one of the connected T1 switches).
    inner_pkt = testutils.simple_udp_packet(ip_src="2.2.2.2",
                                            ip_dst="3.3.3.3")
    outer_pkt = testutils.simple_ipv4ip_packet(eth_src=ptfadapter.dataplane.get_mac(0, ptf_src_port_index),
                                               eth_dst=duthost.facts["router_mac"],
                                               ip_src="1.1.1.1",
                                               ip_dst=vlan_info["ipv4"],
                                               inner_frame=inner_pkt["IP"])
    exp_pkt = inner_pkt.copy()
    exp_pkt = mask.Mask(exp_pkt)
    exp_pkt.set_do_not_care_packet(Ether, "src")
    exp_pkt.set_do_not_care_packet(Ether, "dst")
    exp_pkt.set_do_not_care_packet(IP, "ttl")
    exp_pkt.set_do_not_care_packet(IP, "chksum")
    exp_pkt.set_do_not_care_packet(IP, "tos")
    testutils.send(ptfadapter, ptf_src_port_index, outer_pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=ptf_dst_port_indices)
