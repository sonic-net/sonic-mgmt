import json

import pytest
import ptf.packet as scapy
import ptf.testutils as testutils
from ptf.mask import Mask


pytestmark = [
    pytest.mark.topology('t0')
]
# destination prefix used to discover the DUT active forwarding paths
ROUTE_PREFIX = "192.168.8.0/25"

# packet source and destination IP addresses
DST_IP = "192.168.8.1"
SRC_IP = "1.1.1.1"

# DUT ingress port and a separate port used for negative verification
INGRESS_DUT_PORT = "Ethernet20"
NEGATIVE_DUT_PORT = "Ethernet24"

@pytest.fixture(scope="module")
def forwarding_ports(duthosts, enum_rand_one_per_hwsku_frontend_hostname, tbinfo):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    ptf_indices = mg_facts["minigraph_ptf_indices"]

    # retrieve the active route and its nexthop interfaces from the DUT
    out = json.loads(duthost.shell('vtysh -c "show ip route {} json"'.format(ROUTE_PREFIX),
                                   verbose=False)["stdout"])
    if ROUTE_PREFIX not in out:
        pytest.skip("Route {} is not present on the DUT".format(ROUTE_PREFIX))

    # collect active egress interfaces used by the route
    egress_ifaces = {nh["interfaceName"] for nh in out[ROUTE_PREFIX][0].get("nexthops", [])
                     if nh.get("active") and "interfaceName" in nh}
    egress_ports = []
    for iface in egress_ifaces:
        # expand PortChannels into their physical member ports
        pc = mg_facts["minigraph_portchannels"].get(iface)
        if pc:
            egress_ports.extend(ptf_indices[member] for member in pc["members"])
        elif iface in ptf_indices:
            egress_ports.append(ptf_indices[iface])
    # remove duplicate PTF indices and ensure ordering
    egress_ports = sorted(set(egress_ports))
    if not egress_ports:
        pytest.skip("No active egress ports found for route {}".format(ROUTE_PREFIX))

    # map the selected DUT interfaces to their corresponding PTF ports
    ingress_port = ptf_indices[INGRESS_DUT_PORT]
    non_egress = ptf_indices[NEGATIVE_DUT_PORT]

    return {
        "router_mac": duthost.facts["router_mac"],
        "ingress": ingress_port,
        "egress": egress_ports,
        "non_egress": non_egress,
    }


def build_packets(ptfadapter, ports):
    """Helper function to build the packet and expected packet"""
    pkt = testutils.simple_tcp_packet(
        eth_dst=ports["router_mac"],
        eth_src=ptfadapter.dataplane.get_mac(0, ports["ingress"]),
        ip_src=SRC_IP,
        ip_dst=DST_IP,
        ip_ttl=64,
        tcp_sport=1234,
        tcp_dport=4321,
    )
    exp_pkt = testutils.simple_tcp_packet(
        eth_dst=ports["router_mac"],
        eth_src=ports["router_mac"],
        ip_src=SRC_IP,
        ip_dst=DST_IP,
        ip_ttl=63,
        tcp_sport=1234,
        tcp_dport=4321,
    )

    # used mask to ignore fields that can be changed during routing
    exp_pkt = Mask(exp_pkt)
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "dst")
    exp_pkt.set_do_not_care_scapy(scapy.Ether, "src")
    exp_pkt.set_do_not_care_scapy(scapy.IP, "chksum")
    return pkt, exp_pkt


def test_packet_forwarding(ptfadapter, forwarding_ports):
    """Verify that a routed packet is received on an expected egress port"""
    pkt, exp_pkt = build_packets(ptfadapter, forwarding_ports)
    # clear pending packets before starting the test
    ptfadapter.dataplane.flush()

    testutils.send(ptfadapter, forwarding_ports["ingress"], pkt)
    testutils.verify_packet_any_port(
        ptfadapter, exp_pkt, ports=forwarding_ports["egress"])


def test_forwarding_negative(ptfadapter, forwarding_ports):
    """Verify that the packet is not forwarded to an unrelated port"""
    pkt, exp_pkt = build_packets(ptfadapter, forwarding_ports)
    # clear pending packets before starting the test
    ptfadapter.dataplane.flush()

    testutils.send(ptfadapter, forwarding_ports["ingress"], pkt)
    testutils.verify_packet_any_port(ptfadapter, exp_pkt, ports=forwarding_ports["egress"])
    testutils.verify_no_packet(ptfadapter, exp_pkt, forwarding_ports["non_egress"])

