"""
Test: ARP/NDP packets on L3 interfaces must not cause RX_DRP increment.

Issue: https://github.com/sonic-net/sonic-mgmt/issues/17139

Some ASIC vendors have a rule that copies ARP/NDP packets to the CPU
and also forwards them. On a VLAN interface this is expected because
the packet is both bridged and trapped. On a routed (L3) interface
the packet should only be trapped to the CPU -- there is no forwarding
path -- so the "forward" copy has no destination and gets silently
discarded by the hardware, incrementing the RX_DRP counter.

This is incorrect behaviour: an ARP request/reply or IPv6 Neighbor
Solicitation/Advertisement received on a routed port is a normal
control-plane packet and must not increment any drop counter.
Spurious RX_DRP increments pollute telemetry and monitoring.
"""

import json
import logging
import pytest
import socket
import time

from scapy.all import Ether, ARP, IPv6, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.all import ICMPv6NDOptSrcLLAddr, ICMPv6NDOptDstLLAddr
from scapy.all import inet_pton, inet_ntop
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any"),
]

ARP_PKT_COUNT = 10
DROP_TOLERANCE = 2


def _resolve_l3_interfaces(mg_facts, port_index_map):
    """
    Build a unified list of routed L3 interfaces, covering both plain
    physical router ports (``minigraph_interfaces``) and L3 portchannel
    (LAG) interfaces (``minigraph_portchannel_interfaces``). Some
    topologies (e.g. T1/T2, multi-asic) only have L3 addressing on
    portchannels, so relying on ``minigraph_interfaces`` alone misses
    them entirely.

    Portchannels have no PTF port or portstat counters of their own, so
    for each L3 portchannel we resolve to one physical member port --
    that is where test traffic is actually injected/received and where
    RX_DRP is actually tracked.
    """
    resolved = []

    for intf in mg_facts.get("minigraph_interfaces", []):
        port = intf["attachto"]
        if port not in port_index_map:
            continue
        resolved.append({
            "addr": intf["addr"],
            "peer_addr": intf.get("peer_addr"),
            "logical_port": port,
            "phy_port": port,
        })

    portchannels = mg_facts.get("minigraph_portchannels", {})
    for pc_intf in mg_facts.get("minigraph_portchannel_interfaces", []):
        pc_name = pc_intf["attachto"]
        members = portchannels.get(pc_name, {}).get("members", [])
        phy_port = next(
            (member for member in members if member in port_index_map),
            None
        )
        if phy_port is None:
            continue
        resolved.append({
            "addr": pc_intf["addr"],
            "peer_addr": pc_intf.get("peer_addr"),
            "logical_port": pc_name,
            "phy_port": phy_port,
        })

    return resolved


@pytest.fixture(scope="module")
def l3_intf_setup(duthosts, rand_one_dut_hostname, tbinfo):
    """
    Identify routed L3 interfaces (IPv4 and IPv6) and PTF ports.
    """
    duthost = duthosts[rand_one_dut_hostname]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    port_index_map = mg_facts["minigraph_ptf_indices"]
    dut_mac = duthost.facts["router_mac"]

    l3_interfaces = _resolve_l3_interfaces(mg_facts, port_index_map)
    pytest_assert(
        len(l3_interfaces) > 0,
        "No L3 routed interfaces (physical or portchannel) found in minigraph"
    )

    ipv4_intf = None
    ipv6_intf = None
    for intf in l3_interfaces:
        if ":" not in intf["addr"] and ipv4_intf is None:
            ipv4_intf = intf
        elif ":" in intf["addr"] and ipv6_intf is None:
            ipv6_intf = intf
        if ipv4_intf and ipv6_intf:
            break

    setup_info = {
        "duthost": duthost,
        "dut_mac": dut_mac,
        "port_index_map": port_index_map,
        "ipv4_intf": ipv4_intf,
        "ipv6_intf": ipv6_intf,
    }

    if ipv4_intf:
        logger.info(
            "IPv4 L3 intf: logical_port=%s phy_port=%s ip=%s peer=%s",
            ipv4_intf["logical_port"], ipv4_intf["phy_port"],
            ipv4_intf["addr"], ipv4_intf.get("peer_addr")
        )
    if ipv6_intf:
        logger.info(
            "IPv6 L3 intf: logical_port=%s phy_port=%s ip=%s peer=%s",
            ipv6_intf["logical_port"], ipv6_intf["phy_port"],
            ipv6_intf["addr"], ipv6_intf.get("peer_addr")
        )

    yield setup_info


def get_rx_drp(duthost, interface):
    """Read RX_DRP counter for a specific interface."""
    result = duthost.command("portstat -j")["stdout"]
    counters = json.loads(result)
    if interface not in counters:
        pytest.fail(
            "Interface {} not in portstat output".format(interface)
        )
    return int(counters[interface].get("RX_DRP", 0))


def build_arp_request(src_mac, src_ip, dst_ip, dst_mac):
    """Build an ARP request packet."""
    return (
        Ether(src=src_mac, dst=dst_mac) /
        ARP(
            op="who-has", hwsrc=src_mac, psrc=src_ip,
            hwdst="00:00:00:00:00:00", pdst=dst_ip
        )
    )


def build_ns_packet(src_mac, src_ip, target_ip):
    """Build an IPv6 Neighbor Solicitation packet."""
    tgt_bytes = inet_pton(socket.AF_INET6, target_ip)
    sol_node_addr = inet_ntop(
        socket.AF_INET6,
        b'\xff\x02\x00\x00\x00\x00\x00\x00'
        b'\x00\x00\x00\x01\xff' + tgt_bytes[-3:]
    )
    sol_node_mac = "33:33:ff:{:02x}:{:02x}:{:02x}".format(
        tgt_bytes[-3], tgt_bytes[-2], tgt_bytes[-1]
    )
    return (
        Ether(src=src_mac, dst=sol_node_mac) /
        IPv6(src=src_ip, dst=sol_node_addr) /
        ICMPv6ND_NS(tgt=target_ip) /
        ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    )


def build_na_packet(src_mac, src_ip, dst_mac, dst_ip):
    """Build an IPv6 Neighbor Advertisement packet."""
    return (
        Ether(src=src_mac, dst=dst_mac) /
        IPv6(src=src_ip, dst=dst_ip) /
        ICMPv6ND_NA(tgt=src_ip, R=0, S=1, O=1) /
        ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    )


def _skip_if_virtual(duthost):
    """Skip on virtual platforms where counters are not meaningful."""
    asic_type = duthost.facts.get("asic_type", "")
    if asic_type in ("vs", "vpp"):
        pytest.skip(
            "Counter check not applicable on {} platform"
            .format(asic_type)
        )


def _send_and_verify_no_drop(
    duthost, ptfadapter, dut_port, ptf_port_idx, pkt,
    pkt_desc, pkt_count=ARP_PKT_COUNT
):
    """Send packets and assert RX_DRP does not increment."""
    duthost.command("sonic-clear counters")
    time.sleep(2)

    pre_rx_drp = get_rx_drp(duthost, dut_port)
    logger.info(
        "Pre-test RX_DRP on %s: %d", dut_port, pre_rx_drp
    )

    logger.info(
        "Sending %d %s to %s (ptf port %d)",
        pkt_count, pkt_desc, dut_port, ptf_port_idx
    )
    for _ in range(pkt_count):
        ptfadapter.dataplane.send(ptf_port_idx, bytes(pkt))
    time.sleep(3)

    post_rx_drp = get_rx_drp(duthost, dut_port)
    rx_drp_delta = post_rx_drp - pre_rx_drp
    logger.info(
        "Post-test RX_DRP on %s: %d (delta: %d)",
        dut_port, post_rx_drp, rx_drp_delta
    )

    pytest_assert(
        rx_drp_delta <= DROP_TOLERANCE,
        "RX_DRP increased by {} on {} after sending {} {}. "
        "Pre: {}, Post: {}".format(
            rx_drp_delta, dut_port, pkt_count,
            pkt_desc, pre_rx_drp, post_rx_drp
        )
    )


class TestArpL3NoRxDrop:
    """Verify ARP/NDP on L3 interfaces do not increment RX_DRP."""

    def test_arp_request_no_rx_drop(
        self, l3_intf_setup, ptfadapter
    ):
        """Send ARP requests on L3 port, verify no RX_DRP."""
        setup = l3_intf_setup
        duthost = setup["duthost"]
        _skip_if_virtual(duthost)

        intf = setup["ipv4_intf"]
        if intf is None:
            pytest.skip("No IPv4 L3 interface available")

        dut_port = intf["phy_port"]
        peer_addr = intf.get("peer_addr")
        ptf_idx = setup["port_index_map"][dut_port]
        if peer_addr is None:
            pytest.skip("No peer address for {}".format(dut_port))

        pkt = build_arp_request(
            src_mac="00:11:22:33:44:55",
            src_ip=peer_addr,
            dst_ip=intf["addr"],
            dst_mac="ff:ff:ff:ff:ff:ff"
        )
        _send_and_verify_no_drop(
            duthost, ptfadapter, dut_port, ptf_idx,
            pkt, "ARP requests"
        )

    def test_arp_reply_no_rx_drop(
        self, l3_intf_setup, ptfadapter
    ):
        """Send ARP replies on L3 port, verify no RX_DRP."""
        setup = l3_intf_setup
        duthost = setup["duthost"]
        _skip_if_virtual(duthost)

        intf = setup["ipv4_intf"]
        if intf is None:
            pytest.skip("No IPv4 L3 interface available")

        dut_port = intf["phy_port"]
        dut_mac = setup["dut_mac"]
        peer_addr = intf.get("peer_addr")
        ptf_idx = setup["port_index_map"][dut_port]
        if peer_addr is None:
            pytest.skip("No peer address for {}".format(dut_port))

        pkt = (
            Ether(src="00:11:22:33:44:55", dst=dut_mac) /
            ARP(
                op="is-at",
                hwsrc="00:11:22:33:44:55", psrc=peer_addr,
                hwdst=dut_mac, pdst=intf["addr"]
            )
        )
        _send_and_verify_no_drop(
            duthost, ptfadapter, dut_port, ptf_idx,
            pkt, "ARP replies"
        )

    def test_ndp_ns_no_rx_drop(
        self, l3_intf_setup, ptfadapter
    ):
        """Send IPv6 NS on L3 port, verify no RX_DRP."""
        setup = l3_intf_setup
        duthost = setup["duthost"]
        _skip_if_virtual(duthost)

        intf = setup["ipv6_intf"]
        if intf is None:
            pytest.skip("No IPv6 L3 interface available")

        dut_port = intf["phy_port"]
        peer_addr = intf.get("peer_addr")
        ptf_idx = setup["port_index_map"][dut_port]
        if peer_addr is None:
            pytest.skip("No peer address for {}".format(dut_port))

        pkt = build_ns_packet(
            src_mac="00:11:22:33:44:55",
            src_ip=peer_addr,
            target_ip=intf["addr"]
        )
        _send_and_verify_no_drop(
            duthost, ptfadapter, dut_port, ptf_idx,
            pkt, "IPv6 NS packets"
        )

    def test_ndp_na_no_rx_drop(
        self, l3_intf_setup, ptfadapter
    ):
        """Send IPv6 NA on L3 port, verify no RX_DRP."""
        setup = l3_intf_setup
        duthost = setup["duthost"]
        _skip_if_virtual(duthost)

        intf = setup["ipv6_intf"]
        if intf is None:
            pytest.skip("No IPv6 L3 interface available")

        dut_port = intf["phy_port"]
        dut_mac = setup["dut_mac"]
        peer_addr = intf.get("peer_addr")
        ptf_idx = setup["port_index_map"][dut_port]
        if peer_addr is None:
            pytest.skip("No peer address for {}".format(dut_port))

        pkt = build_na_packet(
            src_mac="00:11:22:33:44:55",
            src_ip=peer_addr,
            dst_mac=dut_mac,
            dst_ip=intf["addr"]
        )
        _send_and_verify_no_drop(
            duthost, ptfadapter, dut_port, ptf_idx,
            pkt, "IPv6 NA packets"
        )
