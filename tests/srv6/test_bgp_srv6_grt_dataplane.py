"""BGP SRv6 GRT packet-forwarding system tests."""

import ipaddress
import shlex
import threading
import time

import pytest
import ptf.testutils as testutils

from tests.common.utilities import wait_until
from tests.srv6.bgp_srv6_grt_helpers import (
    EGRESS_TO_TRANSIT_NEXTHOP,
    INGRESS_TO_TRANSIT_NEXTHOP,
    IPV4_DATAPLANE_PREFIX,
    IPV6_DATAPLANE_PREFIX,
    TRANSIT_TO_EGRESS_PE,
    TRANSIT_TO_INGRESS_PE,
    ConfigDBPatch,
    configured_grt_advertisement,
    fib_route_has_sid,
    fib_route_via,
    get_appl_route_field,
    get_interface_toward,
    get_srv6_source_address,
    mysid_is_programmed,
    route_has_source_address,
    route_has_vpn_sid,
)


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("ciscovs-7nodes"),
    pytest.mark.skip_check_dut_health
]

GRT_PTF_INGRESS_PORT = 1  # P1 Ethernet4, the GRT access port in ciscovs-7nodes


def _start_capture(host, interface, packet_filter):
    capture = {}

    def capture_packet():
        capture["result"] = host.command(
            "sudo timeout 30 tcpdump -i {} -nn -vv -c 1 {}".format(
                shlex.quote(interface), shlex.quote(packet_filter)
            ),
            module_ignore_errors=True
        )

    thread = threading.Thread(target=capture_packet, daemon=True)
    thread.start()
    return thread, capture


def _finish_capture(thread, capture, description):
    thread.join(timeout=35)
    assert not thread.is_alive(), "Timed out waiting for {} packet capture".format(description)
    result = capture.get("result", {})
    output = (result.get("stdout", "") + result.get("stderr", "")).lower()
    assert result.get("rc", 1) == 0, \
        "{} packet capture failed: {}".format(description, output)
    return output


def _send_packet_and_check_path(
        transit_p, egress_pe, duthost, ptfadapter,
        family, prefix, sid, source_address):
    ptf_device, ptf_port = ptfadapter.dataplane.port_to_tuple(GRT_PTF_INGRESS_PORT)
    src_mac = ptfadapter.dataplane.get_mac(ptf_device, ptf_port).decode()
    dut_mac = duthost.facts["router_mac"]
    destination = prefix.split("/")[0]

    if family == "ipv4":
        packet = testutils.simple_tcp_packet(
            eth_src=src_mac,
            eth_dst=dut_mac,
            ip_src="198.18.0.1",
            ip_dst=destination,
            ip_ttl=64
        )
        inner_filter = "ip dst {}".format(destination)
    else:
        packet = testutils.simple_tcpv6_packet(
            eth_src=src_mac,
            eth_dst=dut_mac,
            ipv6_src="2001:db8:ffff::1",
            ipv6_dst=destination,
            ipv6_hlim=64
        )
        inner_filter = "ip6 dst {}".format(destination)

    expected_source = str(ipaddress.IPv6Address(source_address))
    expected_sid = str(ipaddress.IPv6Address(sid))
    expected_destination = str(ipaddress.ip_address(destination))
    outer_filter = "ip6 dst {}".format(expected_sid)

    p_ingress_iface = get_interface_toward(transit_p, TRANSIT_TO_INGRESS_PE)
    p_egress_iface = get_interface_toward(transit_p, TRANSIT_TO_EGRESS_PE)
    egress_p_iface = get_interface_toward(egress_pe, EGRESS_TO_TRANSIT_NEXTHOP)
    p_ingress_capture = _start_capture(transit_p, p_ingress_iface, outer_filter)
    p_egress_capture = _start_capture(transit_p, p_egress_iface, outer_filter)
    inner_capture = _start_capture(egress_pe, egress_p_iface, inner_filter)

    time.sleep(2)
    ptfadapter.dataplane.flush()
    ptfadapter.dataplane.set_qlen(1000000)
    testutils.send(
        ptfadapter,
        ptfadapter.dataplane.port_to_tuple(GRT_PTF_INGRESS_PORT),
        packet,
        count=1
    )

    p_ingress_output = _finish_capture(
        p_ingress_capture[0], p_ingress_capture[1], "transit P ingress"
    )
    p_egress_output = _finish_capture(
        p_egress_capture[0], p_egress_capture[1], "transit P egress"
    )
    inner_output = _finish_capture(
        inner_capture[0], inner_capture[1], "egress PE decapsulated"
    )

    for description, output in (("transit P ingress", p_ingress_output),
                                ("transit P egress", p_egress_output)):
        assert expected_source in output, \
            "{} did not observe configured outer IPv6 source {}: {}".format(
                description, expected_source, output
            )
        assert expected_sid in output, \
            "{} did not observe service SID {} as outer destination: {}".format(
                description, expected_sid, output
            )
    assert expected_destination in inner_output, \
        "Egress PE did not decapsulate and forward inner destination {} to P3: {}".format(
            expected_destination, inner_output
        )


@pytest.mark.parametrize(
    ("family", "prefix"),
    [
        ("ipv4", IPV4_DATAPLANE_PREFIX),
        ("ipv6", IPV6_DATAPLANE_PREFIX),
    ],
    ids=["ipv4", "ipv6"]
)
def test_bgp_srv6_grt_data_plane_forwarding(
        family, prefix, grt_config_backend, nbrhosts, duthosts,
        rand_one_dut_hostname, ptfadapter):
    """Verify PE1 -> transit P3 -> PE2 forwarding and outer encap source address."""
    ingress_pe = duthosts[rand_one_dut_hostname]
    egress_pe = nbrhosts["PE1"]["host"]
    transit_p = nbrhosts["P3"]["host"]
    source_address = get_srv6_source_address(ingress_pe)

    with configured_grt_advertisement(
            egress_pe, ingress_pe, family, [prefix],
            route_next_hop=EGRESS_TO_TRANSIT_NEXTHOP,
            source_address=source_address):
        assert wait_until(60, 2, 0, route_has_vpn_sid, ingress_pe, prefix), \
            "Ingress PE did not install {} with an SRv6 service SID".format(prefix)
        sid = get_appl_route_field(ingress_pe, prefix, "vpn_sid")
        assert wait_until(60, 2, 0, fib_route_has_sid, ingress_pe, family, prefix, sid), \
            "Ingress PE did not install the SRv6 forwarding entry for {}".format(prefix)
        assert wait_until(60, 2, 0, mysid_is_programmed, egress_pe, sid), \
            "Egress PE did not program local uDT46 MySID {} in the default VRF".format(sid)
        assert wait_until(
            60, 2, 0, route_has_source_address, ingress_pe, prefix, source_address
        ), "APPL_DB does not contain seg_src={} for {}".format(source_address, prefix)

        # Route the service SID through P3 so the dataplane must cross the
        # intermediate P router even though the BGP control session is direct.
        underlay_patch = ConfigDBPatch(ingress_pe)
        try:
            underlay_patch.set_fields(
                "STATIC_ROUTE|default|{}/128".format(sid),
                {"nexthop": INGRESS_TO_TRANSIT_NEXTHOP}
            )
            assert wait_until(
                30, 2, 0, fib_route_via, ingress_pe, sid, INGRESS_TO_TRANSIT_NEXTHOP
            ), "Ingress PE did not resolve service SID {} through transit P3".format(sid)
            _send_packet_and_check_path(
                transit_p, egress_pe, ingress_pe, ptfadapter,
                family, prefix, sid, source_address
            )
        finally:
            underlay_patch.restore()
