"""BGP SRv6 GRT control-plane system tests."""

import ipaddress

import pytest

from tests.common.utilities import wait_until
from tests.srv6.bgp_srv6_grt_helpers import (
    IPV4_ADVERTISEMENT_PREFIX,
    IPV4_POLICY_ALLOW_PREFIX,
    IPV4_POLICY_DENY_PREFIX,
    IPV6_ADVERTISEMENT_PREFIX,
    IPV6_POLICY_ALLOW_PREFIX,
    IPV6_POLICY_DENY_PREFIX,
    appl_route_exists,
    configured_grt_advertisement,
    fib_route_has_sid,
    get_appl_route_field,
    get_srv6_source_address,
    mysid_is_programmed,
    route_has_source_address,
    route_has_vpn_sid,
)


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology("ciscovs-7nodes", "force10-7nodes"),
    pytest.mark.skip_check_dut_health
]


def _grt_endpoints(nbrhosts, duthosts, rand_one_dut_hostname):
    """Return logical (ingress PE, egress PE) endpoints."""
    return duthosts[rand_one_dut_hostname], nbrhosts["PE1"]["host"]


@pytest.mark.parametrize(
    ("family", "prefix"),
    [
        ("ipv4", IPV4_ADVERTISEMENT_PREFIX),
        ("ipv6", IPV6_ADVERTISEMENT_PREFIX),
    ],
    ids=["ipv4", "ipv6"]
)
def test_bgp_srv6_grt_sid_advertisement(
        family, prefix, grt_config_backend, nbrhosts, duthosts, rand_one_dut_hostname):
    """Verify route SID advertisement and source-address programming in both backends."""
    ingress_pe, egress_pe = _grt_endpoints(nbrhosts, duthosts, rand_one_dut_hostname)
    source_address = get_srv6_source_address(ingress_pe)

    with configured_grt_advertisement(
            egress_pe, ingress_pe, family, [prefix], source_address=source_address):
        assert wait_until(60, 2, 0, route_has_vpn_sid, ingress_pe, prefix), \
            "Ingress PE did not install {} with an SRv6 service SID".format(prefix)
        sid = get_appl_route_field(ingress_pe, prefix, "vpn_sid")
        assert ipaddress.ip_address(sid).version == 6, \
            "Egress PE advertised an invalid SRv6 service SID for {}: {}".format(prefix, sid)
        assert wait_until(60, 2, 0, mysid_is_programmed, egress_pe, sid), \
            "Egress PE did not program local uDT46 MySID {} in the default VRF".format(sid)
        assert wait_until(60, 2, 0, fib_route_has_sid, ingress_pe, family, prefix, sid), \
            "Ingress PE did not install {} with SRv6 encap SID {}".format(prefix, sid)
        assert wait_until(
            60, 2, 0, route_has_source_address, ingress_pe, prefix, source_address
        ), "Ingress PE did not publish seg_src={} for {} in APPL_DB".format(
            source_address, prefix
        )


@pytest.mark.parametrize(
    ("family", "allow_prefix", "deny_prefix", "prefix_set", "route_map"),
    [
        ("ipv4", IPV4_POLICY_ALLOW_PREFIX, IPV4_POLICY_DENY_PREFIX,
         "BGP_SRV6_GRT_IPV4_PREFIXES", "BGP_SRV6_GRT_IPV4_MAP"),
        ("ipv6", IPV6_POLICY_ALLOW_PREFIX, IPV6_POLICY_DENY_PREFIX,
         "BGP_SRV6_GRT_IPV6_PREFIXES", "BGP_SRV6_GRT_IPV6_MAP"),
    ],
    ids=["ipv4", "ipv6"]
)
def test_bgp_srv6_grt_sid_advertise_route_map_policy(
        family, allow_prefix, deny_prefix, prefix_set, route_map,
        grt_config_backend, nbrhosts, duthosts, rand_one_dut_hostname):
    """Only prefixes selected by the family-specific CONFIG_DB route map carry a SID."""
    ingress_pe, egress_pe = _grt_endpoints(nbrhosts, duthosts, rand_one_dut_hostname)
    prefixes = [allow_prefix, deny_prefix]
    with configured_grt_advertisement(
            egress_pe, ingress_pe, family, prefixes,
            prefix_set_name=prefix_set,
            route_map_name=route_map,
            permit_prefixes=[allow_prefix],
            relaxed_neighbor=True):
        assert wait_until(60, 2, 0, route_has_vpn_sid, ingress_pe, allow_prefix), \
            "Route-map-permitted {} route did not receive an SRv6 service SID".format(family)
        assert wait_until(60, 2, 0, appl_route_exists, ingress_pe, deny_prefix), \
            "srv6-relax peer did not send the route excluded from SID advertisement"

        allowed_sid = get_appl_route_field(ingress_pe, allow_prefix, "vpn_sid")
        denied_sid = get_appl_route_field(ingress_pe, deny_prefix, "vpn_sid")
        assert allowed_sid, "Permitted route is missing its vpn_sid field"
        assert denied_sid is None, \
            "Route-map-denied route unexpectedly carries SRv6 SID {}".format(denied_sid)
