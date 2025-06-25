"""
Test BGP Route Aggregation

Step 1: Ensure eBGP neighborship between DUT and NEI_DUT
Step 2: Capture the route summary advertized to NEI_DUT
Step 3: Aggregate eBGP routes
Step 4: Verify aggregated eBGP routes to NEI_DUT
Step 5: Aggregate eBGP routes with 'as-set'
Step 6: Verify aggregated eBGP routes to NEI_DUT include AS-path

Pass/Fail Criteria:
An aggregate route is generated in all cases, a CLI knob option controls whether or not the specifics
are sent or not.  No as-set information is generated in the AS_PATH of the aggregate route
(or a knob exists that disables the generation of as-set).
"""

import pytest
import time
import logging

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

NEI_IPv4_AGG_ROUTE = "1.1.0.0/16"
NEI_IPv6_AGG_ROUTE = "1:1:1::/48"
establish_bgp_session_time = 120


def create_loopbacks(gather_info):
    gather_info['duthost'].shell("sudo config loopback add Loopback11")
    gather_info['duthost'].shell("sudo config interface ip add Loopback11 1.1.1.1/24")
    gather_info['duthost'].shell("sudo config interface ip add Loopback11 1:1:1:1::/64")
    gather_info['duthost'].shell("sudo config loopback add Loopback12")
    gather_info['duthost'].shell("sudo config interface ip add Loopback12 1.1.2.1/24")
    gather_info['duthost'].shell("sudo config interface ip add Loopback12 1:1:1:2::/64")
    gather_info['duthost'].shell("sudo config loopback add Loopback13")
    gather_info['duthost'].shell("sudo config interface ip add Loopback13 1.1.3.1/24")
    gather_info['duthost'].shell("sudo config interface ip add Loopback13 1:1:1:3::/64")
    gather_info['duthost'].shell("sudo config loopback add Loopback14")
    gather_info['duthost'].shell("sudo config interface ip add Loopback14 1.1.4.1/24")
    gather_info['duthost'].shell("sudo config interface ip add Loopback14 1:1:1:4::/64")
    gather_info['duthost'].shell("sudo config loopback add Loopback15")
    gather_info['duthost'].shell("sudo config interface ip add Loopback15 1.1.5.1/24")
    gather_info['duthost'].shell("sudo config interface ip add Loopback15 1:1:1:5::/64")


def agg_configuration(config, asn, duthost, cli_options, commandv4, commandv6):
    remove_tag = ""
    if not config:
        remove_tag = "no "
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
    -c "{}aggregate-address {} {}" -c "address-family ipv6 unicast" \
    -c "{}aggregate-address {} {}"'.format(cli_options, asn, remove_tag, NEI_IPv4_AGG_ROUTE, commandv4, remove_tag,
                                           NEI_IPv6_AGG_ROUTE, commandv6)
    logger.debug(duthost.shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "clear bgp *"'.format(cli_options)
    duthost.shell(cmd, module_ignore_errors=True)
    time.sleep(establish_bgp_session_time)


def verify_route_agg(dut, neigh_ip_v4, neigh_ip_v6, num_matches, suppress, as_set=False):
    output = dut.shell('show ip bgp neighbors {} advertised-routes | grep -c "*> 1.1."'.format(neigh_ip_v4),
                       module_ignore_errors=True)['stdout']
    logger.debug(output)
    assert num_matches == output
    output = dut.shell('show ipv6 bgp neighbors {} advertised-routes | grep -c "*> 1.1."'.format(neigh_ip_v6),
                       module_ignore_errors=True)['stdout']
    logger.debug(output)
    assert num_matches == output

    output4 = dut.shell('show ip bgp neighbors {} advertised-routes | grep "*> 1.1."'.format(neigh_ip_v4),
                        module_ignore_errors=True)['stdout']
    logger.debug(output4)
    output6 = dut.shell('show ipv6 bgp neighbors {} advertised-routes | grep "*> 1.1."'.format(neigh_ip_v6),
                        module_ignore_errors=True)['stdout']
    logger.debug(output6)
    if suppress:
        assert "1.1.1.0/24" not in output4
        assert "1.1.2.0/24" not in output4
        assert "1:1:1:1::/64" not in output6
        assert "1:1:1:2::/64" not in output6
    if as_set:
        assert "11111" in output4
        assert "22222" in output4
        assert "11111" in output6
        assert "22222" in output6


def check_baseline(dut, neigh_ip_v4, neigh_ip_v6, base_v4, base_v6):
    output = dut.shell('show ip bgp neighbors {} advertised-routes | grep -c "*>"'.format(neigh_ip_v4),
                       module_ignore_errors=True)['stdout']
    logger.debug("output: {}".format(output))
    assert int(base_v4) + 5 == int(output)
    output = dut.shell('show ipv6 bgp neighbors {} advertised-routes | grep -c "*>"'.format(neigh_ip_v6),
                       module_ignore_errors=True)['stdout']
    logger.debug("output: {}".format(output))
    assert int(base_v6) + 5 == int(output)


def test_ebgp_route_aggregation(gather_info):
    # precheck number of routes
    num_v4_routes = gather_info['duthost'].shell('show ip bgp neighbors {} advertised-routes | grep -c "*>"'.format(
        gather_info['neigh_ip_v4']))['stdout']
    num_v6_routes = gather_info['duthost'].shell('show ipv6 bgp neighbors {} advertised-routes | grep -c "*>"'.format(
        gather_info['neigh_ip_v6']))['stdout']

    # Configure and Advertise Loopback Networks on DUT
    create_loopbacks()

    # Create the route maps to be used
    cmd = 'vtysh -c "config" -c "route-map AGG_TEST_1 permit 10" -c "set as-path prepend 11111" -c "exit" -c "end"'
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh -c "config" -c "route-map AGG_TEST_2 permit 10" -c "set as-path prepend 22222" -c "exit" -c "end"'
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    # Assign the route maps to networks
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
          -c "network 1.1.1.0/24 route-map AGG_TEST_1" -c "network 1.1.2.0/24 route-map AGG_TEST_1" \
          -c "network 1.1.3.0/24 route-map AGG_TEST_2" -c "network 1.1.4.0/24 route-map AGG_TEST_2" \
          -c "network 1.1.5.0/24" -c "address-family ipv6 unicast" -c "network 1:1:1:1::/64 route-map AGG_TEST_1" \
          -c "network 1:1:1:2::/64 route-map AGG_TEST_1" -c "network 1:1:1:3::/64 route-map AGG_TEST_2" \
          -c "network 1:1:1:4::/64 route-map AGG_TEST_2" -c "network 1:1:1:5::/64 route-map AGG_TEST_2"'.format(
              gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    verify_route_agg(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], "5", False)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure summary-only route aggregation
    agg_configuration(True, gather_info['dut_asn'], gather_info['duthost'],
                      gather_info['cli_options'], "summary-only", "summary-only")
    logger.debug(gather_info['duthost'].shell('vtysh -c "show run bgp"', module_ignore_errors=True)['stdout'])
    verify_route_agg(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], "1", False)

    # Remove the aggregate configuration
    agg_configuration(False, gather_info['dut_asn'], gather_info['duthost'],
                      gather_info['cli_options'], "summary-only", "summary-only")
    verify_route_agg(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], "5", False)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure as-set summary-only route aggregation
    agg_configuration(True, gather_info['dut_asn'], gather_info['duthost'],
                      gather_info['cli_options'], "as-set summary-only", "as-set summary-only")
    logger.debug(gather_info['duthost'].shell('vtysh -c "show run bgp"', module_ignore_errors=True)['stdout'])
    verify_route_agg(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], "1", False,
                     as_set=True)

    # Remove the aggregate configuration
    agg_configuration(False, gather_info['dut_asn'], gather_info['duthost'],
                      gather_info['cli_options'], "as-set summary-only", "as-set summary-only")
    verify_route_agg(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], "5", False)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure route aggregation with suppress-map
    # Create prefix lists to be used
    cmd = 'vtysh{} -c "config" -c "ip prefix-list SUPPRESS_V4 permit 1.1.1.1/24" \
            -c "ip prefix-list SUPPRESS_V4 permit 1.1.2.1/24" \
            -c "ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:1::/64" \
            -c "ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:2::/64"' \
            .format(gather_info['cli_options'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))

    # Create route maps
    cmd = 'vtysh{} -c "config" -c "route-map SUPPRESS_RM_V4 permit 10" -c "match ip address prefix-list SUPPRESS_V4"' \
          .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh{} -c "config" -c "route-map SUPPRESS_RM_V6 permit 10" \
           -c "match ipv6 address prefix-list SUPPRESS_V6"' \
          .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    agg_configuration(True, gather_info['dut_asn'], gather_info['duthost'],
                      gather_info['cli_options'], "suppress-map SUPPRESS_RM_V4", "suppress-map SUPPRESS_RM_V6")
    logger.debug(gather_info['duthost'].shell('vtysh -c "show run bgp"', module_ignore_errors=True)['stdout'])
    verify_route_agg(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], "4", True)

    # Remove config for suppress-map
    agg_configuration(False, gather_info['dut_asn'], gather_info['duthost'],
                      gather_info['cli_options'], "suppress-map SUPPRESS_RM_V4", "suppress-map SUPPRESS_RM_V6")
    cmd = 'vtysh{} -c "config" -c "no route-map SUPPRESS_RM_V4 permit 10"'.format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh{} -c "config" -c "no route-map SUPPRESS_RM_V6 permit 10"'.format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh{} -c "config" -c "no ip prefix-list SUPPRESS_V4 permit 1.1.1.1/24" \
    -c "no ip prefix-list SUPPRESS_V4 permit 1.1.2.1/24" \
            -c "no ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:1::/64" \
            -c "no ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:2::/64"' \
            .format(gather_info['cli_options'])
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)
