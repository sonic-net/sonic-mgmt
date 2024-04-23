"""
Test BGP Route Aggregation

Step 1: Ensure EBGP neighborship between DUT and NEI_DUT
Step 2: Capture the route summary advertized on NEI_DUT
Step 3: Aggregate EBGP routes
Step 4: Verify aggregated EBGP routes on NEI_DUT
Step 5: Aggregate EBGP routes with 'as-set'
Step 6: Verify aggregated EBGP routes on NEI_DUT include AS-path

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


def agg_configuration(config, asn, duthost, neighbor, cli_options, commandv4, commandv6):
    remove_tag = ""
    if not config:
        remove_tag = "no "
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "{}address-family ipv4 unicast" \
    -c "aggregate-address {} {}" -c "{}address-family ipv6 unicast" \
    -c "aggregate-address {} {}"'.format(cli_options, asn, remove_tag, NEI_IPv4_AGG_ROUTE, commandv4, remove_tag,
                                         NEI_IPv6_AGG_ROUTE, commandv6)
    logger.debug(duthost.shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "clear bgp *"'.format(cli_options)
    duthost.shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh -c "clear bgp *"'
    neighbor.shell(cmd, module_ignore_errors=True)
    time.sleep(establish_bgp_session_time)


def verify_route_agg(neighbor, num_matches, suppress):
    output = neighbor.shell("show ip bgp summary", module_ignore_errors=True)['stdout']
    logger.debug(output)
    assert num_matches == output.split("\n")[11].split()[9]
    output = neighbor.shell("show ipv6 bgp summary", module_ignore_errors=True)['stdout']
    logger.debug(output)
    assert num_matches == output.split("\n")[11].split()[9]
    output = neighbor.shell("show ip route | grep \"*1.1.\"", module_ignore_errors=True)['stdout']
    logger.debug(output)
    assert NEI_IPv4_AGG_ROUTE in output
    assert "1.1.1.0/24" not in output
    assert "1.1.2.0/24" not in output
    assert "1.1.3.0/24" not in output
    output = neighbor.shell("show ipv6 route | grep \"*1:1:\"", module_ignore_errors=True)['stdout']
    logger.debug(output)
    assert NEI_IPv6_AGG_ROUTE in output
    assert "1:1:1:1::/64" not in output
    assert "1:1:1:2::/64" not in output
    assert "1:1:1:3::/64" not in output
    if not suppress:
        assert "1.1.4.0/24" not in output
        assert "1.1.5.0/24" not in output
        assert "1:1:1:4::/64" not in output
        assert "1:1:1:5::/64" not in output


def test_ebgp_route_aggregation(gather_info):
    # Configure and Advertise Loopback Networks on DUT
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

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
          -c "network 1.1.1.0/24" -c "network 1.1.2.0/24" -c "network 1.1.3.0/24" -c "network 1.1.4.0/24" \
          -c "network 1.1.5.0/24" -c "address-family ipv6 unicast" -c "network 1:1:1:1::/64" -c "network 1:1:1:2::/64"\
          -c "network 1:1:1:3::/64" -c "network 1:1:1:4::/64" -c "network 1:1:1:5::/64"'.format(
              gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['neighhost'].shell("show ip bgp summary", module_ignore_errors=True)['stdout'])
    output = gather_info['neighhost'].shell("show ip bgp summary", module_ignore_errors=True)['stdout'].split("\n")[11]
    assert "6" == output.split()[9]
    output = gather_info['neighhost'].shell("show ipv6 bgp summary", module_ignore_errors=True)['stdout'].split("\n")
    assert "6" == output[11].split()[9]

    # Configure summary-only route aggregation
    agg_configuration(True, gather_info['dut_asn'], gather_info['duthost'], gather_info['neighhost'],
                      gather_info['cli_options'], "summary-only", "summary-only")
    verify_route_agg(gather_info['neighhost'], "2", False)

    # Remove the aggregate configuration
    agg_configuration(False, gather_info['dut_asn'], gather_info['duthost'], gather_info['neighhost'],
                      gather_info['cli_options'], "summary-only", "summary-only")

    # Configure as-set summary-only route aggregation
    agg_configuration(True, gather_info['dut_asn'], gather_info['duthost'], gather_info['neighhost'],
                      gather_info['cli_options'], "as-set summary-only", "as-set summary-only")
    verify_route_agg(gather_info['neighhost'], "2", False)

    # Remove the aggregate configuration
    agg_configuration(False, gather_info['dut_asn'], gather_info['duthost'], gather_info['neighhost'],
                      gather_info['cli_options'], "as-set summary-only", "as-set summary-only")

    # Configure route aggregation with suppress-map
    # Create prefix lists to be used
    cmd = 'vtysh{} -c "config" -c "ip prefix-list SUPPRESS_V4 permit 1.1.1.0/24" \
            -c "ip prefix-list SUPPRESS_V4 permit 1.1.2.0/24" -c "ip prefix-list SUPPRESS_V4 permit 1.1.3.0/24" \
            -c "ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:1::/64" \
            -c "ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:2::/64" \
            -c "ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:3::/64"' \
            .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)

    # Create route maps
    cmd = 'vtysh{} -c "config" -c "route-map SUPPRESS_RM_V4 permit 10" -c "match ip address prefix-list SUPPRESS_V4"' \
          .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh{} -c "config" -c "route-map SUPPRESS_RM_V6 permit 10" \
           -c "match ipv6 address prefix-list SUPPRESS_V6"' \
          .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    agg_configuration(True, gather_info['dut_asn'], gather_info['duthost'], gather_info['neighhost'],
                      gather_info['cli_options'], "suppress-map SUPPRESS_RM_V4", "suppress-map SUPPRESS_RM_V6")
    logger.debug(gather_info['neighhost'].shell("show ip bgp summary", module_ignore_errors=True)['stdout'])
    logger.debug(gather_info['neighhost'].shell("show ipv6 bgp summary", module_ignore_errors=True)['stdout'])
    logger.debug(gather_info['duthost'].shell('vtysh -c "show run bgp"', module_ignore_errors=True)['stdout'])
    verify_route_agg(gather_info['neighhost'], "4", True)

    # Remove config for suppress-map
    agg_configuration(False, gather_info['dut_asn'], gather_info['duthost'], gather_info['neighhost'],
                      gather_info['cli_options'], "suppress-map SUPPRESS_RM_V4", "suppress-map SUPPRESS_RM_V6")
    cmd = 'vtysh{} -c "config" -c "no route-map SUPPRESS_RM_V4 permit 10"'.format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh{} -c "config" -c "no route-map SUPPRESS_RM_V6 permit 10"'.format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh{} -c "config" -c "no ip prefix-list SUPPRESS_V4 permit 1.1.1.0/24" \
    -c "no ip prefix-list SUPPRESS_V4 permit 1.1.2.0/24" -c "no ip prefix-list SUPPRESS_V4 permit 1.1.3.0/24" \
            -c "no ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:1::/64" \
            -c "no ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:2::/64" \
            -c "no ipv6 prefix-list SUPPRESS_V6 permit 1:1:1:3::/64"' \
            .format(gather_info['cli_options'])
