'''

This script is to Verify applied policies manipulate traffic as
expected for the configured routes.

Step 1: 
Step 2: 

'''
import logging

import pytest
import time
import textfsm
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)
dut_4byte_asn = 400003
neighbor_4byte_asn = 400001
bgp_sleep = 60
bgp_id_textfsm = "./bgp/templates/bgp_id.template"

pytestmark = [
    pytest.mark.topology('t2')
]


def verify_rm(dut, nei_ip, cli_options, ipX, route_map, prefix_list, route_count, match_prefix):
    cmd = 'vtysh{} -c "show route-map {}"'.format(cli_options, route_map)
    output = dut.shell(cmd, module_ignore_errors=True)['stdout']
    logger.info(output)
    assert route_map in output
    assert prefix_list in output

    if ipX == "ipv4":
        output = dut.shell("show ip bgp neighbors {} routes".format(nei_ip))['stdout']
    elif ipX == "ipv6":
        output = dut.shell("show ipv6 bgp neighbors {} routes".format(nei_ip))['stdout']
    # logger.info(output)
    if route_count == "0":
        assert output == ""
    else:
        assert "Displayed  {} routes".format(route_count) in output
        assert match_prefix in output

def test_policy(gather_info):
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

     # Create prefix lists to be used
    cmd = 'vtysh{} -c "config" -c "ip prefix-list DEFAULT_V4 permit 0.0.0.0/0" \
            -c "ipv6 prefix-list DEFAULT_V6 permit 0::/0"' \
            .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)

    # Create route maps
    cmd = 'vtysh{} -c "config" -c "route-map DEFAULT_RM_V4 permit 10" -c "match ip address prefix-list DEFAULT_V4"' \
          .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    cmd = 'vtysh{} -c "config" -c "route-map DEFAULT_RM_V6 permit 10" -c "match ipv6 address prefix-list DEFAULT_V6"' \
          .format(gather_info['cli_options'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    # agg_configuration(True, gather_info['dut_asn'], gather_info['duthost'], gather_info['neighhost'],
    #                   gather_info['cli_options'], "suppress-map SUPPRESS_RM_V4", "suppress-map SUPPRESS_RM_V6")
    logger.debug(gather_info['neighhost'].shell("show ip bgp summary", module_ignore_errors=True)['stdout'])
    logger.debug(gather_info['neighhost'].shell("show ipv6 bgp summary", module_ignore_errors=True)['stdout'])
    logger.debug(gather_info['duthost'].shell('vtysh -c "show run bgp"', module_ignore_errors=True)['stdout'])
    # verify_route_agg(gather_info['neighhost'], "4", True)

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "neighbor {} route-map DEFAULT_RM_V4 in" \
           -c "neighbor {} route-map DEFAULT_RM_V6 in"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'], 
                  gather_info['neigh_ip_v6'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(10)
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4", "DEFAULT_RM_V4", 
              "DEFAULT_V4", "1", "0.0.0.0/0")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6", "DEFAULT_RM_V6", 
              "DEFAULT_V6", "1", "::/0")
    
    # remove route-map to neighbor
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "no neighbor {} route-map DEFAULT_RM_V4 in" \
           -c "no neighbor {} route-map DEFAULT_RM_V6 in"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'], 
                  gather_info['neigh_ip_v6'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    time.sleep(10)
