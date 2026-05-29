import pytest
import logging
import time
import re

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]


def test_ospf_neighborship(ospf_setup, duthosts, rand_one_dut_hostname):
    setup_info_nbr_addr = ospf_setup['nbr_addr']
    neigh_ip_addrs = list(setup_info_nbr_addr.values())
    duthost = duthosts[rand_one_dut_hostname]

    # Check get existing bgp routes on the DUT
    original_prefixes = ospf_setup['bgp_routes']

    # Configure OSPF neighbors in DUT if not already configured
    ospf_configured = False
    cmd = 'vtysh -c "show ip ospf neighbor"'
    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    for neighbor in ospf_neighbors:
        if ("ospfd is not running" not in neighbor) and (neighbor != "") and ("Neighbor ID" not in neighbor):
            ospf_configured = True

    if not ospf_configured:
        cmd_list = [
            'docker exec -it bgp bash',
            'cd /usr/lib/frr',
            './ospfd &',
            'exit',
            'vtysh',
            'config t',
            'no router bgp',
            'router ospf'
        ]

        for ip_addr in neigh_ip_addrs:
            cmd_list.append('network {}/31 area 0'.format(str(ip_addr)))

        cmd_list.extend([
            'do write',
            'end',
            'exit'
        ])

        duthost.shell_cmds(cmd_list)
        time.sleep(5)

    # Verify old BGP routes are available as OSPF routes in the DUT
    cmd = 'vtysh -c "show ip ospf neighbor"'
    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    for neighbor in ospf_neighbors:
        if (neighbor != "") and ("Neighbor ID" not in neighbor):
            assert "Full" in neighbor

    # Compare new OSPF prefixes with old BGP prefixes
    cmd = "show ip route ospf"
    ospf_routes = duthost.shell(cmd)['stdout']
    ospf_routes_pattern = re.compile(r'O>\*(\d+\.\d+\.\d+\.\d+/\d+)')
    new_prefixes = ospf_routes_pattern.findall(ospf_routes).sort()

    assert original_prefixes == new_prefixes


def test_ospf_dynamic_routing(ospf_setup, duthosts, rand_one_dut_hostname, nbrhosts):
    setup_info_nbr_addr = ospf_setup['nbr_addr']
    neigh_ip_addrs = list(setup_info_nbr_addr.values())
    duthost = duthosts[rand_one_dut_hostname]

    # Add loopback interface in the first neighboring device
    first_nbr = list(nbrhosts.keys())[0]
    loopback_cmd = "config interface ip add Loopback10 192.168.10.1/32"
    nbrhosts[first_nbr]["host"].shell(loopback_cmd)

    # Advertise newly created loopback network to the DUT via OSPF
    advertise_network_cmd = "vtysh -c 'config terminal' -c 'router ospf' -c 'network 192.168.10.1/32 area 0'"
    nbrhosts[first_nbr]["host"].shell(advertise_network_cmd)

    # Check OSPF already configured in DUT
    ospf_configured = False
    cmd = 'vtysh -c "show ip ospf neighbor"'
    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    for neighbor in ospf_neighbors:
        if ("ospfd is not running" not in neighbor) and (neighbor != "") and ("Neighbor ID" not in neighbor):
            ospf_configured = True

    # Configure OSPF neighbors in DUT if not already configured
    if not ospf_configured:
        cmd_list = [
            'docker exec -it bgp bash',
            'cd /usr/lib/frr',
            './ospfd &',
            'exit',
            'vtysh',
            'config t',
            'no router bgp',
            'router ospf'
        ]

        for ip_addr in neigh_ip_addrs:
            cmd_list.append('network {}/31 area 0'.format(str(ip_addr)))

        cmd_list.extend([
            'do write',
            'end',
            'exit'
        ])

        duthost.shell_cmds(cmd_list)
        time.sleep(5)

    # Verify OSPF neighborship successfully established and loopback route shared to the DUT
    cmd = 'vtysh -c "show ip ospf neighbor"'
    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    for neighbor in ospf_neighbors:
        if (neighbor != "") and ("Neighbor ID" not in neighbor):
            assert "Full" in neighbor
    route_found = False
    cmd = 'show ip route ospf'
    ospf_routes = duthost.shell(cmd)['stdout'].split("\n")
    for route in ospf_routes:
        if '192.168.10.1/32' in route:
            route_found = True
            break
    assert route_found is True

    # Simulate link down by removing loopback interface from neighbor
    rem_loopback_cmd = "config interface ip remove Loopback10 192.168.10.1/32"
    nbrhosts[first_nbr]["host"].shell(rem_loopback_cmd)
    time.sleep(5)

    # Verify that loopback route is not present in DUT
    route_found = False
    cmd = 'show ip route ospf'
    ospf_routes = duthost.shell(cmd)['stdout'].split("\n")
    for route in ospf_routes:
        if '192.168.10.1/32' in route:
            route_found = True
            break
    assert route_found is False
