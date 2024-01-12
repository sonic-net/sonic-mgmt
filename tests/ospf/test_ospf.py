import pytest
import logging
import time

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]


@pytest.mark.topology('t0')
def test_ospf_neighborship(ospf_setup, duthosts, rand_one_dut_hostname):
    setup_info = ospf_setup
    neigh_ip_addrs = list(setup_info.values())

    duthost = duthosts[rand_one_dut_hostname]

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

    cmd = "vtysh -c show ip ospf neighbor"

    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    for neighbor in ospf_neighbors:
        if (neighbor != "") and (neighbor[:11] != "Neighbor ID"):
            assert neighbor.split()[2][:4] == "Full"


@pytest.mark.topology('t0')
def test_ospf_dynamic_routing(ospf_setup, duthosts, rand_one_dut_hostname):

    setup_info = ospf_setup
    neigh_ip_addrs = list(setup_info.values())

    duthost = duthosts[rand_one_dut_hostname]

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

    cmd = 'vtysh -c "show ip ospf neighbor"'

    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    for neighbor in ospf_neighbors:
        if (neighbor != "") and (neighbor[:11] != "Neighbor ID"):
            assert neighbor.split()[2][:4] == "Full"

    # SIMULATE LINK DOWN

    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    neighbor_found = False
    for neighbor in ospf_neighbors:
        if (neighbor != "") and (neighbor[:11] != "Neighbor ID"):
            neighbor_found = neighbor.split()[0] == "10.250.0.51"

    assert neighbor_found is False
