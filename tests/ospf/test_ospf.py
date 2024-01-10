import random
import pytest
import ipaddress
import logging
import ptf.testutils as testutils
import six
import time
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0')
]

@pytest.fixture(scope='module')
def ospf_setup(duthosts, rand_one_dut_hostname, ptfhost, nbrhosts, tbinfo, request):

    # verify neighbors are type sonic
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    
    duthost = duthosts[rand_one_dut_hostname]

    setup_info = {}

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for a_bgp_nbr in mg_facts['minigraph_bgp']:
        setup_info[a_bgp_nbr['name']] = a_bgp_nbr['addr']
    
    for neigh_name in list(nbrhosts.keys()):
        ip_addr = None
        neigh_mg_facts = nbrhosts[neigh_name]["host"].minigraph_facts(host = nbrhosts[neigh_name]["host"].hostname)
        for neigh_bgp_nbr in neigh_mg_facts['minigraph_bgp']:
            if neigh_bgp_nbr['name'] == duthost.hostname:
                ip_addr = neigh_bgp_nbr['addr']
                break
        cmd_list = [
            'docker exec -it bgp bash',
            'cd /usr/lib/frr',
            './ospfd &',
            'exit',
            'vtysh',
            'config t',
            'no router bgp',
            'router ospf',
            'network {}/31 area 0'.format(str(ip_addr)),
            'do write',
            'end',
            'exit'
        ]
        nbrhosts[neigh_name]["host"].shell_cmds(cmd_list)


    yield setup_info

    # restore config to original state on both DUT and neighbor
    config_reload(duthost, safe_reload=True)
    time.sleep(10)
    for neigh_name in list(nbrhosts.keys()):
        config_reload(nbrhosts[neigh_name]["host"], is_dut=False)


@pytest.mark.topology('t0') #Test will run only if topology is given as t0 or not given
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

@pytest.mark.topology('t0') #Test will run only if topology is given as t0 or not given
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
    
    #SIMULATE LINK DOWN
    
    ospf_neighbors = duthost.shell(cmd)['stdout'].split("\n")
    neighbor_found = False
    for neighbor in ospf_neighbors:
        if (neighbor != "") and (neighbor[:11] != "Neighbor ID"):
            neighbor_found = neighbor.split()[0] == "10.250.0.51"
    
    assert neighbor_found == False