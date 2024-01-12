'''
Conftest file for OSPF tests
'''

import pytest
import time
from tests.common.config_reload import config_reload


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
        neigh_mg_facts = nbrhosts[neigh_name]["host"].minigraph_facts(host=nbrhosts[neigh_name]["host"].hostname)
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
