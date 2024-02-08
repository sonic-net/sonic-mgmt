'''

The test case will verify that forcing a macsec policy delete and add behaves as intended.

Step 1: 
Step 2: 
Step 3: 
Step 3: 
Step 4: 
Step 5: 


'''
import logging

import pytest
import time
# import textfsm
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)
# dut_4byte_asn = 400003
# neighbor_4byte_asn = 400001
# bgp_sleep = 60
# bgp_id_textfsm = "./bgp/templates/bgp_id.template"

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology('t2')
]


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, request):
    # verify neighbors are type sonic
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")

    duthost = duthosts[enum_frontend_dut_hostname]
    # asic_index = enum_rand_one_frontend_asic_index
    # namespace = duthost.get_namespace_from_asic_id(asic_index)
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    logger.debug("lldp table: {}".format(lldp_table))
    neigh1 = lldp_table[1]
    # neigh2 = duthost.shell("show lldp table")['stdout'].split("\n")[5].split()[1]
    dut_int = lldp_table[0]
    neigh_int = lldp_table[2]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_int).asic_index
    else:
        asic_index = None

    if nbrhosts[neigh1]["host"].is_multi_asic:
        neigh_asic_index = nbrhosts[neigh1]["host"].get_port_asic_instance(neigh_int).asic_index
    else:
        neigh_asic_index = None

    namespace = duthost.get_namespace_from_asic_id(asic_index)
    time.sleep(60)

    # neighbors = dict()
    skip_hosts = duthost.get_asic_namespace_list()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == neigh1:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
            # if v['description'] == neigh2:
            #     if v['ip_version'] == 4:
            #         neigh2_ip_v4 = k
            #     elif v['ip_version'] == 6:
            #         neigh2_ip_v6 = k
                logger.debug("neigh {} is in {} state".format(v['description'], v['state']))
                assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            # neighbors[v['description']] = nbrhosts[v['description']]["host"]

    # verify macsec connection is established
    macsec_state = duthost.shell("show macsec {}".format(dut_int))['stdout_lines'][3].split()
    assert macsec_state[1] == "true"

    ns = '-n ' + str(asic_index) if asic_index is not None else ''

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh1]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh1]['bgp']['peers'][dut_asn][1]

    # dut_ip_bgp_sum = duthost.shell('show ip bgp summary')['stdout']
    # neigh_ip_bgp_sum = nbrhosts[tor1]["host"].shell('show ip bgp summary')['stdout']
    # neigh2_ip_bgp_sum = nbrhosts[tor1]["host"].shell('show ip bgp summary')['stdout']
    # with open(bgp_id_textfsm) as template:
    #     fsm = textfsm.TextFSM(template)
    #     dut_bgp_id = fsm.ParseText(dut_ip_bgp_sum)[0][0]
    #     neigh_bgp_id = fsm.ParseText(neigh_ip_bgp_sum)[1][0]
    #     neigh2_bgp_id = fsm.ParseText(neigh2_ip_bgp_sum)[1][0]

    # dut_ipv4_network = duthost.shell("show run bgp | grep 'ip prefix-list'")['stdout'].split()[6]
    # dut_ipv6_network = duthost.shell("show run bgp | grep 'ipv6 prefix-list'")['stdout'].split()[6]
    # neigh_ipv4_network = nbrhosts[tor1]["host"].shell("show run bgp | grep 'ip prefix-list'")['stdout'].split()[6]
    # neigh_ipv6_network = nbrhosts[tor1]["host"].shell("show run bgp | grep 'ipv6 prefix-list'")['stdout'].split()[6]

    setup_info = {
        'duthost': duthost,
        'neighhost': nbrhosts[neigh1],
        # 'neigh2host': neighbors[neigh2],
        'neigh1': neigh1,
        # 'neigh2': neigh2,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh1],
        # 'neigh2_asn': neigh_asn[neigh2],
        'asn_dict':  neigh_asn,
        # 'neighbors': nbrhosts,
        'namespace': namespace,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        # 'neigh2_ip_v4': neigh2_ip_v4,
        # 'neigh2_ip_v6': neigh2_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'asic_index': asic_index,
        'neigh_asic_index': neigh_asic_index,
        'dut_int': dut_int,
        'ns': ns,
        # 'dut_bgp_id': dut_bgp_id,
        # 'neigh_bgp_id': neigh_bgp_id,
        # 'neigh2_bgp_id': neigh2_bgp_id,
        # 'dut_ipv4_network': dut_ipv4_network,
        # 'dut_ipv6_network': dut_ipv6_network,
        # 'neigh_ipv4_network': neigh_ipv4_network,
        # 'neigh_ipv6_network': neigh_ipv6_network
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(nbrhosts[neigh1]["host"].shell("show run bgp")['stdout']))
    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    config_reload(duthost)
    config_reload(nbrhosts[neigh1]["host"], is_dut=False)
    time.sleep(60)

    # verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == neigh1:
                # logger.info(v['description'])
                logger.info("neigh {} is in {} state".format(v['description'], v['state']))
                assert v['state'] == 'established'


def test_delete_add_policy(setup, startup_macsec, shutdown_macsec):
    
    # cmd = 'vtysh -n {} -c "test macsec mka rekey interface {}"'.format(setup['ns'], setup['dut_int'])

    # command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)

    # if len(command_output["stdout_lines"]) != 0:
    #     logger.error("Error when resetting macsec key")
    #     return False
    
    # logger.info("Macsec profile: {}".format(macsec_profile))
    # logger.info("done w test")
    shutdown_macsec()

    macsec_state = setup['duthost'].shell("show macsec {}".format(setup['dut_int']))['stdout_lines'][3].split()
    assert macsec_state[1] == "false"

    startup_macsec()

    macsec_state = setup['duthost'].shell("show macsec {}".format(setup['dut_int']))['stdout_lines'][3].split()
    assert macsec_state[1] == "true"