'''

The test case will verify that the DUT supports 4-byte AS Number translation.

Step 1: Configure DUT and neighbor with 4-Byte ASN
Step 2: Verify 4-byte BGP session between DUT and neighbor is established
Step 3: Verify BGP is established for 4-byte neighbor and down for 2-byte neighbors
Step 3: Configure DUT to use 2-byte local-ASN for 2-byte neighbors
Step 4: Verify BGP is now established for 4-byte neighbor AND 2-byte neighbors
Step 5: Verify 2-byte neighbors receive routes from upstream 4-byte routers


'''
import logging

import pytest
import time
import textfsm
from tests.common.config_reload import config_reload

logger = logging.getLogger(__name__)
dut_4byte_asn = 400003
neighbor_4byte_asn = 400001
bgp_sleep = 120
bgp_id_textfsm = "./bgp/templates/bgp_id.template"

pytestmark = [
    pytest.mark.topology('t2')
]


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index, request):
    # verify neighbors are type sonic
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    neigh1 = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()[1]
    neigh2 = duthost.shell("show lldp table")['stdout'].split("\n")[5].split()[1]

    neighbors = dict()
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
            if v['description'] == neigh2:
                if v['ip_version'] == 4:
                    neigh2_ip_v4 = k
                elif v['ip_version'] == 6:
                    neigh2_ip_v6 = k
            assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            neighbors[v['description']] = nbrhosts[v['description']]["host"]
    if neighbors[neigh1].is_multi_asic:
        neigh_cli_options = " -n " + neigh1.get_namespace_from_asic_id(asic_index)
    else:
        neigh_cli_options = ''

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh1]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh1]['bgp']['peers'][dut_asn][1]

    dut_ip_bgp_sum = duthost.shell('show ip bgp summary')['stdout']
    neigh_ip_bgp_sum = nbrhosts[neigh1]["host"].shell('show ip bgp summary')['stdout']
    neigh2_ip_bgp_sum = nbrhosts[neigh1]["host"].shell('show ip bgp summary')['stdout']
    with open(bgp_id_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        dut_bgp_id = fsm.ParseText(dut_ip_bgp_sum)[0][0]
        neigh_bgp_id = fsm.ParseText(neigh_ip_bgp_sum)[1][0]
        neigh2_bgp_id = fsm.ParseText(neigh2_ip_bgp_sum)[1][0]

    dut_ipv4_network = duthost.shell("show run bgp | grep 'ip prefix-list'")['stdout'].split()[6]
    dut_ipv6_network = duthost.shell("show run bgp | grep 'ipv6 prefix-list'")['stdout'].split()[6]
    neigh_ipv4_network = nbrhosts[neigh1]["host"].shell("show run bgp | grep 'ip prefix-list'")['stdout'].split()[6]
    neigh_ipv6_network = nbrhosts[neigh1]["host"].shell("show run bgp | grep 'ipv6 prefix-list'")['stdout'].split()[6]

    setup_info = {
        'duthost': duthost,
        'neighhost': neighbors[neigh1],
        'neigh2host': neighbors[neigh2],
        'neigh1': neigh1,
        'neigh2': neigh2,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh1],
        'neigh2_asn': neigh_asn[neigh2],
        'asn_dict':  neigh_asn,
        'neighbors': neighbors,
        'cli_options': cli_options,
        'neigh_cli_options': neigh_cli_options,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'neigh2_ip_v4': neigh2_ip_v4,
        'neigh2_ip_v6': neigh2_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'asic_index': asic_index,
        'dut_bgp_id': dut_bgp_id,
        'neigh_bgp_id': neigh_bgp_id,
        'neigh2_bgp_id': neigh2_bgp_id,
        'dut_ipv4_network': dut_ipv4_network,
        'dut_ipv6_network': dut_ipv6_network,
        'neigh_ipv4_network': neigh_ipv4_network,
        'neigh_ipv6_network': neigh_ipv6_network
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(nbrhosts[neigh1]["host"].shell("show run bgp")['stdout']))
    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    config_reload(duthost)
    config_reload(neighbors[neigh1], is_dut=False)

    # verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            logger.debug(v['description'])
            assert v['state'] == 'established'


def test_4_byte_asn_translation(setup):
    # copy existing BGP config to a new 4-byte ASN.  Use existing route-maps for consistancy.
    cmd = 'vtysh{} \
    -c "config" \
    -c "no router bgp {}" \
    -c "router bgp {}" \
    -c "bgp router-id {}" \
    -c "bgp log-neighbor-changes" \
    -c "no bgp ebgp-requires-policy" \
    -c "no bgp default ipv4-unicast" \
    -c "bgp bestpath as-path multipath-relax" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "address-family ipv4 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map FROM_BGP_PEER_V4 in" \
    -c "neighbor {} route-map TO_BGP_PEER_V4 out" \
    -c "neighbor {} activate" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    -c "address-family ipv6 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map FROM_BGP_PEER_V6 in" \
    -c "neighbor {} route-map TO_BGP_PEER_V6 out" \
    -c "neighbor {} activate" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    '.format(setup['cli_options'], setup['dut_asn'], dut_4byte_asn, setup['dut_bgp_id'],
             setup['peer_group_v4'], setup['peer_group_v6'], setup['neigh_ip_v4'], neighbor_4byte_asn,
             setup['neigh_ip_v4'], setup['peer_group_v4'], setup['neigh_ip_v4'], setup['neigh1'], setup['neigh_ip_v4'],
             setup['neigh_ip_v4'], setup['neigh_ip_v6'], neighbor_4byte_asn, setup['neigh_ip_v6'],
             setup['peer_group_v6'], setup['neigh_ip_v6'], setup['neigh1'], setup['neigh_ip_v6'], setup['neigh_ip_v6'],
             setup['neigh2_ip_v4'], setup['neigh2_asn'], setup['neigh2_ip_v4'], setup['peer_group_v4'],
             setup['neigh2_ip_v4'], setup['neigh2'], setup['neigh2_ip_v4'], setup['neigh2_ip_v4'],
             setup['neigh2_ip_v6'], setup['neigh2_asn'], setup['neigh2_ip_v6'], setup['peer_group_v6'],
             setup['neigh2_ip_v6'], setup['neigh2'], setup['neigh2_ip_v6'], setup['neigh2_ip_v6'],
             setup['dut_ipv4_network'], setup['peer_group_v4'], setup['peer_group_v4'], setup['peer_group_v4'],
             setup['neigh_ip_v4'], setup['neigh2_ip_v4'], setup['dut_ipv6_network'], setup['peer_group_v6'],
             setup['peer_group_v6'], setup['peer_group_v6'], setup['neigh_ip_v6'], setup['neigh2_ip_v6'])
    logger.debug(setup['duthost'].shell(cmd, module_ignore_errors=True))

    # configure 4-byte ASN on neighbor device, reusing the established BGP config and route-maps
    cmd = 'vtysh{} \
    -c "config" \
    -c "no router bgp {}" \
    -c "router bgp {}" \
    -c "bgp router-id {}" \
    -c "bgp log-neighbor-changes" \
    -c "no bgp ebgp-requires-policy" \
    -c "no bgp default ipv4-unicast" \
    -c "bgp bestpath as-path multipath-relax" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} peer-group" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "neighbor {} remote-as {}" \
    -c "neighbor {} peer-group {}" \
    -c "neighbor {} description {}" \
    -c "neighbor {} timers 3 10" \
    -c "neighbor {} timers connect 10" \
    -c "address-family ipv4 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map FROM_BGP_PEER_V4 in" \
    -c "neighbor {} route-map TO_BGP_PEER_V4 out" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    -c "address-family ipv6 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map FROM_BGP_PEER_V6 in" \
    -c "neighbor {} route-map TO_BGP_PEER_V6 out" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    '.format(setup['neigh_cli_options'], setup['neigh_asn'], neighbor_4byte_asn, setup['neigh_bgp_id'],
             setup['peer_group_v4'], setup['peer_group_v6'], setup['dut_ip_v4'], dut_4byte_asn, setup['dut_ip_v4'],
             setup['peer_group_v4'], setup['dut_ip_v4'], 'DUT', setup['dut_ip_v4'], setup['dut_ip_v4'],
             setup['dut_ip_v6'], dut_4byte_asn, setup['dut_ip_v6'], setup['peer_group_v6'], setup['dut_ip_v6'], 'DUT',
             setup['dut_ip_v6'], setup['dut_ip_v6'], setup['neigh_ipv4_network'], setup['peer_group_v4'],
             setup['peer_group_v4'], setup['peer_group_v4'], setup['dut_ip_v4'], setup['neigh_ipv6_network'],
             setup['peer_group_v6'], setup['peer_group_v6'], setup['peer_group_v6'], setup['dut_ip_v6'])

    logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))

    logger.debug("DUT BGP Config: {}".format(setup['duthost'].shell("show run bgp")['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(setup['neighhost'].shell("show run bgp")['stdout']))

    time.sleep(bgp_sleep)

    # verify session to 4-byte neighbor is established and 2-byte neighbor is down
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() == setup['neigh1']:
            logger.debug(v['description'])
            assert v['state'] == 'established'
        elif v['description'].lower() == setup['neigh2']:
            logger.debug(v['description'])
            assert v['state'] != 'established'

    # Configure DUT to use 2-byte local-ASN for 2-byte neighbors
    cmd = 'vtysh{} \
    -c "config" \
    -c "router bgp {}" \
    -c "neighbor {} local-as {}" \
    -c "neighbor {} local-as {}" \
    '.format(setup['cli_options'], dut_4byte_asn, setup['peer_group_v4'], setup['dut_asn'], setup['peer_group_v6'],
             setup['dut_asn'])
    logger.debug(setup['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "clear bgp *"'.format(setup['cli_options'])
    logger.debug(setup['duthost'].shell(cmd, module_ignore_errors=True))

    time.sleep(bgp_sleep)

    # verify session to 4-byte and 2-byte neighbor is established
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() == setup['neigh1']:
            logger.debug(v['description'])
            assert v['state'] == 'established'
        elif v['description'].lower() == setup['neigh2']:
            logger.debug(v['description'])
            assert v['state'] == 'established'

    cmd = 'vtysh -c "show bgp ipv4 all neighbors {}" received-routes'.format(setup['neigh_ipv4_network'])
    logger.debug(setup['neigh2host'].shell(cmd, module_ignore_errors=True))
