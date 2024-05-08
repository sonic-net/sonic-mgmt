'''

This script is to Verify applied communities manipulate traffic as
expected between 4-byte and 2-byte AS neighbors.

Step 1: Configure DUT and neighbor with 4Byte ASN
Step 2: Verify 4-byte BGP session between DUT and neighbor is established

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
    # verify neighbors are type sonic and skip if not
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + duthost.get_namespace_from_asic_id(asic_index)
    else:
        cli_options = ''

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    neigh = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()[1]
    logger.debug("Neighbor is: {}".format(neigh))

    neighbors = dict()
    skip_hosts = duthost.get_asic_namespace_list()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == neigh:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
            assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']
            neighbors[v['description']] = nbrhosts[v['description']]["host"]

    if neighbors[neigh].is_multi_asic:
        neigh_cli_options = " -n " + neigh.get_namespace_from_asic_id(asic_index)
    else:
        neigh_cli_options = ''

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][1]

    dut_ip_bgp_sum = duthost.shell('show ip bgp summary')['stdout']
    neigh_ip_bgp_sum = nbrhosts[neigh]["host"].shell('show ip bgp summary')['stdout']
    with open(bgp_id_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        dut_bgp_id = fsm.ParseText(dut_ip_bgp_sum)[0][0]
        neigh_bgp_id = fsm.ParseText(neigh_ip_bgp_sum)[1][0]

    dut_ipv4_network = duthost.shell("show run bgp | grep 'ip prefix-list'")['stdout'].split()[6]
    dut_ipv6_network = duthost.shell("show run bgp | grep 'ipv6 prefix-list'")['stdout'].split()[6]
    neigh_ipv4_network = nbrhosts[neigh]["host"].shell("show run bgp | grep 'ip prefix-list'")['stdout'].split()[6]
    neigh_ipv6_network = nbrhosts[neigh]["host"].shell("show run bgp | grep 'ipv6 prefix-list'")['stdout'].split()[6]

    setup_info = {
        'duthost': duthost,
        'neighhost': neighbors[neigh],
        'neigh': neigh,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh],
        'asn_dict':  neigh_asn,
        'neighbors': neighbors,
        'cli_options': cli_options,
        'neigh_cli_options': neigh_cli_options,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'asic_index': asic_index,
        'dut_bgp_id': dut_bgp_id,
        'neigh_bgp_id': neigh_bgp_id,
        'dut_ipv4_network': dut_ipv4_network,
        'dut_ipv6_network': dut_ipv6_network,
        'neigh_ipv4_network': neigh_ipv4_network,
        'neigh_ipv6_network': neigh_ipv6_network
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(nbrhosts[neigh]["host"].shell("show run bgp")['stdout']))
    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    config_reload(duthost)
    config_reload(neighbors[neigh], is_dut=False)

    # verify sessions are established
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            logger.debug(v['description'])
            assert v['state'] == 'established'


def test_4_byte_asn_community(setup):
    # configure BGP with 4-byte ASN using the standard T2 config and existing route-maps on DUT
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
    '.format(setup['cli_options'], setup['dut_asn'], dut_4byte_asn, setup['dut_bgp_id'],
             setup['peer_group_v4'], setup['peer_group_v6'], setup['neigh_ip_v4'], neighbor_4byte_asn,
             setup['neigh_ip_v4'], setup['peer_group_v4'], setup['neigh_ip_v4'], setup['neigh'], setup['neigh_ip_v4'],
             setup['neigh_ip_v4'], setup['neigh_ip_v6'], neighbor_4byte_asn, setup['neigh_ip_v6'],
             setup['peer_group_v6'], setup['neigh_ip_v6'], setup['neigh'], setup['neigh_ip_v6'], setup['neigh_ip_v6'],
             setup['dut_ipv4_network'], setup['peer_group_v4'], setup['peer_group_v4'], setup['peer_group_v4'],
             setup['neigh_ip_v4'], setup['dut_ipv6_network'], setup['peer_group_v6'], setup['peer_group_v6'],
             setup['peer_group_v6'], setup['neigh_ip_v6'])
    logger.debug(setup['duthost'].shell(cmd, module_ignore_errors=True))

    # configure BGP with 4-byte ASN using the standard T2 config and existing route-maps on neighbor device
    cmd = 'vtysh{}\
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

    output = setup['duthost'].shell("show ip bgp summary | grep {}".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ipv6 bgp summary | grep {}".format(setup['neigh_ip_v6'].lower()))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ip bgp neighbors {} routes".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in str(output.split('\n')[9].split()[5])
    output = setup['duthost'].shell("show ipv6 bgp neighbors {} routes".format(setup['neigh_ip_v6'].lower()))['stdout']
    assert str(neighbor_4byte_asn) in str(output.split('\n')[9].split()[5])

    output = setup['neighhost'].shell("show ip bgp summary | grep {}".format(setup['dut_ip_v4']))['stdout']
    assert str(dut_4byte_asn) in output.split()[2]
    output = setup['neighhost'].shell("show ipv6 bgp summary | grep {}".format(setup['dut_ip_v6'].lower()))['stdout']
    assert str(dut_4byte_asn) in output.split()[2]
    output = setup['neighhost'].shell("show ip bgp neighbors {} routes".format(setup['dut_ip_v4']))['stdout']
    assert str(dut_4byte_asn) in str(output.split('\n')[9].split()[5])
    output = setup['neighhost'].shell("show ipv6 bgp neighbors {} routes".format(setup['dut_ip_v6'].lower()))['stdout']
    assert str(dut_4byte_asn) in str(output.split('\n')[9].split()[5])
