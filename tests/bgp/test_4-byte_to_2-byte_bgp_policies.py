'''

The test case will verify that the applied 4-Byte(DUT) to 2-Byte(neighbor)
policies manipulate traffic as expected for the configured routes.

1: Configure DUT with 4-Byte ASN and update neighbor configuration with DUT's 4-Byte ASN
2: Verify BGP session between DUT(4-Byte) and neighbor(2-Byte) is established
3: Configure loopback interfaces to advertise.
4: Configure and verify policy to permit only Default Route
5: Configure and verify policy to permit only the first two prefixes
6: Configure and verify policy with AS-path prepend
7: Configure and verify AS-path access list using Regexp (matching)
8: Configure and verify AS-path access list using Regexp (non-matching)
9: Configure and verify Community-list policy to permit only first two routes
10: Configure and verify Community-list policy to permit remaining Routes
11: Configure and verify Community-list policy to permit only first two routes using regexp
12: Configure and verify Community-list policy to permit remaining Routes using regexp


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
    neigh = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()[1]

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
    logger.info('Setup_info: {}'.format(setup_info))

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


@pytest.fixture(scope='session')
def get_test_routes(gather_info):

    # gather IPv4 routes
    cmd = 'vtysh{} -c "show ip bgp neighbors {} advertised-routes"'.format(gather_info['cli_options'],
                                                                           gather_info['neigh_ip_v4'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    split_out = output.split("\n")
    list_route_v4 = []
    test_route_v4 = []
    i = 0
    for line in split_out:
        if str(gather_info['neigh_asn']) in line:
            list_route_v4.append(line)
            i = i + 1
            if i > 3:
                break
    for line in list_route_v4:
        temp = line.split()
        test_route_v4.append(temp[1])

    # gather IPv6 routes
    cmd = 'vtysh{} -c "show bgp ipv6 neighbors {} advertised-routes"'.format(gather_info['cli_options'],
                                                                             gather_info['neigh_ip_v6'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    split_out = output.split("\n")
    logger.info(output)
    list_route_v6 = []
    test_route_v6 = []
    i = 0
    for line in split_out:
        if str(gather_info['neigh_asn']) in line:
            logger.info(line)
            list_route_v6.append(line)
            i = i + 1
            if i > 3:
                break
    for line in list_route_v6:
        temp = line.split()
        test_route_v6.append(temp[1])
    return test_route_v4, test_route_v6


def verify_rm(dut, nei_ip, cli_options, ipX, route_map, prefix_list, route_count):
    cmd = 'vtysh{} -c "show route-map {}"'.format(cli_options, route_map)
    output = dut.shell(cmd, module_ignore_errors=True)['stdout']
    logger.debug(output)
    assert route_map in output
    assert prefix_list in output

    ip = "ip"
    grep = ' | grep -c "*>"'
    if ipX == "ipv6":
        ip = "ipv6"
    if route_count == "0":
        grep = ''
    output = dut.shell('show {} bgp neighbors {} advertised-routes{}'.format(ip, nei_ip, grep))['stdout']
    logger.debug("output: {}".format(output)[len(output) - 200:])
    if route_count == "0":
        assert output == ""
    else:
        assert route_count == output
        # assert match_prefix in output


def check_baseline(dut, neigh_ip_v4, neigh_ip_v6, base_v4, base_v6):
    output = dut.shell('show ip bgp neighbors {} advertised-routes | grep -c "*>"'.format(neigh_ip_v4),
                       module_ignore_errors=True)['stdout']
    logger.debug("output: {}".format(output))
    assert int(base_v4) + 5 == int(output)
    output = dut.shell('show ipv6 bgp neighbors {} advertised-routes | grep -c "*>"'.format(neigh_ip_v6),
                       module_ignore_errors=True)['stdout']
    logger.debug("output: {}".format(output))
    assert int(base_v6) + 5 == int(output)


def test_configure_4_byte_asn(setup):
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
             setup['peer_group_v4'], setup['peer_group_v6'], setup['neigh_ip_v4'], setup['neigh_asn'],
             setup['neigh_ip_v4'], setup['peer_group_v4'], setup['neigh_ip_v4'], setup['neigh'],
             setup['neigh_ip_v4'], setup['neigh_ip_v4'], setup['neigh_ip_v6'], setup['neigh_asn'],
             setup['neigh_ip_v6'], setup['peer_group_v6'], setup['neigh_ip_v6'], setup['neigh'],
             setup['neigh_ip_v6'], setup['neigh_ip_v6'], setup['dut_ipv4_network'], setup['peer_group_v4'],
             setup['peer_group_v4'], setup['peer_group_v4'], setup['neigh_ip_v4'], setup['dut_ipv6_network'],
             setup['peer_group_v6'], setup['peer_group_v6'], setup['peer_group_v6'], setup['neigh_ip_v6'])
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
    '.format(setup['neigh_cli_options'], setup['neigh_asn'], setup['neigh_asn'], setup['neigh_bgp_id'],
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

    # verify session to 4-byte neighbor is established
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() == setup['neigh']:
            logger.debug(v['description'])
            assert v['state'] == 'established'

    logger.debug(setup['duthost'].shell("show ip bgp summ", module_ignore_errors=True)['stdout'])
    logger.debug(setup['neighhost'].shell("show ip bgp summ", module_ignore_errors=True)['stdout'])


def test_4byte_to_2byte_policy(gather_info, setup):
    gather_info['dut_asn'] = dut_4byte_asn
    logger.info("gather_info: {}".format(gather_info))

    # precheck number of routes
    num_v4_routes = gather_info['duthost'].shell('show ip bgp neighbors {} advertised-routes | grep -c "*>"'.format(
        gather_info['neigh_ip_v4']))['stdout']
    num_v6_routes = gather_info['duthost'].shell('show ipv6 bgp neighbors {} advertised-routes | grep -c "*>"'.format(
        gather_info['neigh_ip_v6']))['stdout']

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

    # create initial route maps to be used for tests
    cmd = 'vtysh -c "config" -c "route-map POLICY_TEST_1 permit 10" -c "set community 65001:1" -c "set as-path prepend\
        11111" -c "route-map POLICY_TEST_2 permit 10" -c "set community 65002:2" -c "set as-path prepend 22222"'
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
          -c "network 1.1.1.0/24 route-map POLICY_TEST_1" -c "network 1.1.2.0/24 route-map POLICY_TEST_1" -c \
          "network 1.1.3.0/24 route-map POLICY_TEST_2" -c "network 1.1.4.0/24 route-map POLICY_TEST_2" \
          -c "network 1.1.5.0/24 route-map POLICY_TEST_2" -c "address-family ipv6 unicast" -c \
          "network 1:1:1:1::/64 route-map POLICY_TEST_1" -c "network 1:1:1:2::/64 route-map POLICY_TEST_1"\
          -c "network 1:1:1:3::/64 route-map POLICY_TEST_2" -c "network 1:1:1:4::/64 route-map POLICY_TEST_2" -c \
          "network 1:1:1:5::/64 route-map POLICY_TEST_2"'.format(
              gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell("show ip bgp summary", module_ignore_errors=True)['stdout'])

    # Verify loopbacks are being advertised to neighbor
    output = gather_info['duthost'].shell('show ip bgp neighbors {} advertised-routes | grep "*> 1.1."'.format(
        gather_info['neigh_ip_v4']), module_ignore_errors=True)['stdout'].split("\n")
    out_num = len(output)
    assert 5 == out_num
    logger.debug("out split: {}\nbase: {} num: {}".format(output, num_v4_routes, out_num))
    output = gather_info['duthost'].shell('show ipv6 bgp neighbors {} advertised-routes | grep "*> 1:1:"'.format(
        gather_info['neigh_ip_v6']), module_ignore_errors=True)['stdout'].split("\n")
    out_num = len(output)
    assert 5 == out_num
    logger.debug("out split: {}\nbase: {} num: {}".format(output, num_v6_routes, out_num))
    output = gather_info['duthost'].shell('show ip bgp neighbors {} advertised-routes | grep -c "*>"'.format(
        gather_info['neigh_ip_v4']), module_ignore_errors=True)['stdout']
    assert 5 + int(num_v4_routes) == int(output)
    output = gather_info['duthost'].shell('show ipv6 bgp neighbors {} advertised-routes | grep -c "*>"'.format(
        gather_info['neigh_ip_v6']), module_ignore_errors=True)['stdout']
    assert 5 + int(num_v6_routes) == int(output)

    # Create default prefix lists to be used
    cmd = 'vtysh{} -c "config" -c "ip prefix-list DEFAULT_V4 permit 0.0.0.0/0" \
            -c "ipv6 prefix-list DEFAULT_V6 permit 0::/0"' \
            .format(gather_info['cli_options'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))

    # Create route maps
    cmd = 'vtysh{} -c "config" -c "route-map DEFAULT_RM_V4 permit 10" -c "match ip address prefix-list DEFAULT_V4"' \
          .format(gather_info['cli_options'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "route-map DEFAULT_RM_V6 permit 10" -c "match ipv6 address prefix-list DEFAULT_V6"' \
          .format(gather_info['cli_options'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "show run bgp"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map DEFAULT_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map DEFAULT_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4", "DEFAULT_RM_V4",
              "DEFAULT_V4", "1")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6", "DEFAULT_RM_V6",
              "DEFAULT_V6", "1")

    # remove route-map to neighbor
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" -c \
          "no neighbor {} route-map DEFAULT_RM_V4 out" \
          -c "address-family ipv6 unicast" -c "no neighbor {} route-map DEFAULT_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    gather_info['duthost'].shell(cmd, module_ignore_errors=True)
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # permit first two prefixes only
    cmd = 'vtysh{} -c "config" -c "ip prefix-list TWO_PREFIX_V4 permit 1.1.1.1/24" \
            -c "ip prefix-list TWO_PREFIX_V4 permit 1.1.2.1/24" -c \
            "ipv6 prefix-list TWO_PREFIX_V6 permit 1:1:1:1::/64" -c \
            "ipv6 prefix-list TWO_PREFIX_V6 permit 1:1:1:2::/64"'.format(gather_info['cli_options'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))

    cmd = 'vtysh{} -c "config" -c "route-map TWO_PREFIX_RM_V4 permit 10" -c \
        "match ip address prefix-list TWO_PREFIX_V4"'.format(gather_info['cli_options'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "route-map TWO_PREFIX_RM_V6 permit 10" -c \
        "match ipv6 address prefix-list TWO_PREFIX_V6"'.format(gather_info['cli_options'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map TWO_PREFIX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map TWO_PREFIX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "2")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "2")

    # remove two prefix route map
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map TWO_PREFIX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map TWO_PREFIX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure and verify policy with AS-path prepend
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "route-map TWO_PREFIX_RM_V4 permit 10" -c \
        "set as-path prepend 12345"'.format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "route-map TWO_PREFIX_RM_V6 permit 10" -c \
        "set as-path prepend 12345"'.format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map TWO_PREFIX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map TWO_PREFIX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "2")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "2")

    # verify '12345' in AS Path
    output = gather_info['duthost'].shell('show ip bgp neighbors {} advertised-routes'.format(
        gather_info['neigh_ip_v4']))['stdout']
    logger.debug(output)
    assert '12345' in output
    output = gather_info['duthost'].shell('show ipv6 bgp neighbors {} advertised-routes'.format(
        gather_info['neigh_ip_v6']))['stdout']
    logger.debug(output)
    assert '12345' in output

    # remove two prefix route map
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map TWO_PREFIX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map TWO_PREFIX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "route-map TWO_PREFIX_RM_V4 permit 10" \
           -c "no set as-path prepend 12345" \
           -c "route-map TWO_PREFIX_RM_V6 permit 10" -c "no set as-path prepend 12345"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure and verify AS-path access list using Regexp (matching)
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "bgp as-path access-list 21 permit .*111.*" \
           -c "route-map AS_PATH_RGX_RM_V4 permit 10" -c "match as-path 21" \
           -c "route-map AS_PATH_RGX_RM_V6 permit 10" -c "match as-path 21"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map AS_PATH_RGX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map AS_PATH_RGX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "2")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "2")

    # remove as path prefix route map
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map AS_PATH_RGX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map AS_PATH_RGX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "route-map AS_PATH_RGX_RM_V4 permit 10" \
           -c "no match as-path 21" \
           -c "route-map AS_PATH_RGX_RM_V6 permit 10" -c "no match as-path 21" -c \
           "no bgp as-path access-list 21 permit .*111.*"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure and verify AS-path access list using Regexp (non-matching)
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "bgp as-path access-list 21 permit .*333.*" \
           -c "route-map AS_PATH_RGX_RM_V4 permit 10" -c "match as-path 21" \
           -c "route-map AS_PATH_RGX_RM_V6 permit 10" -c "match as-path 21"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map AS_PATH_RGX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map AS_PATH_RGX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "0")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "0")

    # remove as path prefix route map
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map AS_PATH_RGX_RM_V4 out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map AS_PATH_RGX_RM_V6 out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "route-map AS_PATH_RGX_RM_V4 permit 10" \
           -c "no match as-path 21" \
           -c "route-map AS_PATH_RGX_RM_V6 permit 10" -c "no match as-path 21" -c \
           "no bgp as-path access-list 21 permit .*333.*"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure and verify Community-list policy to permit only first two routes
    cmd = 'vtysh{} -c "show bgp ipv4 unicast community 65001:1"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  2 routes and " in output
    cmd = 'vtysh{} -c "show bgp ipv6 unicast community 65001:1"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  2 routes and " in output

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "bgp community-list expanded MATCH_COMMUNITY_1 permit 65001:1" \
          -c "bgp community-list expanded MATCH_COMMUNITY_2 permit 65002:2"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" \
           -c "route-map MATCH_COMMUNITY_RM permit 10" -c "match community MATCH_COMMUNITY_1"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map MATCH_COMMUNITY_RM out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map MATCH_COMMUNITY_RM out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "2")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "2")

    # remove match community route map
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map MATCH_COMMUNITY_RM out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map MATCH_COMMUNITY_RM out" -c \
           "no route-map MATCH_COMMUNITY_RM permit 10"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure and verify Community-list policy to permit remaining Routes
    cmd = 'vtysh{} -c "show bgp ipv4 unicast community 65002:2"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  3 routes and " in output
    cmd = 'vtysh{} -c "show bgp ipv6 unicast community 65002:2"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  3 routes and " in output

    cmd = 'vtysh{} -c "config" -c "router bgp {}" \
           -c "route-map MATCH_COMMUNITY_RM permit 10" -c "match community MATCH_COMMUNITY_2"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map MATCH_COMMUNITY_RM out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map MATCH_COMMUNITY_RM out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "3")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "3")

    # remove match community route map
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map MATCH_COMMUNITY_RM out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map MATCH_COMMUNITY_RM out" -c \
           "no route-map MATCH_COMMUNITY_RM permit 10" -c "exit" -c "no route-map MATCH_COMMUNITY_RM permit 10"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure and verify Community-list policy to permit only first two routes using regexp
    cmd = 'vtysh{} -c "show bgp ipv4 unicast community 65001:1"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  2 routes and " in output
    cmd = 'vtysh{} -c "show bgp ipv6 unicast community 65001:1"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  2 routes and " in output

    cmd = 'vtysh{} -c "config" -c "router bgp {}" \
           -c "bgp community-list expanded MATCH_COMMUNITY_RGX_1 permit .*.*.*.*1:1" -c \
            "bgp community-list expanded MATCH_COMMUNITY_RGX_2 permit .*.*.*.*2:2"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" \
           -c "route-map MATCH_COMMUNITY_RGX_RM permit 10" -c "match community MATCH_COMMUNITY_RGX_1"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map MATCH_COMMUNITY_RGX_RM out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map MATCH_COMMUNITY_RGX_RM out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "2")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "2")

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map MATCH_COMMUNITY_RGX_RM out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map MATCH_COMMUNITY_RGX_RM out" -c "exit" \
           -c "no route-map MATCH_COMMUNITY_RGX_RM permit 10"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)

    # Configure and verify Community-list policy to permit remaining Routes using regexp
    cmd = 'vtysh{} -c "show bgp ipv4 unicast community 65002:2"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  3 routes and " in output
    cmd = 'vtysh{} -c "show bgp ipv6 unicast community 65002:2"'.format(gather_info['cli_options'])
    output = gather_info['duthost'].shell(cmd, module_ignore_errors=True)['stdout']
    assert "Displayed  3 routes and " in output

    cmd = 'vtysh{} -c "config" -c "router bgp {}" \
           -c "route-map MATCH_COMMUNITY_RGX_RM permit 10" -c "match community MATCH_COMMUNITY_RGX_2"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "neighbor {} route-map MATCH_COMMUNITY_RGX_RM out" \
           -c "address-family ipv6 unicast" -c "neighbor {} route-map MATCH_COMMUNITY_RGX_RM out"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)

    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['cli_options'], "ipv4",
              "TWO_PREFIX_RM_V4", "TWO_PREFIX_V4", "3")
    verify_rm(gather_info['duthost'], gather_info['neigh_ip_v6'], gather_info['cli_options'], "ipv6",
              "TWO_PREFIX_RM_V6", "TWO_PREFIX_V6", "3")

    cmd = 'vtysh{} -c "config" -c "router bgp {}" -c "address-family ipv4 unicast" \
           -c "no neighbor {} route-map MATCH_COMMUNITY_RGX_RM out" \
           -c "address-family ipv6 unicast" -c "no neighbor {} route-map MATCH_COMMUNITY_RGX_RM out" -c "exit" \
           -c "no route-map MATCH_COMMUNITY_RGX_RM permit 10"' \
          .format(gather_info['cli_options'], gather_info['dut_asn'], gather_info['neigh_ip_v4'],
                  gather_info['neigh_ip_v6'])
    logger.debug(gather_info['duthost'].shell(cmd, module_ignore_errors=True))
    logger.debug(gather_info['duthost'].shell('vtysh{} -c "clear bgp * soft"'.format(gather_info['cli_options']),
                                              module_ignore_errors=True)['stdout'])
    time.sleep(10)
    check_baseline(gather_info['duthost'], gather_info['neigh_ip_v4'], gather_info['neigh_ip_v6'], num_v4_routes,
                   num_v6_routes)
