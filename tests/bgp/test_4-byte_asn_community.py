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
import re
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)
dut_4byte_asn = 400003
neighbor_4byte_asn = 400001
bgp_sleep = 120
bgp_id_textfsm = "./bgp/templates/bgp_id.template"

pytestmark = [
    pytest.mark.topology('t2')
]


class BGPRouter(ABC):
    def __init__(self, host, asn):
        self.host = host
        self.asn = asn
        self.saved_bgp_config = None

    def __str__(self):
        return f"{self.host} {self.asn}"

    @abstractmethod
    def get_router_id(self):
        pass

    @abstractmethod
    def get_current_bgp_asn(self):
        pass

    @abstractmethod
    def save_bgp_config(self):
        pass

    @abstractmethod
    def remove_bgp_config(self, asn=None):
        pass

    @abstractmethod
    def restore_bgp_config(self, asn_to_be_removed):
        pass

    @abstractmethod
    def get_bgp_config(self):
        pass

    @abstractmethod
    def get_originated_ipv4_networks(self):
        pass

    @abstractmethod
    def get_originated_ipv6_networks(self):
        pass


class SonicBGPRouter(BGPRouter):
    def __init__(self, host, asn):
        super().__init__(host, asn)
        self.os_type = 'sonic'

    def get_router_id(self):
        # TODO: Add SONiC implementation
        pass

    def get_current_bgp_asn(self):
        # TODO: Add SONiC implementation
        pass

    def save_bgp_config(self):
        # TODO: Add SONiC implementation
        pass

    def remove_bgp_config(self, asn=None):
        # TODO: Add SONiC implementation
        pass

    def restore_bgp_config(self, asn_to_be_removed):
        # TODO: Add SONiC implementation
        pass

    def get_bgp_config(self):
        # TODO: Add SONiC implementation
        pass

    def get_originated_ipv4_networks(self):
        # TODO: Add SONiC implementation
        pass

    def get_originated_ipv6_networks(self):
        # TODO: Add SONiC implementation
        pass


class EosBGPRouter(BGPRouter):
    def __init__(self, host, asn):
        super().__init__(host, asn)
        self.os_type = 'eos'

    def get_router_id(self):
        neigh_ip_bgp_sum = self.get_command_output("show ip bgp summary")
        neigh_ip_bgp_sum = neigh_ip_bgp_sum.split("\n")
        # Use regular expression to find the router identifier
        match = re.search(r'Router identifier (\d+\.\d+\.\d+\.\d+)', neigh_ip_bgp_sum[1])
        if match:
            router_id = match.group(1)
        else:
            pytest_assert(router_id is not None, f"Failed to get BGP ID {self.host}")
        return router_id

    def get_current_bgp_asn(self):
        current_bgp_asn = self.get_command_output("show run section bgp | sec router bgp")
        match = re.search(r'router bgp (\d+)', current_bgp_asn)
        if match:
            current_asn = match.group(1)
        else:
            pytest_assert(current_asn is not None, f"Failed to get BGP ASN {self.host}")
        return current_asn

    def save_bgp_config(self):
        self.saved_bgp_config = self.get_command_output("show run section bgp")

    def remove_bgp_config(self, asn=None):
        if asn is None:
            asn = self.get_current_bgp_asn()
        self.host.eos_config(
            lines=["no router bgp {}".format(asn)])

    def restore_bgp_config(self, asn_to_be_removed):
        self.remove_bgp_config(asn=asn_to_be_removed)
        self.host.eos_config(lines=list(self.saved_bgp_config.split("\n")))

    def get_bgp_config(self):
        current_bgp_config = self.get_command_output("show run section bgp")
        return current_bgp_config

    def get_originated_ipv4_networks(self):
        ipv4_af_output = self.get_command_output("show run section bgp | sec address-family ipv4")
        match = re.search(r'network (\d+\.\d+\.\d+\.\d+/\d+)', ipv4_af_output)
        if match:
            self_ipv4_network = match.group(1)
        else:
            pytest_assert(self_ipv4_network is not None, f"Failed to get IPv4 network {self.host}")
        return self_ipv4_network

    def get_originated_ipv6_networks(self):
        ipv6_af_network = self.get_command_output("show run section bgp | sec address-family ipv6")
        match = re.search(r'network ([a-fA-F0-9:]+/\d+)', ipv6_af_network)
        if match:
            self_ipv6_network = match.group(1)
        else:
            pytest_assert(self_ipv6_network is not None, f"Failed to get IPv6 network {self.host}")
        return self_ipv6_network

    def get_command_output(self, command):
        return self.host.eos_command(commands=[command])['stdout'][0]


def check_bgp_neighbor(duthost, bgp_neighbors):
    """
    Validate all the bgp neighbors are established
    """
    pytest_assert(
        wait_until(300, 10, 0, duthost.check_bgp_session_state, bgp_neighbors),
        "bgp sessions {} are not up".format(bgp_neighbors)
    )


def setup_ceos(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index, request):
    duthost = duthosts[enum_frontend_dut_hostname]
    asic_index = enum_rand_one_frontend_asic_index

    if duthost.is_multi_asic:
        cli_options = " -n " + str(asic_index)
    else:
        cli_options = ''

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    neighbors = dict()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    ceosNeighbors = [v['description'] for v in bgp_facts['bgp_neighbors'].values()
                     if 'asic' not in v['description'].lower()]
    if not ceosNeighbors:
        pytest.skip("No ceos neighbors found")
    neigh = ceosNeighbors[0]
    logger.debug("Neighbor is: {}".format(neigh))
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        # skip iBGP neighbors
        if "INTERNAL" not in v["peer group"] and "VOQ_CHASSIS" not in v["peer group"]:
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

    neigh_cli_options = ''

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh]['bgp']['peers'][dut_asn][1]

    dut_ip_bgp_sum = duthost.shell('show ip bgp summary')['stdout']

    bgp_neigh = EosBGPRouter(nbrhosts[neigh]["host"], neigh_asn[neigh])
    neigh_bgp_id = bgp_neigh.get_router_id()
    with open(bgp_id_textfsm) as template:
        fsm = textfsm.TextFSM(template)
        dut_bgp_id = fsm.ParseText(dut_ip_bgp_sum)[0][0]

    dut_ipv4_network = duthost.shell("show run bgp | grep 'ip prefix-list'")['stdout'].split()[6]
    dut_ipv6_network = duthost.shell("show run bgp | grep 'ipv6 prefix-list'")['stdout'].split()[6]
    neigh_ipv4_network = bgp_neigh.get_originated_ipv4_networks()
    neigh_ipv6_network = bgp_neigh.get_originated_ipv6_networks()

    setup_info = {
        'bgp_neigh': bgp_neigh,
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
        'neigh_ipv6_network': neigh_ipv6_network,
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(bgp_neigh.get_bgp_config()))
    logger.debug('Setup_info: {}'.format(setup_info))
    bgp_neigh.save_bgp_config()

    yield setup_info

    bgp_neigh.restore_bgp_config(asn_to_be_removed=neighbor_4byte_asn)
    # restore config to original state
    config_reload(duthost, safe_reload=True, wait_for_bgp=True)


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, enum_rand_one_frontend_asic_index, request):
    # verify neighbors are type sonic and skip if not
    if request.config.getoption("neighbor_type") != "sonic":
        yield from setup_ceos(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname,
                              enum_rand_one_frontend_asic_index, request)
        return
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
        'bgp_neigh': SonicBGPRouter(neighbors[neigh], neigh_asn[neigh]),
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


def config_dut_4_byte_asn_dut(setup):
    # configure BGP with 4-byte ASN using the standard T2 config and existing route-maps on DUT
    # as route-map names varies dependin on the topology, used ALLOW_ANY route-map to
    # allow all routes as we only have two neighbors.
    cmd = 'vtysh{} \
    -c "config" \
    -c "no router bgp {}" \
    -c "route-map ALLOW_ANY permit 10" \
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
    -c "neighbor {} route-map ALLOW_ANY in" \
    -c "neighbor {} route-map ALLOW_ANY out" \
    -c "neighbor {} activate" \
    -c "maximum-paths 64" \
    -c "exit-address-family" \
    -c "address-family ipv6 unicast" \
    -c "network {}" \
    -c "neighbor {} soft-reconfiguration inbound" \
    -c "neighbor {} route-map ALLOW_ANY in" \
    -c "neighbor {} route-map ALLOW_ANY out" \
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


def run_bgp_4_byte_asn_community_sonic(setup):
    config_dut_4_byte_asn_dut(setup)

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
    # Command output 'show ipv6 bgp neighbors <xxx> routes'  may split into two lines, hence checking both the lines
    #    Network          Next Hop             Metric LocPrf Weight Path
    # *> 2064:100::1/128  fe80::4cc2:44ff:feee:73ff
    #                                                       0 400001 i
    assert (str(neighbor_4byte_asn) in str(output.split('\n')[9]) or
            str(neighbor_4byte_asn) in str(output.split('\n')[10]))

    output = setup['neighhost'].shell("show ip bgp summary | grep {}".format(setup['dut_ip_v4']))['stdout']
    assert str(dut_4byte_asn) in output.split()[2]
    output = setup['neighhost'].shell("show ipv6 bgp summary | grep {}".format(setup['dut_ip_v6'].lower()))['stdout']
    assert str(dut_4byte_asn) in output.split()[2]
    output = setup['neighhost'].shell("show ip bgp neighbors {} routes".format(setup['dut_ip_v4']))['stdout']
    assert str(dut_4byte_asn) in str(output.split('\n')[9].split()[5])
    output = setup['neighhost'].shell("show ipv6 bgp neighbors {} routes".format(setup['dut_ip_v6'].lower()))['stdout']
    assert str(dut_4byte_asn) in str(output.split('\n')[9].split()[5])


def run_bgp_4_byte_asn_community_eos(setup):
    config_dut_4_byte_asn_dut(setup)

    bgp_neigh = setup['bgp_neigh']
    bgp_neigh.remove_bgp_config()
    # configure BGP with 4-byte ASN using the standard T2 config and existing route-maps on neighbor device
    cmd = [
        "router bgp {}".format(neighbor_4byte_asn),
        "router-id {}".format(setup['neigh_bgp_id']),
        "neighbor {} remote-as {}".format(setup['dut_ip_v4'], dut_4byte_asn),
        "neighbor {} description {}".format(setup['dut_ip_v4'], 'DUT'),
        "neighbor {} maximum-routes 0".format(setup['dut_ip_v4']),
        "neighbor {} remote-as {}".format(setup['dut_ip_v6'], dut_4byte_asn),
        "neighbor {} description {}".format(setup['dut_ip_v6'], 'DUT'),
        "neighbor {} maximum-routes 0".format(setup['dut_ip_v6']),
        "!",
        "address-family ipv4",
        "neighbor {} activate".format(setup['dut_ip_v4']),
        "network {}".format(setup['neigh_ipv4_network']),
        "!",
        "address-family ipv6",
        "neighbor {} activate".format(setup['dut_ip_v6']),
        "network {}".format(setup['neigh_ipv6_network'])
    ]

    logger.debug(bgp_neigh.host.eos_config(lines=cmd))

    logger.debug("DUT BGP Config: {}".format(setup['duthost'].shell("show run bgp")['stdout']))
    logger.debug("Neighbor BGP Config: {}".format(bgp_neigh.get_bgp_config()))

    time.sleep(60)
    check_bgp_neighbor(setup['duthost'], [setup['neigh_ip_v4'], setup['neigh_ip_v6']])

    output = setup['duthost'].shell("show ip bgp summary | grep {}".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ipv6 bgp summary | grep {}".format(setup['neigh_ip_v6'].lower()))['stdout']
    assert str(neighbor_4byte_asn) in output.split()[2]
    output = setup['duthost'].shell("show ip bgp neighbors {} routes".format(setup['neigh_ip_v4']))['stdout']
    assert str(neighbor_4byte_asn) in str(output.split('\n')[9])
    output = setup['duthost'].shell("show ipv6 bgp neighbors {} routes".format(setup['neigh_ip_v6'].lower()))['stdout']
    # show ipv6 bgp neighbors <xxx> routes  may split into two lines, hence checking both lines
    #     Network          Next Hop            Metric LocPrf Weight Path
    # *> 2064:100::1d/128 fe80::4059:38ff:feaa:82db
    #                                                       0 400001 i
    assert (str(neighbor_4byte_asn) in str(output.split('\n')[9]) or
           str(neighbor_4byte_asn) in str(output.split('\n')[10]))

    output = bgp_neigh.get_command_output("show ip bgp summary | include {}".format(setup['dut_ip_v4']))
    assert str(dut_4byte_asn) in output.split()[3]
    output = bgp_neigh.get_command_output("show ipv6 bgp summary | include {}".format(setup['dut_ip_v6'].lower()))
    assert str(dut_4byte_asn) in output.split()[3]
    output = bgp_neigh.get_command_output("show ip bgp neighbors {} routes".format(setup['dut_ip_v4']))
    assert str(dut_4byte_asn) in str(output.split('\n')[-1])
    output = bgp_neigh.get_command_output("show ipv6 bgp peers {} routes".format(setup['dut_ip_v6'].lower()))
    assert str(dut_4byte_asn) in str(output.split('\n')[-1]) or str(dut_4byte_asn) in str(output.split('\n')[-2])


def test_4_byte_asn_community(setup):
    if setup['bgp_neigh'].os_type == 'eos':
        run_bgp_4_byte_asn_community_eos(setup)
    else:
        run_bgp_4_byte_asn_community_sonic(setup)
