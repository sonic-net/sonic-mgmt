'''

This script is to test BGP passive peering on SONiC.

'''

import logging
import pytest
import time
from tests.common.config_reload import config_reload
from tests.common.devices.eos import EosHost
from tests.common.helpers.constants import DEFAULT_NAMESPACE

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]

bgp_config_sleeptime = 90
peer_password = "sonic.123"
wrong_password = "wrong-password"
EOS_BACKUP_CONFIG_FILE = "/tmp/eos_neighbor_test_passive_peering_backup_config_{}"


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, rand_one_dut_front_end_hostname, request):
    # verify neighbors are type sonic
    is_sonic = False
    if request.config.getoption("neighbor_type") == "sonic":
        is_sonic = True

    duthost = duthosts[rand_one_dut_front_end_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    neigh_name = lldp_table[1]
    dut_int = lldp_table[0]
    neigh_int = lldp_table[2]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_int).asic_index
    else:
        asic_index = DEFAULT_NAMESPACE

    if nbrhosts[neigh_name]["host"].is_multi_asic:
        neigh_asic_index = nbrhosts[neigh_name]["host"].get_port_asic_instance(neigh_int).asic_index
    else:
        neigh_asic_index = DEFAULT_NAMESPACE

    namespace = duthost.get_namespace_from_asic_id(asic_index)

    skip_hosts = duthost.get_asic_namespace_list()

    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_asn = dict()
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'] not in skip_hosts:
            if v['description'] == neigh_name:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                    assert v['state'] == 'established'
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
                    assert v['state'] == 'established'
            neigh_asn[v['description']] = v['remote AS']

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][1]

    # verify sessions are established
    logger.debug(duthost.shell('show ip bgp summary')['stdout'])
    logger.debug(duthost.shell('show ipv6 bgp summary')['stdout'])

    setup_info = {
        'duthost': duthost,
        'neighhost': nbrhosts[neigh_name]["host"],
        'neigh_name': neigh_name,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh_name],
        'asn_dict':  neigh_asn,
        'namespace': namespace,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'asic_index': asic_index,
        'neigh_asic_index': neigh_asic_index,
        'is_sonic': is_sonic
    }

    logger.debug('Setup_info: {}'.format(setup_info))
    neighbor_dut = nbrhosts[neigh_name]["host"]

    is_arista_neighbor = not is_sonic and isinstance(neighbor_dut, EosHost)

    if is_arista_neighbor:
        # Neighbor is running EOS, backup config
        neighbor_dut.eos_config(
            backup=True,
            backup_options={
                'filename': EOS_BACKUP_CONFIG_FILE.format(neighbor_dut.hostname)
            }
        )

    yield setup_info

    # restore config to original state on both DUT and neighbor

    if is_arista_neighbor:
        # Neighbor is running EOS, backup config
        neighbor_dut.load_configuration(EOS_BACKUP_CONFIG_FILE.format(neighbor_dut.hostname))
    elif is_sonic:
        config_reload(nbrhosts[neigh_name]["host"], is_dut=False)

    config_reload(duthost, safe_reload=True, wait_for_bgp=True)


def test_bgp_passive_peering_ipv4(setup):
    # configure passive EBGP peering session on DUT and ensure adjacency stays established (IPv4)
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} passive"'.format(setup['asic_index'],
                                                                                       setup['dut_asn'],
                                                                                       setup['peer_group_v4'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'

    # configure password on DUT and ensure the adjacency is not established (IPv4)
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['asic_index'],
                                                                                           setup['dut_asn'],
                                                                                           setup['peer_group_v4'],
                                                                                           peer_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'

    logger.info("is_sonic: {}".format(setup['is_sonic']))

    # configure password on Neighbor and ensure the adjacency is established (IPv4)
    if setup['is_sonic']:
        cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(
                                                                                        setup['neigh_asic_index'],
                                                                                        setup['neigh_asn'],
                                                                                        setup['dut_ip_v4'],
                                                                                        peer_password)
        setup['neighhost'].shell(cmd, module_ignore_errors=True)
    else:
        cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v4'], peer_password)]
        logger.debug(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))
        logger.debug(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    logger.debug("BGP facts: {}".format(bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]))
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established'

    # configure mismatch password on DUT and ensure the adjacency is not established (IPv4)
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['asic_index'],
                                                                                           setup['dut_asn'],
                                                                                           setup['peer_group_v4'],
                                                                                           wrong_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established'


def test_bgp_passive_peering_ipv6(setup):
    # configure passive EBGP peering session on DUT and ensure adjacency stays established (IPv6)
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} passive"'.format(setup['asic_index'],
                                                                                       setup['dut_asn'],
                                                                                       setup['peer_group_v6'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # configure password on DUT and ensure the adjacency is not established (IPv6)
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['asic_index'],
                                                                                           setup['dut_asn'],
                                                                                           setup['peer_group_v6'],
                                                                                           peer_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'

    # configure password on Neighbor and ensure the adjacency is established (IPv6)
    if setup['is_sonic']:
        cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.\
                                                                                    format(
                                                                                        setup['neigh_asic_index'],
                                                                                        setup['neigh_asn'],
                                                                                        setup['dut_ip_v6'],
                                                                                        peer_password)
        setup['neighhost'].shell(cmd, module_ignore_errors=True)
    else:
        cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v6'], peer_password)]
        logger.debug(setup['neighhost'].eos_config(lines=cmd, parents="router bgp {}".format(setup['neigh_asn'])))
        logger.debug(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    logger.debug("BGP facts: {}".format(bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]))
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established'

    # configure mismatch password on DUT and ensure the adjacency is not established (IPv6)
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(setup['asic_index'],
                                                                                           setup['dut_asn'],
                                                                                           setup['peer_group_v6'],
                                                                                           wrong_password)
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    time.sleep(bgp_config_sleeptime)

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    assert bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established'
