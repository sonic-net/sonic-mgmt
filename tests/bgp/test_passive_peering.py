'''

This script is to test BGP passive peering on SONiC

'''

import logging
import time
import pytest
from tests.common.config_reload import config_reload
from tests.common.helpers.bgp import get_vtysh_cmd_for_asic
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until
from tests.bgp.bgp_helpers import eos_bgp_neighbor_config_parents, get_topo_lldp_neighbors

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2', 'lrh', 'urh')
]

BGP_WAIT_TIMEOUT = 90
BGP_WAIT_INTERVAL = 10
# [SuppressMessage("Microsoft.Security", "CS002:SecretInNextLine", Justification="Test placeholder password")]
peer_password = "sonic.123"
wrong_password = "wrong-password"


def remove_password_on_neighbor(setup):
    """Undo neighbor BGP passwords added by the tests (EOS or SONiC)."""
    if setup['is_sonic']:
        for dut_ip in (setup['dut_ip_v4'], setup['dut_ip_v6']):
            cmd = get_vtysh_cmd_for_asic(
                setup['neighhost'], setup['neigh_asic_index'],
                'vtysh -c "config" -c "router bgp {}" -c "no neighbor {} password"'.format(
                    setup['neigh_asn'], dut_ip),
            )
            setup['neighhost'].shell(cmd)
    else:
        cmd = [
            "no neighbor {} password".format(setup['dut_ip_v4']),
            "no neighbor {} password".format(setup['dut_ip_v6']),
        ]
        setup['neighhost'].eos_config(lines=cmd, parents=setup['neigh_eos_bgp_parents'])


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, rand_one_dut_front_end_hostname, request):
    # verify neighbors are type sonic
    is_sonic = False
    if request.config.getoption("neighbor_type") == "sonic":
        is_sonic = True

    duthost = duthosts[rand_one_dut_front_end_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    confed_asn = duthost.get_bgp_confed_asn()

    lldp_neighbor = get_topo_lldp_neighbors(duthost, nbrhosts)[0]
    neigh_name = lldp_neighbor["neigh_name"]
    dut_int = lldp_neighbor["dut_int"]
    neigh_int = lldp_neighbor["neigh_int"]
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
    neigh_ip_v4 = None
    neigh_ip_v6 = None
    peer_group_v4 = None
    peer_group_v6 = None
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

    if (neigh_ip_v4 is None or neigh_ip_v6 is None or peer_group_v4 is None or
            peer_group_v6 is None):
        pytest.skip("Failed to get neighbor info")

    neigh_bgp_config = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']
    peer_in_bgp_confed = neigh_bgp_config.get('peer_in_bgp_confed', False)
    if peer_in_bgp_confed:
        asn = int(confed_asn)
    else:
        asn = int(dut_asn)
    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][asn][1]

    # EOS/cEOS converged: eos_config parents (nbrhosts flag or tbinfo convergence_data fallback)
    if is_sonic:
        neigh_eos_bgp_parents = None
    else:
        neigh_eos_bgp_parents = eos_bgp_neighbor_config_parents(
            tbinfo, nbrhosts, neigh_name, neigh_asn[neigh_name])

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
        'is_sonic': is_sonic,
        'neigh_eos_bgp_parents': neigh_eos_bgp_parents,
    }

    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # Undo only what the tests changed on the neighbor. Full EOS backup restore via
    # load_configuration() can fail on VS (e.g. VLAN subnet overlap on Vl2004/Vlan1).
    if is_sonic:
        config_reload(nbrhosts[neigh_name]["host"], is_dut=False)
    else:
        remove_password_on_neighbor(setup_info)

    time.sleep(10)
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)


def check_bgp_neighbor_state(duthost, asic_index, neigh_ip, should_be_established=True):
    """Check if BGP neighbor has reached the expected state.

    Args:
        duthost: DUT host object
        asic_index: ASIC instance index
        neigh_ip: Neighbor IP address
        should_be_established: True if expecting 'established', False otherwise
    """
    try:
        bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
        state = bgp_facts['bgp_neighbors'][neigh_ip]['state']
    except KeyError:
        logger.debug("BGP neighbor {} not found in bgp_facts yet".format(neigh_ip))
        return not should_be_established
    logger.debug("BGP neighbor {} state: {}".format(neigh_ip, state))
    if should_be_established:
        return state == 'established'
    return state != 'established'


def test_bgp_passive_peering_ipv4(setup):
    # configure passive EBGP peering session on DUT and ensure adjacency stays established (IPv4)
    cmd = get_vtysh_cmd_for_asic(
        setup['duthost'], setup['asic_index'],
        'vtysh -c "config" -c "router bgp {}" -c "neighbor {} passive"'.format(
            setup['dut_asn'], setup['peer_group_v4']),
    )
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v4'], True), \
        "BGP IPv4 session not established after configuring passive peering"

    # configure password on DUT and ensure the adjacency is not established (IPv4)
    cmd = get_vtysh_cmd_for_asic(
        setup['duthost'], setup['asic_index'],
        'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(
            setup['dut_asn'], setup['peer_group_v4'], peer_password),
    )
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v4'], False), \
        "BGP IPv4 session still established after configuring password mismatch"

    logger.info("is_sonic: {}".format(setup['is_sonic']))

    # configure password on Neighbor and ensure the adjacency is established (IPv4)
    if setup['is_sonic']:
        cmd = get_vtysh_cmd_for_asic(
            setup['neighhost'], setup['neigh_asic_index'],
            'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(
                setup['neigh_asn'], setup['dut_ip_v4'], peer_password),
        )
        setup['neighhost'].shell(cmd, module_ignore_errors=True)
    else:
        cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v4'], peer_password)]
        logger.debug(setup['neighhost'].eos_config(
            lines=cmd, parents=setup['neigh_eos_bgp_parents']))
        logger.debug(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v4'], True), \
        "BGP IPv4 session not established after configuring matching password"

    # configure mismatch password on DUT and ensure the adjacency is not established (IPv4)
    cmd = get_vtysh_cmd_for_asic(
        setup['duthost'], setup['asic_index'],
        'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(
            setup['dut_asn'], setup['peer_group_v4'], wrong_password),
    )
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v4'], False), \
        "BGP IPv4 session still established after configuring wrong password"


def test_bgp_passive_peering_ipv6(setup):
    # configure passive EBGP peering session on DUT and ensure adjacency stays established (IPv6)
    cmd = get_vtysh_cmd_for_asic(
        setup['duthost'], setup['asic_index'],
        'vtysh -c "config" -c "router bgp {}" -c "neighbor {} passive"'.format(
            setup['dut_asn'], setup['peer_group_v6']),
    )
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v6'], True), \
        "BGP IPv6 session not established after configuring passive peering"

    # configure password on DUT and ensure the adjacency is not established (IPv6)
    cmd = get_vtysh_cmd_for_asic(
        setup['duthost'], setup['asic_index'],
        'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(
            setup['dut_asn'], setup['peer_group_v6'], peer_password),
    )
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v6'], False), \
        "BGP IPv6 session still established after configuring password mismatch"

    # configure password on Neighbor and ensure the adjacency is established (IPv6)
    if setup['is_sonic']:
        cmd = get_vtysh_cmd_for_asic(
            setup['neighhost'], setup['neigh_asic_index'],
            'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(
                setup['neigh_asn'], setup['dut_ip_v6'], peer_password),
        )
        setup['neighhost'].shell(cmd, module_ignore_errors=True)
    else:
        cmd = ["neighbor {} password 0 {}".format(setup['dut_ip_v6'], peer_password)]
        logger.debug(setup['neighhost'].eos_config(
            lines=cmd, parents=setup['neigh_eos_bgp_parents']))
        logger.debug(setup['neighhost'].eos_command(commands=["show run | section bgp"]))

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v6'], True), \
        "BGP IPv6 session not established after configuring matching password"

    # configure mismatch password on DUT and ensure the adjacency is not established (IPv6)
    cmd = get_vtysh_cmd_for_asic(
        setup['duthost'], setup['asic_index'],
        'vtysh -c "config" -c "router bgp {}" -c "neighbor {} password {}"'.format(
            setup['dut_asn'], setup['peer_group_v6'], wrong_password),
    )
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    assert wait_until(BGP_WAIT_TIMEOUT, BGP_WAIT_INTERVAL, 0,
                      check_bgp_neighbor_state, setup['duthost'], setup['asic_index'],
                      setup['neigh_ip_v6'], False), \
        "BGP IPv6 session still established after configuring wrong password"
