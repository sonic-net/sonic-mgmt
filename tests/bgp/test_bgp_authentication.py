"""
This script is to test the EBGP Authentication feature of SONiC.
"""
import logging

import pytest
import time

from tests.bgp.bgp_helpers import eos_bgp_neighbor_config_parents
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2', 'lrh', 'urh')
]

BGP_PASS = "sonic.123"
MISMATCH_PASS = "badpassword"


def get_lldp_neighbors(duthost):
    neighbors = []
    for line in duthost.shell("show lldp table")['stdout'].splitlines()[3:]:
        fields = line.split()
        if len(fields) >= 3:
            neighbors.append({
                'dut_intf': fields[0],
                'name': fields[1],
                'neigh_intf': fields[2],
            })
    return neighbors


def get_peer_addrs(tbinfo, tor1, dut_asn, confed_asn):
    try:
        neigh_bgp = tbinfo['topo']['properties']['configuration'][tor1]['bgp']
    except KeyError:
        return None

    peers = neigh_bgp.get('peers', {})
    try:
        asn = int(confed_asn) if neigh_bgp.get('peer_in_bgp_confed', False) else int(dut_asn)
    except (TypeError, ValueError):
        return None

    return peers.get(asn) or peers.get(str(asn))


def get_bgp_neighbor_info(duthost, asic_index, tor1, bgp_facts=None):
    skip_hosts = set([host.lower() for host in duthost.get_asic_namespace_list()])
    if bgp_facts is None:
        bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neighbor_info = {
        'bgp_facts': bgp_facts,
        'neigh_ip_v4': None,
        'neigh_ip_v6': None,
        'peer_group_v4': None,
        'peer_group_v6': None,
        'neigh_asn': None,
    }

    for neigh_ip, facts in bgp_facts['bgp_neighbors'].items():
        if facts['description'].lower() in skip_hosts or facts['description'] != tor1:
            continue

        if facts['ip_version'] == 4:
            neighbor_info['neigh_ip_v4'] = neigh_ip
            neighbor_info['peer_group_v4'] = facts['peer group']
        elif facts['ip_version'] == 6:
            neighbor_info['neigh_ip_v6'] = neigh_ip
            neighbor_info['peer_group_v6'] = facts['peer group']
        neighbor_info['neigh_asn'] = facts['remote AS']

    return neighbor_info


def get_valid_bgp_neighbor(tbinfo, nbrhosts, duthost, dut_asn, confed_asn, is_sonic_neigh):
    bgp_facts_cache = {}
    reject_reasons = []

    for lldp_neigh in get_lldp_neighbors(duthost):
        tor1 = lldp_neigh['name']
        if tor1 not in nbrhosts:
            reject_reasons.append("{}: not in nbrhosts".format(tor1))
            continue

        try:
            if duthost.is_multi_asic:
                asic_index = duthost.get_port_asic_instance(lldp_neigh['dut_intf']).asic_index
            else:
                asic_index = None
        except Exception as e:
            reason = "{}: failed to get DUT ASIC index, error={}".format(tor1, e)
            logger.debug("Skipping neighbor {}".format(reason))
            reject_reasons.append(reason)
            continue

        if asic_index not in bgp_facts_cache:
            bgp_facts_cache[asic_index] = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']

        neighbor_info = get_bgp_neighbor_info(duthost, asic_index, tor1, bgp_facts_cache[asic_index])
        if not all([neighbor_info['neigh_ip_v4'], neighbor_info['neigh_ip_v6'],
                    neighbor_info['peer_group_v4'], neighbor_info['peer_group_v6'],
                    neighbor_info['neigh_asn']]):
            reject_reasons.append("{}: missing IPv4/IPv6 BGP neighbor info".format(tor1))
            continue

        bgp_facts = neighbor_info['bgp_facts']
        if (bgp_facts['bgp_neighbors'][neighbor_info['neigh_ip_v4']]['state'] != 'established' or
                bgp_facts['bgp_neighbors'][neighbor_info['neigh_ip_v6']]['state'] != 'established'):
            reject_reasons.append("{}: IPv4/IPv6 BGP session is not established".format(tor1))
            continue

        peer_addrs = get_peer_addrs(tbinfo, tor1, dut_asn, confed_asn)
        if not peer_addrs or len(peer_addrs) < 2:
            reject_reasons.append("{}: missing peer addresses for dut_asn/confed_asn".format(tor1))
            continue

        neigh_asic_index = None
        if is_sonic_neigh and nbrhosts[tor1]["host"].is_multi_asic:
            try:
                neigh_asic_index = nbrhosts[tor1]["host"].get_port_asic_instance(lldp_neigh['neigh_intf']).asic_index
            except Exception as e:
                reason = "{}: failed to get neighbor ASIC index, error={}".format(tor1, e)
                logger.debug("Skipping neighbor {}".format(reason))
                reject_reasons.append(reason)
                continue

        neighbor_info.update({
            'tor1': tor1,
            'dut_intf': lldp_neigh['dut_intf'],
            'neigh_intf': lldp_neigh['neigh_intf'],
            'asic_index': asic_index,
            'neigh_asic_index': neigh_asic_index,
            'dut_ip_v4': peer_addrs[0],
            'dut_ip_v6': peer_addrs[1],
        })
        return neighbor_info

    pytest.skip("Failed to find an established IPv4/IPv6 BGP neighbor. Candidates checked: {}. Reasons: {}"
                .format(len(reject_reasons), "; ".join(reject_reasons)))


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, request):
    neighbor_type = request.config.getoption("neighbor_type")
    if neighbor_type not in ["sonic", "csonic", "eos"]:
        pytest.skip("Unsupported neighbor type: {}".format(neighbor_type))

    is_sonic_neigh = True
    if neighbor_type not in ("sonic", "csonic"):
        is_sonic_neigh = False

    duthost = duthosts[enum_frontend_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']
    confed_asn = duthost.get_bgp_confed_asn()

    neighbor_info = get_valid_bgp_neighbor(tbinfo, nbrhosts, duthost, dut_asn, confed_asn, is_sonic_neigh)
    tor1 = neighbor_info['tor1']
    asic_index = neighbor_info['asic_index']
    neigh_asic_index = neighbor_info['neigh_asic_index']
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    neigh_ip_v4 = neighbor_info['neigh_ip_v4']
    neigh_ip_v6 = neighbor_info['neigh_ip_v6']
    peer_group_v4 = neighbor_info['peer_group_v4']
    peer_group_v6 = neighbor_info['peer_group_v6']
    neigh_asn = neighbor_info['neigh_asn']
    bgp_facts = neighbor_info['bgp_facts']

    # EOS/cEOS: converged (multi-VRF) uses "router bgp <primary_asn> vrf <hostname>", not default vrf.
    if is_sonic_neigh:
        neigh_eos_bgp_parents = None
    else:
        neigh_eos_bgp_parents = eos_bgp_neighbor_config_parents(tbinfo, nbrhosts, tor1, neigh_asn)

    dut_ip_v4 = neighbor_info['dut_ip_v4']
    dut_ip_v6 = neighbor_info['dut_ip_v6']

    logger.info("default namespace {}".format(DEFAULT_NAMESPACE))

    tor1_namespace = DEFAULT_NAMESPACE
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        if tor1 == neigh['name']:
            tor1_namespace = neigh['namespace']
            break

    # verify sessions are established
    logger.debug(duthost.shell('show ip bgp summary'))
    logger.debug(duthost.shell('show ipv6 bgp summary'))

    assert bgp_facts['bgp_neighbors'][neigh_ip_v4]['state'] == 'established'
    assert bgp_facts['bgp_neighbors'][neigh_ip_v6]['state'] == 'established'

    setup_info = {
        'duthost': duthost,
        'neighhost': nbrhosts[tor1]["host"],
        'tor1': tor1,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'tor1_namespace': tor1_namespace,
        'dut_namespace': namespace,
        'asic_index': asic_index,
        'neigh_asic_index': neigh_asic_index,
        'is_sonic_neigh': is_sonic_neigh,
        'neigh_eos_bgp_parents': neigh_eos_bgp_parents,
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)))
    neigh_host = nbrhosts[tor1]["host"]
    if is_sonic_neigh:
        logger.debug("Neighbor BGP Config: {}".format(neigh_host.shell("show run bgp", module_ignore_errors=True)))
    else:
        logger.debug("Neighbor BGP Config: {}".format(neigh_host.eos_command(commands=["show run | section bgp"])))

    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    if is_sonic_neigh:
        config_reload(neigh_host, is_dut=False)
    else:
        remove_password_on_neighbor(setup_info)

    time.sleep(10)
    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)


def test_bgp_peer_group_password(setup):
    configure_password_on_duthost(setup, "peer_group", BGP_PASS)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_not_established, setup),
        message="BGP sessions are still established after timeout",
    )

    configure_password_on_neighbor(setup)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_established, setup),
        message="BGP sessions are still not established after timeout",
    )

    # mismatch peer group passwords
    configure_password_on_duthost(setup, "peer_group", MISMATCH_PASS)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_not_established, setup),
        message="BGP sessions are still established after timeout",
    )

    # remove peer group passwords on both DUT and neighbor
    remove_password_on_duthost(setup, "peer_group", MISMATCH_PASS)
    remove_password_on_neighbor(setup)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_established, setup),
        message="BGP sessions are still not established after timeout",
    )


def test_bgp_neighbor_password(setup):
    configure_password_on_duthost(setup, "neighbor", BGP_PASS)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_not_established, setup),
        message="BGP sessions are still established after timeout",
    )

    configure_password_on_neighbor(setup)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_established, setup),
        message="BGP sessions are still not established after timeout",
    )

    # mismatch passwords
    configure_password_on_duthost(setup, "neighbor", MISMATCH_PASS)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_not_established, setup),
        message="BGP sessions are still established after timeout",
    )

    # remove password configs on both DUT and neighbor
    remove_password_on_duthost(setup, "neighbor", MISMATCH_PASS)
    remove_password_on_neighbor(setup)
    pytest_assert(
        wait_until(300, 20, 0, verify_neighbor_bgp_established, setup),
        message="BGP sessions are still not established after timeout",
    )


def configure_password_on_duthost(setup, neighbor_type, password):
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = (
        'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "neighbor {} password {}" -c "neighbor {} password {}" '
        '-c "end"'.format(
            setup['dut_asn'],
            setup['peer_group_v4'] if neighbor_type == 'peer_group' else setup['neigh_ip_v4'],
            password,
            setup['peer_group_v6'] if neighbor_type == 'peer_group' else setup['neigh_ip_v6'],
            password,
        )
    )

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)
    if len(command_output["stdout_lines"]) != 0:
        pytest.fail("Error configuring BGP password")

    logger.debug(setup['duthost'].shell('show run bgp'))


def remove_password_on_duthost(setup, neighbor_type, password):
    ns = '-n ' + str(setup['asic_index']) if setup['asic_index'] is not None else ''
    cmd = (
        'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "no neighbor {} password {}" '
        '-c "no neighbor {} password {}" -c "end"'.format(
            setup['dut_asn'],
            setup['peer_group_v4'] if neighbor_type == 'peer_group' else setup['neigh_ip_v4'],
            password,
            setup['peer_group_v6'] if neighbor_type == 'peer_group' else setup['neigh_ip_v6'],
            password,
        )
    )

    command_output = setup['duthost'].shell(cmd, module_ignore_errors=True)
    if len(command_output["stdout_lines"]) != 0:
        pytest.fail("Error removing BGP password")

    logger.debug(setup['duthost'].shell('show run bgp'))


def configure_password_on_neighbor(setup):
    ns = '-n ' + str(setup['neigh_asic_index']) if setup['neigh_asic_index'] is not None else ''
    if setup['is_sonic_neigh']:
        cmd = (
            'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "neighbor {} password {}" '
            '-c "neighbor {} password {}"'.format(
                setup['neigh_asn'],
                setup['dut_ip_v4'],
                BGP_PASS,
                setup['dut_ip_v6'],
                BGP_PASS,
            )
        )

        logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))
        logger.debug(setup['neighhost'].shell("show run bgp"))
    else:
        cmd = [
            "neighbor {} password 0 {}".format(setup['dut_ip_v4'], BGP_PASS),
            "neighbor {} password 0 {}".format(setup['dut_ip_v6'], BGP_PASS),
        ]

        logger.debug(setup['neighhost'].eos_config(
            lines=cmd,
            parents=setup['neigh_eos_bgp_parents'],
        ))

        logger.debug(setup['neighhost'].eos_command(commands=["show run | section bgp"]))


def remove_password_on_neighbor(setup):
    ns = '-n ' + str(setup['neigh_asic_index']) if setup['neigh_asic_index'] is not None else ''
    if setup['is_sonic_neigh']:
        cmd = (
            'vtysh ' + ns + ' -c "config" -c "router bgp {}" -c "no neighbor {} password {}" '
            '-c "no neighbor {} password {}"'.format(
                setup['neigh_asn'],
                setup['dut_ip_v4'],
                BGP_PASS,
                setup['dut_ip_v6'],
                BGP_PASS,
            )
        )

        logger.debug(setup['neighhost'].shell(cmd, module_ignore_errors=True))
        logger.debug(setup['neighhost'].shell("show run bgp"))
    else:
        cmd = [
            "no neighbor {} password 0 {}".format(setup['dut_ip_v4'], BGP_PASS),
            "no neighbor {} password 0 {}".format(setup['dut_ip_v6'], BGP_PASS),
        ]

        logger.debug(setup['neighhost'].eos_config(
            lines=cmd,
            parents=setup['neigh_eos_bgp_parents'],
        ))

        logger.debug(setup['neighhost'].eos_command(commands=["show run | section bgp"]))


def get_duthost_bgp_fact(setup):
    logger.debug(setup['duthost'].shell('show ip bgp summary'))
    logger.debug(setup['duthost'].shell('show ipv6 bgp summary'))
    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    return bgp_facts


def verify_neighbor_bgp_not_established(setup):
    bgp_facts = get_duthost_bgp_fact(setup)
    return (bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] != 'established' and
            bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] != 'established')


def verify_neighbor_bgp_established(setup):
    bgp_facts = get_duthost_bgp_fact(setup)
    return (bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established' and
            bgp_facts['bgp_neighbors'][setup['neigh_ip_v6']]['state'] == 'established')
