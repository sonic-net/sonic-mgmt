"""
This script is to test the EBGP Authentication feature of SONiC.
"""
import logging

import pytest
import time

from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.config_reload import config_reload
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]

BGP_PASS = "sonic.123"
MISMATCH_PASS = "badpassword"
EOS_NEIGH_BACKUP_CONFIG_FILE = "/tmp/bgp_auth_eos_backup_config_{}"


@pytest.fixture(scope='module')
def setup(tbinfo, nbrhosts, duthosts, enum_frontend_dut_hostname, request):
    neighbor_type = request.config.getoption("neighbor_type")
    if neighbor_type not in ["sonic", "eos"]:
        pytest.skip("Unsupported neighbor type: {}".format(neighbor_type))

    is_sonic_neigh = True
    if neighbor_type != "sonic":
        is_sonic_neigh = False

    duthost = duthosts[enum_frontend_dut_hostname]
    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    lldp_table = duthost.shell("show lldp table")['stdout'].split("\n")[3].split()
    tor1 = lldp_table[1]
    dut_int = lldp_table[0]
    neigh_int = lldp_table[2]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_int).asic_index
    else:
        asic_index = None

    if is_sonic_neigh:
        if nbrhosts[tor1]["host"].is_multi_asic:
            neigh_asic_index = nbrhosts[tor1]["host"].get_port_asic_instance(neigh_int).asic_index
        else:
            neigh_asic_index = None
    else:
        neigh_asic_index = None

    namespace = duthost.get_namespace_from_asic_id(asic_index)

    skip_hosts = duthost.get_asic_namespace_list()
    bgp_facts = duthost.bgp_facts(instance_id=asic_index)['ansible_facts']
    neigh_ip_v4 = None
    neigh_ip_v6 = None
    peer_group_v4 = None
    peer_group_v6 = None
    neigh_asn = None
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
            if v['description'] == tor1:
                if v['ip_version'] == 4:
                    neigh_ip_v4 = k
                    peer_group_v4 = v['peer group']
                elif v['ip_version'] == 6:
                    neigh_ip_v6 = k
                    peer_group_v6 = v['peer group']
                neigh_asn = v['remote AS']

    if (neigh_ip_v4 is None or neigh_ip_v6 is None or peer_group_v4 is None or
            peer_group_v6 is None or neigh_asn is None):
        pytest.skip("Failed to get neighbor info")

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][tor1]['bgp']['peers'][dut_asn][1]

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
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell("show run bgp", module_ignore_errors=True)))
    neigh_host = nbrhosts[tor1]["host"]
    if is_sonic_neigh:
        logger.debug("Neighbor BGP Config: {}".format(neigh_host.shell("show run bgp", module_ignore_errors=True)))
    else:
        logger.debug("Neighbor BGP Config: {}".format(neigh_host.eos_command(commands=["show run | section bgp"])))
        logger.debug(neigh_host.eos_config(
            backup=True,
            backup_options={'filename': EOS_NEIGH_BACKUP_CONFIG_FILE.format(neigh_host.hostname)},
        ))

    logger.debug('Setup_info: {}'.format(setup_info))

    yield setup_info

    # restore config to original state
    if is_sonic_neigh:
        config_reload(neigh_host, is_dut=False)
    else:
        neigh_host.load_configuration(EOS_NEIGH_BACKUP_CONFIG_FILE.format(neigh_host.hostname))

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
            parents=['router bgp {}'.format(setup['neigh_asn'])],
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
            parents=['router bgp {}'.format(setup['neigh_asn'])],
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
