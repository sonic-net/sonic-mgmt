"""

This script is to verify DUT's ability to carry both IPv4 and IPv6
Network Layer Reachability Information (NLRI) over a single IPv4 BGP session.

"""
import logging
import re
import time

import pytest
from tests.common.config_reload import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import DEFAULT_NAMESPACE
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2')
]

EOS_NEIGH_BACKUP_CONFIG_FILE = "/tmp/ipv6_nlri_eos_backup_config_{}"


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
    neigh_name = lldp_table[1]
    dut_int = lldp_table[0]
    neigh_int = lldp_table[2]
    if duthost.is_multi_asic:
        asic_index = duthost.get_port_asic_instance(dut_int).asic_index
    else:
        asic_index = None

    if is_sonic_neigh:
        if nbrhosts[neigh_name]["host"].is_multi_asic:
            neigh_asic_index = nbrhosts[neigh_name]["host"].get_port_asic_instance(neigh_int).asic_index
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
    neigh_asn = dict()

    # verify sessions are established and gather neighbor information
    for k, v in bgp_facts['bgp_neighbors'].items():
        if v['description'].lower() not in skip_hosts:
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
            logger.debug(v['description'])

    if (neigh_ip_v4 is None or neigh_ip_v6 is None or peer_group_v4 is None or
            peer_group_v6 is None or neigh_asn is None):
        pytest.skip("Failed to get neighbor info")

    dut_ip_v4 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][0]
    dut_ip_v6 = tbinfo['topo']['properties']['configuration'][neigh_name]['bgp']['peers'][dut_asn][1].lower()

    neigh_namespace = DEFAULT_NAMESPACE
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    for dut_port, neigh in mg_facts['minigraph_neighbors'].items():
        if neigh_name == neigh['name']:
            neigh_namespace = neigh['namespace']
            break

    logger.debug(duthost.shell('show ip bgp summary')['stdout'])
    logger.debug(duthost.shell('show ipv6 bgp summary')['stdout'])

    cmd = "show ipv6 bgp neighbor {} received-routes -n {}".format(neigh_ip_v6, namespace)
    dut_received_routes = duthost.shell(cmd, module_ignore_errors=True)['stdout']
    dut_nlri_routes = parse_dut_received_routes(dut_received_routes)
    dut_nlri_route = dut_nlri_routes[2]
    logger.debug("DUT NLRI route: {}".format(dut_nlri_route))

    neigh_host = nbrhosts[neigh_name]["host"]
    if is_sonic_neigh:
        logger.debug(neigh_host.shell('vtysh -n {} vtysh -c "clear bgp * soft"'.format(neigh_namespace)))
        cmd = "show ipv6 bgp neighbor {} received-routes".format(dut_ip_v6)
        neigh_nlri_routes = neigh_host.shell(cmd, module_ignore_errors=True)['stdout'].split('\n')
        logger.debug("neighbor routes: {}".format(neigh_nlri_routes[len(neigh_nlri_routes) - 3]))
        neigh_nlri_route = neigh_nlri_routes[len(neigh_nlri_routes) - 3].split()[1]
    else:
        logger.debug(neigh_host.eos_command(commands=["clear bgp * soft"]))
        cmd = "show ipv6 bgp peers {} received-routes".format(dut_ip_v6)
        neigh_nlri_routes = neigh_host.eos_command(commands=[cmd])['stdout'][0].split('\n')
        neigh_nlri_route_output = neigh_nlri_routes[len(neigh_nlri_routes) - 1]
        logger.debug("neighbor routes: {}".format(neigh_nlri_route_output))
        neigh_nlri_route = neigh_nlri_route_output.split()[2]

    setup_info = {
        'duthost': duthost,
        'neighhost': nbrhosts[neigh_name]["host"],
        'neigh_name': neigh_name,
        'dut_asn': dut_asn,
        'neigh_asn': neigh_asn[neigh_name],
        'namespace': namespace,
        'dut_ip_v4': dut_ip_v4,
        'dut_ip_v6': dut_ip_v6,
        'neigh_ip_v4': neigh_ip_v4,
        'neigh_ip_v6': neigh_ip_v6,
        'peer_group_v4': peer_group_v4,
        'peer_group_v6': peer_group_v6,
        'dut_nlri_route': dut_nlri_route,
        'neigh_nlri_route': neigh_nlri_route,
        'neigh_namespace': neigh_namespace,
        'dut_namespace': namespace,
        'asic_index': asic_index,
        'neigh_asic_index': neigh_asic_index,
        'is_sonic_neigh': is_sonic_neigh,
    }

    logger.debug("DUT BGP Config: {}".format(duthost.shell('show run bgp')['stdout']))
    if is_sonic_neigh:
        logger.debug("Neighbor BGP Config: {}".format(neigh_host.shell("show run bgp")['stdout']))
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
        config_reload(nbrhosts[neigh_name]["host"], wait=60, is_dut=False)
    else:
        neigh_host.load_configuration(EOS_NEIGH_BACKUP_CONFIG_FILE.format(neigh_host.hostname))

    config_reload(duthost, safe_reload=True, check_intf_up_ports=True, wait_for_bgp=True)


def test_nlri(setup):
    # show current adjacency
    cmd = "show ipv6 route {} -n {}".format(setup['dut_nlri_route'], setup['dut_namespace'])
    logger.debug("DUT Route from neighbor: {}".format(setup['duthost'].shell(cmd)['stdout']))
    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    if setup['is_sonic_neigh']:
        logger.debug("Neighbor Route from DUT: {}".format(setup['neighhost'].shell(cmd)['stdout']))
    else:
        logger.debug("Neighbor Route from DUT: {}".format(setup['neighhost'].eos_command(commands=[cmd])['stdout']))

    # remove current neighbor adjacency
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} peer-group {}" \
        -c "no neighbor {} peer-group {}"'\
        .format(setup['asic_index'], setup['dut_asn'], setup['neigh_ip_v4'], setup['peer_group_v4'],
                setup['neigh_ip_v6'], setup['peer_group_v6'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    logger.debug("DUT BGP Config After Neighbor Removal: {}".format(setup['duthost'].shell('show run bgp')['stdout']))

    if setup['is_sonic_neigh']:
        cmd = (
            'vtysh -n {} -c "config" -c "router bgp {}" -c "no neighbor {} peer-group {}" '
            '-c "no neighbor {} peer-group {}"'.format(
                setup['asic_index'],
                setup['neigh_asn'],
                setup['dut_ip_v4'],
                setup['peer_group_v4'],
                setup['dut_ip_v6'],
                setup['peer_group_v6'],
            )
        )

        setup['neighhost'].shell(cmd, module_ignore_errors=True)
        logger.debug("Neighbor BGP Config After Neighbor Removal: {}".format(
            setup['neighhost'].shell(cmd="show run bgp")['stdout'])
        )
    else:
        cmds = [
            "no neighbor {}".format(setup['dut_ip_v4']),
            "no neighbor {}".format(setup['dut_ip_v6']),
        ]

        setup['neighhost'].eos_config(
            lines=cmds,
            parents=['router bgp {}'.format(setup['neigh_asn'])],
        )

    wait_until(
        180,
        10,
        0,
        check_bgp_summary,
        setup['neighhost'],
        setup['dut_ip_v4'],
        False,
        setup['dut_ip_v6'],
        False,
        setup['is_sonic_neigh'],
    )

    # clear BGP table
    cmd = 'vtysh -n {} -c "clear ip bgp * soft"'.format(setup['asic_index'])
    setup['duthost'].shell(cmd)
    if setup['is_sonic_neigh']:
        cmd = 'vtysh -c "clear ip bgp * soft"'
        setup['neighhost'].shell(cmd)
    else:
        setup['neighhost'].eos_command(commands=["clear ip bgp * soft"])

    # verify route is no longer shared
    time.sleep(30)
    cmd = "show ipv6 route {} -n {}".format(setup['dut_nlri_route'], setup['dut_namespace'])
    dut_route_out = setup['duthost'].shell(cmd)['stdout']
    pytest_assert(
        setup['neigh_ip_v6'] not in get_addresses_from_show_route(dut_route_out),
        "neigh_ip_v6 route still exists in DUT",
    )

    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    if setup['is_sonic_neigh']:
        neigh_route_out = setup['neighhost'].shell(cmd)['stdout']
    else:
        neigh_route_out = setup['neighhost'].eos_command(commands=[cmd])['stdout'][0]

    pytest_assert(setup['dut_ip_v6'] not in neigh_route_out, "No route to IPv6 DUT.")

    # configure IPv4 peer config on DUT
    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor NLRI peer-group" -c "address-family ipv4 unicast" \
        -c "neighbor NLRI allowas-in" -c "neighbor NLRI send-community both" \
        -c "neighbor NLRI soft-reconfiguration inbound" -c "exit-address-family" -c "address-family ipv6 unicast" \
        -c "neighbor NLRI allowas-in" -c "neighbor NLRI send-community both" \
            -c "neighbor NLRI soft-reconfiguration inbound"'.format(setup['asic_index'], setup['dut_asn'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)

    cmd = 'vtysh -n {} -c "config" -c "router bgp {}" -c "neighbor {} peer-group NLRI" -c "neighbor {} remote-as {}"\
        -c "address-family ipv4 unicast" -c "neighbor NLRI activate" -c "exit-address-family" \
        -c "address-family ipv6 unicast" -c "neighbor NLRI activate"'\
            .format(setup['asic_index'], setup['dut_asn'], setup['neigh_ip_v4'], setup['neigh_ip_v4'],
                    setup['neigh_asn'])
    setup['duthost'].shell(cmd, module_ignore_errors=True)
    logger.debug("DUT BGP Config After Peer Config: {}".format(setup['duthost'].shell('show run bgp')['stdout']))

    # configure IPv4 peer on neighbor
    if setup['is_sonic_neigh']:
        cmd = (
            'vtysh -c "config" -c "router bgp {}" -c "neighbor NLRI peer-group" '
            '-c "address-family ipv4 unicast" -c "neighbor NLRI allowas-in" '
            '-c "neighbor NLRI send-community both" -c "neighbor NLRI soft-reconfiguration inbound" '
            '-c "address-family ipv6 unicast" -c "neighbor NLRI activate" '
            '-c "neighbor NLRI allowas-in" -c "neighbor NLRI soft-reconfiguration inbound"'
        ).format(setup['neigh_asn'])
        setup['neighhost'].shell(cmd, module_ignore_errors=True)

        cmd = (
            'vtysh -c "config" -c "router bgp {}" -c "neighbor {} peer-group NLRI" -c "neighbor {} remote-as {}" '
            '-c "address-family ipv4 unicast" -c "neighbor NLRI activate"'
        ).format(setup['neigh_asn'], setup['dut_ip_v4'], setup['dut_ip_v4'], setup['dut_asn'])
        setup['neighhost'].shell(cmd, module_ignore_errors=True)
        logger.debug(
            "Neighbor BGP Config After Peer Config: {}".format(setup['neighhost'].shell('show run bgp')['stdout'])
        )
    else:
        cmds = [
            "neighbor NLRI peer group",
            "address-family ipv4",
            "neighbor NLRI allowas-in",
            "neighbor NLRI send-community",
            "neighbor NLRI rib-in pre-policy retain all",
            "address-family ipv6",
            # "neighbor NLRI activate",
            "neighbor NLRI allowas-in",
            "neighbor NLRI rib-in pre-policy retain all",
            "neighbor {} peer group NLRI".format(setup['dut_ip_v4']),
            "neighbor {} remote-as {}".format(setup['dut_ip_v4'], setup['dut_asn']),
        ]

        setup['neighhost'].eos_config(
            lines=cmds,
            parents=['router bgp {}'.format(setup['neigh_asn'])],
        )

        logger.debug("Neighbor BGP Config After Peer Config: {}".format(
            setup['neighhost'].eos_command(commands=["show run | section bgp"])['stdout']
        ))

    wait_until(
        180,
        10,
        0,
        check_bgp_summary,
        setup['neighhost'],
        setup['dut_ip_v4'],
        True,
        setup['dut_ip_v6'],
        False,
        setup['is_sonic_neigh'],
    )

    bgp_facts = setup['duthost'].bgp_facts(instance_id=setup['asic_index'])['ansible_facts']
    pytest_assert(bgp_facts['bgp_neighbors'][setup['neigh_ip_v4']]['state'] == 'established',
                  "Neighbor IPv4 state is no established.")

    # verify route is shared
    cmd = "show ipv6 route {} -n {}".format(setup['dut_nlri_route'], setup['dut_namespace'])
    pytest_assert(
        wait_until(
            180,
            15,
            0,
            check_dut_routing_entry, setup['duthost'], cmd, setup['dut_nlri_route'],
        ),
        "Routing entry for DUT not established.",
    )

    cmd = "show ipv6 route {}".format(setup['neigh_nlri_route'])
    if setup['is_sonic_neigh']:
        neigh_route_out = setup['neighhost'].shell(cmd)['stdout']
    else:
        neigh_route_out = setup['neighhost'].eos_command(commands=[cmd])['stdout'][0]

    pytest_assert("Routing entry for {}".format(setup['neigh_nlri_route']) in neigh_route_out,
                  "Routing entry for neighbor not established.")


def parse_dut_received_routes(command_output):
    lines = command_output.split('\n')
    combined_lines = []
    current_line = ""
    for line in lines:
        if line.startswith(" *>"):
            if current_line:
                combined_lines.append(current_line)

            current_line = line
        else:
            current_line += " " + line.strip()

    if current_line:
        combined_lines.append(current_line)

    # Regular expression to match the routes
    route_pattern = re.compile(r'^\s*\*>\s+([\da-fA-F:\/]+)\s+([\da-fA-F:]+)\s+.*$')
    routes = []
    for line in combined_lines:
        match = route_pattern.match(line)
        if match:
            network = match.group(1)
            routes.append(network)

    return routes


def check_bgp_summary(host, neighbor_v4, v4_present, neighbor_v6, v6_present, is_sonic_neigh):
    if is_sonic_neigh:
        ipv4_sum = host.shell(cmd="show ip bgp summary")[u'stdout']
        is_present = neighbor_v4 in ipv4_sum
        if is_present != v4_present:
            return False

        ipv6_sum = host.shell(cmd="show ipv6 bgp summary")[u'stdout']
        is_present = neighbor_v6 in ipv6_sum
        if is_present != v6_present:
            return False
        return True
    else:
        ipv4_sum = host.eos_command(commands=["show ip bgp summary"])['stdout'][0]
        is_present = neighbor_v4 in ipv4_sum
        if is_present != v4_present:
            return False

        ipv6_sum = host.eos_command(commands=["show ipv6 bgp summary"])['stdout'][0]
        is_present = neighbor_v6 in ipv6_sum
        if is_present != v6_present:
            return False
        return True


def get_addresses_from_show_route(cmd_output):
    matches = re.findall(r'\* ([^,]+), via', cmd_output)
    return set(matches)


def check_dut_routing_entry(duthost, cmd, route_to_check):
    dut_route_out = duthost.shell(cmd)['stdout']
    return "Routing entry for {}".format(route_to_check) in dut_route_out
