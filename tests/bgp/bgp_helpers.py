import os
import re
import time
import json
import pytest
import yaml
import random
import logging
import requests
from natsort import natsorted
import ipaddr as ipaddress
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_NEIGHBOR_MAP, DEFAULT_NAMESPACE
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.helpers.parallel import parallel_run
from tests.common.utilities import wait_until

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DUT_TMP_DIR = os.path.join('tmp', os.path.basename(BASE_DIR))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
BGP_PLAIN_TEMPLATE = 'bgp_plain.j2'
BGP_NO_EXPORT_TEMPLATE = 'bgp_no_export.j2'
BGP_CONFIG_BACKUP = 'backup_bgpd.conf.j2'
DEFAULT_BGP_CONFIG = '/usr/share/sonic/templates/bgpd/bgpd.conf.j2'
DUMP_FILE = "/tmp/bgp_monitor_dump.log"
CUSTOM_DUMP_SCRIPT = "bgp/bgp_monitor_dump.py"
CUSTOM_DUMP_SCRIPT_DEST = "/usr/share/exabgp/bgp_monitor_dump.py"
BGPMON_TEMPLATE_FILE = 'bgp/templates/bgp_template.j2'
BGPMON_CONFIG_FILE = '/tmp/bgpmon.json'
BGP_MONITOR_NAME = "bgp_monitor"
BGP_MONITOR_PORT = 7000
BGPSENTINEL_CONFIG_FILE = '/tmp/bgpsentinel.json'
BGP_SENTINEL_NAME_V4 = "bgp_sentinelV4"
BGP_SENTINEL_NAME_V6 = "bgp_sentinelV6"
BGP_SENTINEL_PORT_V4 = 7900
BGP_SENTINEL_PORT_V6 = 7901
BGP_ANNOUNCE_TIME = 30  # should be enough to receive and parse bgp updates
CONSTANTS_FILE = '/etc/sonic/constants.yml'
EXABGP_BASE_PORT = 5000
EXABGP_BASE_PORT_V6 = 6000
TEST_COMMUNITY = '1010:1010'
PREFIX_LISTS = {
    'ALLOWED': ['172.16.10.0/24'],
    'ALLOWED_WITH_COMMUNITY': ['172.16.30.0/24'],
    'ALLOWED_V6': ['2000:172:16:10::/64'],
    'ALLOWED_WITH_COMMUNITY_V6': ['2000:172:16:30::/64'],
    'DISALLOWED': ['172.16.50.0/24'],
    'DISALLOWED_V6': ['2000:172:16:50::/64']
}
ALLOW_LIST_PREFIX_JSON_FILE = '/tmp/allow_list.json'
DROP_COMMUNITY = ''
DEFAULT_ACTION = ''
ANNOUNCE = 'announce'
DEFAULT = "default"
IP_VER = 4
QUEUED = "queued"
ACTION_IN = "in"
ACTION_NOT_IN = "not"
ACTION_STOP = "stop"


def apply_bgp_config(duthost, template_name):
    """
    Apply bgp configuration on the bgp docker of DUT

    Args:
        duthost: DUT host object
        template_name: pathname of the bgp config on the DUT
    """
    duthost.docker_copy_to_all_asics('bgp', template_name, DEFAULT_BGP_CONFIG)
    duthost.restart_service("bgp")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "swss"),
                  "SWSS not started.")


def define_config(duthost, template_src_path, template_dst_path):
    """
    Define configuration of bgp on the DUT

    Args:
        duthost: DUT host object
        template_src_path: pathname of the bgp config on the server
        template_dst_path: pathname of the bgp config on the DUT
    """
    duthost.shell("mkdir -p {}".format(DUT_TMP_DIR))
    duthost.copy(src=template_src_path, dest=template_dst_path)


def get_no_export_output(vm_host):
    """
    Get no export routes on the VM

    Args:
        vm_host: VM host object
    """
    out = vm_host.eos_command(commands=['show ip bgp community no-export'])["stdout"]
    return re.findall(r'\d+\.\d+.\d+.\d+\/\d+\s+\d+\.\d+.\d+.\d+.*', out[0])


def apply_default_bgp_config(duthost, copy=False):
    """
    Apply default bgp configuration on the bgp docker of DUT

    Args:
        duthost: DUT host object
        copy: Bool value defines copy action of default bgp configuration
    """
    bgp_config_backup = os.path.join(DUT_TMP_DIR, BGP_CONFIG_BACKUP)
    if copy:
        duthost.docker_copy_from_asic('bgp', DEFAULT_BGP_CONFIG, bgp_config_backup)
    else:
        duthost.docker_copy_to_all_asics('bgp', bgp_config_backup, DEFAULT_BGP_CONFIG)
        # Skip 'start-limit-hit' threshold
        duthost.reset_service("bgp")
        duthost.restart_service("bgp")
        pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"),
                      "BGP not started.")


def parse_exabgp_dump(host):
    """
    Parse the dump file of exabgp, and build a set for checking routes
    """
    routes = set()
    output_lines = host.shell("cat {}".format(DUMP_FILE), verbose=False)['stdout_lines']
    for line in output_lines:
        routes.add(line)
    return routes


def parse_rib(host, ip_ver, asic_namespace=None):
    """
    Parse output of 'show bgp ipv4/6' and parse into a dict for checking routes
    """
    routes = {}

    if asic_namespace:
        asic_list = [asic_namespace]
    else:
        asic_list = host.get_frontend_asic_namespace_list()

    for namespace in asic_list:
        bgp_cmd = "vtysh -c \"show bgp ipv%d json\"" % ip_ver
        cmd = host.get_vtysh_cmd_for_namespace(bgp_cmd, namespace)

        route_data = json.loads(host.shell(cmd, verbose=False)['stdout'])
        for ip, nexthops in list(route_data['routes'].items()):
            aspath = set()
            for nexthop in nexthops:
                # if internal route with aspath as '' skip adding
                if 'path' in nexthop and nexthop['path'] == '':
                    continue
                aspath.add(nexthop['path'])
            # if aspath is valid, add it into routes
            if aspath:
                routes[ip] = aspath

    return routes


def get_routes_not_announced_to_bgpmon(duthost, ptfhost, asic_namespace=None):
    """
    Get the routes that are not announced to bgpmon by checking dump of bgpmon on PTF.
    """
    def _dump_fie_exists(host):
        return host.stat(path=DUMP_FILE).get('stat', {}).get('exists', False)
    pytest_assert(wait_until(120, 10, 0, _dump_fie_exists, ptfhost))
    time.sleep(20)  # Wait until all routes announced to bgpmon
    bgpmon_routes = parse_exabgp_dump(ptfhost)
    rib_v4 = parse_rib(duthost, 4, asic_namespace=asic_namespace)
    rib_v6 = parse_rib(duthost, 6, asic_namespace=asic_namespace)
    routes_dut = dict(list(rib_v4.items()) + list(rib_v6.items()))
    return [route for route in list(routes_dut.keys()) if route not in bgpmon_routes]


def remove_bgp_neighbors(duthost, asic_index):
    """
    Remove the bgp neigbors for a particular BGP instance
    """
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    namespace_prefix = '-n ' + namespace if namespace else ''

    # Convert the json formatted result of sonic-cfggen into bgp_neighbors dict
    bgp_neighbors = json.loads(duthost.command("sudo sonic-cfggen {} -d --var-json {}"
                               .format(namespace_prefix, "BGP_NEIGHBOR"))["stdout"])
    cmd = 'sudo sonic-db-cli {} CONFIG_DB keys "BGP_NEI*" | xargs sonic-db-cli {} CONFIG_DB del'\
          .format(namespace_prefix, namespace_prefix)
    duthost.shell(cmd)

    # Restart BGP instance on that asic
    duthost.restart_service_on_asic("bgp", asic_index)
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")

    return bgp_neighbors


def restore_bgp_neighbors(duthost, asic_index, bgp_neighbors):
    """
    Restore the bgp neigbors for a particular BGP instance
    """
    namespace = duthost.get_namespace_from_asic_id(asic_index)
    namespace_prefix = '-n ' + namespace if namespace else ''

    # Convert the bgp_neighbors dict into json format after adding the table name.
    bgp_neigh_dict = {"BGP_NEIGHBOR": bgp_neighbors}
    bgp_neigh_json = json.dumps(bgp_neigh_dict)
    duthost.shell("sudo sonic-cfggen {} -a '{}' --write-to-db".format(namespace_prefix, bgp_neigh_json))

    # Restart BGP instance on that asic
    duthost.restart_service_on_asic("bgp", asic_index)
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")


@pytest.fixture(scope='module')
def bgp_allow_list_setup(tbinfo, nbrhosts, duthosts, rand_one_dut_hostname):
    """
    Get bgp_allow_list related information
    """
    duthost = duthosts[rand_one_dut_hostname]
    topo_type = tbinfo["topo"]["type"]
    constants_stat = duthost.stat(path=CONSTANTS_FILE)
    pytest_require(constants_stat['stat']['exists'] is not None,
                   "No file {} on DUT, BGP Allow List is not supported".format(CONSTANTS_FILE))

    constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])

    global DEFAULT_ACTION
    try:
        DEFAULT_ACTION = constants['constants']['bgp']['allow_list']['default_action']
    except KeyError:
        pytest.skip('No BGP Allow List configuration in {}, BGP Allow List is not supported.'.format(CONSTANTS_FILE))

    global DROP_COMMUNITY
    try:
        DROP_COMMUNITY = constants['constants']['bgp']['allow_list']['drop_community']
    except KeyError:
        pytest.skip('No BGP Allow List Drop Commnity define in {}, BGP Allow List is not supported.'
                    .format(CONSTANTS_FILE))

    setup_info = {}

    upstream_type = UPSTREAM_NEIGHBOR_MAP[topo_type].upper()
    downstream_type = DOWNSTREAM_NEIGHBOR_MAP[topo_type].upper()
    downstream_neighbors = \
        natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith(downstream_type)])
    downstream = downstream_neighbors[0]
    upstream_neighbors = natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith(upstream_type)])
    other_neighbors = downstream_neighbors[1:3]    # Only check a few neighbors to save time
    if upstream_neighbors:
        other_neighbors += upstream_neighbors[0:2]

    downstream_offset = tbinfo['topo']['properties']['topology']['VMs'][downstream]['vm_offset']
    downstream_exabgp_port = EXABGP_BASE_PORT + downstream_offset
    downstream_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + downstream_offset

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    downstream_namespace = DEFAULT_NAMESPACE
    for _, neigh in list(mg_facts['minigraph_neighbors'].items()):
        if downstream == neigh['name'] and neigh['namespace']:
            downstream_namespace = neigh['namespace']
            break

    setup_info = {
        'downstream': downstream,
        'downstream_namespace': downstream_namespace,
        'downstream_exabgp_port': downstream_exabgp_port,
        'downstream_exabgp_port_v6': downstream_exabgp_port_v6,
        'other_neighbors': other_neighbors,
    }
    yield setup_info


def update_routes(action, ptfip, port, route):
    if action not in ['announce', 'withdraw']:
        logging.error('Unsupported route update operation: {}'.format(action))
        return
    msg = '{} route {} next-hop {}'.format(action, route['prefix'], route['nexthop'])
    if 'community' in route:
        msg += ' community {}'.format(route['community'])

    url = 'http://%s:%d' % (ptfip, port)
    data = {'commands': msg}
    logging.info('Post url={}, data={}'.format(url, data))
    r = requests.post(url, data=data)
    assert r.status_code == 200


def build_routes(tbinfo, prefix_list, expected_community):
    nhipv4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6']
    routes = []
    for list_name, prefixes in list(prefix_list.items()):
        logging.info('list_name: {}, prefixes: {}'.format(list_name, str(prefixes)))
        for prefix in prefixes:
            route = {}
            route['prefix'] = prefix
            if ipaddress.IPNetwork(prefix).version == 4:
                route['nexthop'] = nhipv4
            else:
                route['nexthop'] = nhipv6
            if 'COMMUNITY' in list_name:
                route['community'] = expected_community
            routes.append(route)

    return routes


@pytest.fixture(scope='module', autouse=True)
def prepare_eos_routes(bgp_allow_list_setup, ptfhost, nbrhosts, tbinfo):
    routes = build_routes(tbinfo, PREFIX_LISTS, TEST_COMMUNITY)
    downstream = bgp_allow_list_setup['downstream']
    downstream_exabgp_port = bgp_allow_list_setup['downstream_exabgp_port']
    downstream_exabgp_port_v6 = bgp_allow_list_setup['downstream_exabgp_port_v6']
    downstream_asn = tbinfo['topo']['properties']['configuration'][downstream]['bgp']['asn']
    downstream_peers = tbinfo['topo']['properties']['configuration'][downstream]['bgp']['peers']

    # By default, EOS does not send community, this is to config EOS to send community
    cmds = []
    for peer_ips in list(downstream_peers.values()):
        for peer_ip in peer_ips:
            cmds.append('neighbor {} send-community'.format(peer_ip))
    nbrhosts[downstream]['host'].eos_config(lines=cmds, parents='router bgp {}'.format(downstream_asn))

    for route in routes:
        if ipaddress.IPNetwork(route['prefix']).version == 4:
            update_routes('announce', ptfhost.mgmt_ip, downstream_exabgp_port, route)
        else:
            update_routes('announce', ptfhost.mgmt_ip, downstream_exabgp_port_v6, route)
    time.sleep(3)

    yield

    for route in routes:
        if ipaddress.IPNetwork(route['prefix']).version == 4:
            update_routes('withdraw', ptfhost.mgmt_ip, downstream_exabgp_port, route)
        else:
            update_routes('withdraw', ptfhost.mgmt_ip, downstream_exabgp_port_v6, route)
    # Restore EOS config
    no_cmds = ['no {}'.format(cmd) for cmd in cmds]
    nbrhosts[downstream]['host'].eos_config(lines=no_cmds, parents='router bgp {}'.format(downstream_asn))


def apply_allow_list(duthost, namespace, allow_list, allow_list_file_path):
    duthost.copy(content=json.dumps(allow_list, indent=3), dest=allow_list_file_path)
    duthost.shell('sonic-cfggen {} -j {} -w'.format('-n ' + namespace if namespace else '', allow_list_file_path))
    time.sleep(3)


def remove_allow_list(duthost, namespace, allow_list_file_path):
    allow_list_keys = duthost.shell('sonic-db-cli {} CONFIG_DB keys "BGP_ALLOWED_PREFIXES*"'
                                    .format('-n ' + namespace if namespace else ''))['stdout_lines']
    for key in allow_list_keys:
        duthost.shell('sonic-db-cli {} CONFIG_DB del "{}"'.format('-n ' + namespace if namespace else '', key))

    duthost.shell('rm -rf {}'.format(allow_list_file_path))


def check_routes_on_from_neighbor(setup_info, nbrhosts):
    """
    Verify if there are routes on neighbor who announce them.
    """
    downstream = setup_info['downstream']
    for prefixes in list(PREFIX_LISTS.values()):
        for prefix in prefixes:
            downstream_route = nbrhosts[downstream]['host'].get_route(prefix)
            route_entries = downstream_route['vrfs']['default']['bgpRouteEntries']
            pytest_assert(prefix in route_entries, 'Announced route {} not found on {}'.format(prefix, downstream))


def check_results(results):
    pytest_assert(len(list(results.keys())) > 0, 'No result on neighbors')
    failed_results = {}
    for node, node_prefix_results in list(results.items()):
        failed_results[node] = [r for r in node_prefix_results if r['failed']]

    pytest_assert(all([len(r) == 0 for r in list(failed_results.values())]),
                  'Unexpected routes on neighbors, failed_results={}'.format(json.dumps(failed_results, indent=2)))


def check_routes_on_neighbors_empty_allow_list(nbrhosts, setup, permit=True):
    """
    Check routes result for neighbors in parallel without applying allow list
    """
    other_neighbors = setup['other_neighbors']

    @reset_ansible_local_tmp
    def check_other_neigh(nbrhosts, permit, node=None, results=None):
        logging.info('Checking routes on {}'.format(node))

        prefix_results = []
        for list_name, prefixes in list(PREFIX_LISTS.items()):
            for prefix in prefixes:
                prefix_result = {'failed': False, 'prefix': prefix, 'reasons': []}
                neigh_route = nbrhosts[node]['host'].get_route(prefix)['vrfs']['default']['bgpRouteEntries']

                if permit:
                    # All routes should be forwarded
                    if prefix not in neigh_route:
                        prefix_result['failed'] = True
                        prefix_result['reasons'].append('Route {} not found on {}'.format(prefix, node))
                    else:
                        communityList = neigh_route[prefix]['bgpRoutePaths'][0]['routeDetail']['communityList']

                        # Should add drop_community to all routes
                        if DROP_COMMUNITY not in communityList:
                            prefix_result['failed'] = True
                            prefix_result['reasons'].append('When default_action="permit" and allow list is empty, '
                                                            'should add drop_community to all routes. route={}, node={}'
                                                            .format(prefix, node))

                        # Should keep original route community
                        if 'COMMUNITY' in list_name:
                            if TEST_COMMUNITY not in communityList:
                                prefix_result['failed'] = True
                                prefix_result['reasons']\
                                    .append('When default_action="permit" and allow list is empty, should keep the '
                                            'original community {}, route={}, node={}'
                                            .format(TEST_COMMUNITY, prefix, node))

                else:
                    # All routes should be dropped
                    if prefix in neigh_route:
                        prefix_result['failed'] = True
                        prefix_result['reasons'].append('When default_action="deny" and allow list is empty, all routes'
                                                        ' should be dropped. route={}, node={}'.format(prefix, node))
                prefix_results.append(prefix_result)
        results[node] = prefix_results

    results = parallel_run(check_other_neigh, (nbrhosts, permit), {}, other_neighbors, timeout=180)
    check_results(results)


def check_routes_on_neighbors(nbrhosts, setup, permit=True):
    """
    Check routes result for neighbors in parallel
    """
    other_neighbors = setup['other_neighbors']

    @reset_ansible_local_tmp
    def check_other_neigh(nbrhosts, permit, node=None, results=None):
        logging.info('Checking routes on {}'.format(node))

        prefix_results = []
        for list_name, prefixes in list(PREFIX_LISTS.items()):
            for prefix in prefixes:
                prefix_result = {'failed': False, 'prefix': prefix, 'reasons': []}
                neigh_route = nbrhosts[node]['host'].get_route(prefix)['vrfs']['default']['bgpRouteEntries']

                if permit:
                    # All routes should be forwarded
                    if prefix not in neigh_route:
                        prefix_result['failed'] = True
                        prefix_result['reasons'].append('Route {} not found on {}'.format(prefix, node))
                    else:
                        communityList = neigh_route[prefix]['bgpRoutePaths'][0]['routeDetail']['communityList']

                        if 'DISALLOWED' in list_name:
                            # Should add drop_community to routes not on allow list
                            if DROP_COMMUNITY not in communityList:
                                prefix_result['failed'] = True
                                prefix_result['reasons']\
                                    .append('When default_action="permit", should add drop_community to routes not on '
                                            'allow list. route={}, node={}'.format(prefix, node))
                        else:
                            # Should not add drop_community to routes on allow list
                            if DROP_COMMUNITY in communityList:
                                prefix_result['failed'] = True
                                prefix_result['reasons']\
                                    .append('When default_action="permit", should not add drop_community to routes on '
                                            'allow listroute in allow list with community, route={}, node={}'
                                            .format(prefix, node))

                            # Should keep original route community
                            if 'COMMUNITY' in list_name:
                                if TEST_COMMUNITY not in communityList:
                                    prefix_result['failed'] = True
                                    prefix_result['reasons']\
                                        .append('When default_action="permit", route on allow list with community '
                                                'should keep its original community {}, route={}, node={}'
                                                .format(TEST_COMMUNITY, prefix, node))
                else:
                    if 'DISALLOWED' in list_name:
                        # Routes not on allow list should not be forwarded
                        if prefix in neigh_route:
                            prefix_result['failed'] = True
                            prefix_result['reasons'].append('When default_action="deny", route NOT on allow list should'
                                                            ' not be forwarded. route={}, node={}'.format(prefix, node))
                    else:
                        # Routes on allow list should be forwarded
                        if prefix not in neigh_route:
                            prefix_result['failed'] = True
                            prefix_result['reasons'].append('When default_action="deny", route on allow list should be '
                                                            'forwarded. route={}, node={}'.format(prefix, node))
                        else:
                            communityList = neigh_route[prefix]['bgpRoutePaths'][0]['routeDetail']['communityList']
                            # Forwarded route should not have DROP_COMMUNITY
                            if DROP_COMMUNITY in communityList:
                                prefix_result['failed'] = True
                                prefix_result['reasons']\
                                    .append('When default_action="deny", route on allow list with community should not '
                                            'have drop_community. route={}, node={}'.format(prefix, node))

                            # Should keep original route community
                            if 'COMMUNITY' in list_name:
                                if TEST_COMMUNITY not in communityList:
                                    prefix_result['failed'] = True
                                    prefix_result['reasons'].\
                                        append('When default_action="deny", route on allow list with community should '
                                               'keep its original community {}. route={}, node={}'
                                               .format(TEST_COMMUNITY, prefix, node))
                prefix_results.append(prefix_result)
        results[node] = prefix_results

    results = parallel_run(check_other_neigh, (nbrhosts, permit), {}, other_neighbors, timeout=180)
    check_results(results)


def checkout_bgp_mon_routes(duthost, ptfhost):
    routes_not_announced = get_routes_not_announced_to_bgpmon(duthost, ptfhost)
    pytest_assert(routes_not_announced == [], "Not all routes are announced to bgpmon: {}".format(routes_not_announced))


def get_default_action():
    """
    Since the value of this constant has been changed in the helper, it cannot be directly imported
    """
    return DEFAULT_ACTION


def restart_bgp_session(duthost):
    """
    Restart bgp session
    """
    logging.info("Restart all BGP sessions")
    duthost.shell('vtysh -c "clear bgp *"')


def get_ptf_recv_port(duthost, vm_name, tbinfo):
    """
    Get ptf receive port
    """
    port = duthost.shell("show lldp table | grep -w {} | awk '{{print $1}}'".format(vm_name))['stdout']
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    return mg_facts['minigraph_ptf_indices'][port]


def get_eth_port(duthost, tbinfo):
    """
    Get ethernet port that connects to T0 VM
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    t0_vm = [vm_name for vm_name in mg_facts['minigraph_devices'].keys() if vm_name.endswith('T0')][0]
    port = duthost.shell("show ip interface | grep -w {} | awk '{{print $1}}'".format(t0_vm))['stdout']
    return port


def get_vm_offset(duthost, nbrhosts, tbinfo):
    """
    Get port offset of exabgp and ptf receive port
    """
    logging.info("get_vm_offset ---------")
    vm_name = random.choice([vm_name for vm_name in nbrhosts.keys() if vm_name.endswith('T0')])
    ptf_recv_port = get_ptf_recv_port(duthost, vm_name, tbinfo)
    port_offset = tbinfo['topo']['properties']['topology']['VMs'][vm_name]['vm_offset']
    logging.info("vm_offset of {} is: {}".format(vm_name, port_offset))
    return port_offset, ptf_recv_port


def get_exabgp_port(duthost, nbrhosts, tbinfo, exabgp_base_port):
    """
    Get exabgp port and ptf receive port
    """
    port_offset, ptf_recv_port = get_vm_offset(duthost, nbrhosts, tbinfo)
    return exabgp_base_port + port_offset, ptf_recv_port


def get_vm_name(tbinfo, vm_level='T2'):
    """
    Get vm name, default return value would be T2 VM name
    """
    for vm in tbinfo['topo']['properties']['topology']['VMs'].keys():
        if vm[-2:] == vm_level:
            return vm


def get_t2_ptf_intfs(mg_facts):
    """
    Get ptf interface list that connect with T2 VMs
    """
    t2_ethernets = []
    for k, v in mg_facts["minigraph_neighbors"].items():
        if v['name'][-2:] == 'T2':
            t2_ethernets.append(k)

    ptf_interfaces = []
    for port in t2_ethernets:
        ptf_interfaces.append(mg_facts['minigraph_ptf_indices'][port])
    return ptf_interfaces


def get_bgp_neighbor_ip(duthost, vm_name, vrf=DEFAULT):
    """
    Get ipv4 and ipv6 bgp neighbor ip addresses
    """
    if vrf == DEFAULT:
        cmd_v4 = "show ip interface | grep -w {} | awk '{{print $5}}'"
        cmd_v6 = "show ipv6 interface | grep -w {} | awk '{{print $5}}'"
        bgp_neighbor_ip = duthost.shell(cmd_v4.format(vm_name))['stdout']
        bgp_neighbor_ipv6 = duthost.shell(cmd_v6.format(vm_name))['stdout']
    else:
        cmd_v4 = "show ip interface | grep -w {} | awk '{{print $7}}' | sed 's/)//g'"
        cmd_v6 = "show ipv6 interface | grep -w {} | awk '{{print $7}}' | sed 's/)//g'"
        bgp_neighbor_ip = duthost.shell(cmd_v4.format(vm_name))['stdout'][1:-1]
        bgp_neighbor_ipv6 = duthost.shell(cmd_v6.format(vm_name))['stdout'][1:-1]
    logging.info("BGP neighbor of {} is {}".format(vm_name, bgp_neighbor_ip))
    logging.info("IPv6 BGP neighbor of {} is {}".format(vm_name, bgp_neighbor_ipv6))

    return bgp_neighbor_ip, bgp_neighbor_ipv6


def get_vrf_route_json(duthost, route, vrf=DEFAULT, ip_ver=IP_VER):
    """
    Get output of 'show ip route vrf xxx xxx json' or 'show ipv6 route vrf xxx xxx json'
    """
    if ip_ver == IP_VER:
        logging.info('Execute command - vtysh -c "show ip route vrf {} {} json"'.format(vrf, route))
        out = json.loads(duthost.shell('vtysh -c "show ip route vrf {} {} json"'.
                                       format(vrf, route), verbose=False)['stdout'])
    else:
        logging.info('Execute command - vtysh -c "show ipv6 route vrf {} {} json"'.format(vrf, route))
        out = json.loads(duthost.shell('vtysh -c "show ipv6 route vrf {} {} json"'.
                                       format(vrf, route), verbose=False)['stdout'])

    logging.info('Command output:\n {}'.format(out))
    return out


def check_route_status(duthost, route, check_field, vrf=DEFAULT, ip_ver=IP_VER, expect_status=True):
    """
    Get 'offloaded' or 'queu' value of specific route
    """
    out = get_vrf_route_json(duthost, route, vrf, ip_ver)
    check_field_status = out[route][0].get(check_field, None)
    if check_field_status:
        logging.info("Route:{} - {} status:{} - expect status:{}"
                     .format(route, check_field, check_field_status, expect_status))
        return True is expect_status
    else:
        logging.info("No {} value found in route:{}".format(check_field, out))
        return False is expect_status


def check_route_install_status(duthost, route, vrf=DEFAULT, ip_ver=IP_VER, check_point=QUEUED, action=ACTION_IN):
    """
    Verify route install status
    """
    if check_point == QUEUED:
        if action == ACTION_IN:
            pytest_assert(wait_until(60, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver),
                          "Vrf:{} - route:{} is not in {} state".format(vrf, route, check_point))
        else:
            pytest_assert(wait_until(60, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver, False),
                          "Vrf:{} - route:{} is in {} state".format(vrf, route, check_point))
    else:
        if action == ACTION_IN:
            pytest_assert(wait_until(60, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver),
                          "Vrf:{} - route:{} is not installed into FIB".format(vrf, route))
        else:
            pytest_assert(wait_until(60, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver, False),
                          "Vrf:{} - route:{} is installed into FIB".format(vrf, route))


def check_propagate_route(duthost, route, bgp_neighbor, vrf=DEFAULT, ip_ver=IP_VER, action=ACTION_IN):
    """
    Check whether ipv4 or ipv6 route is advertised to T2 VM
    """
    if ip_ver == IP_VER:
        logging.info('Execute command - vtysh -c "show ip bgp vrf {} neighbors {} advertised-routes"'
                     .format(vrf, bgp_neighbor))
        out = duthost.shell('vtysh -c "show ip bgp vrf {} neighbors {} advertised-routes"'.format(vrf, bgp_neighbor),
                            verbose=False)['stdout']
    else:
        logging.info('Execute command - vtysh -c "show ip bgp vrf {} ipv6 neighbors {} advertised-routes"'
                     .format(vrf, bgp_neighbor))
        out = duthost.shell('vtysh -c "show ip bgp vrf {} ipv6 neighbors {} advertised-routes"'.
                            format(vrf, bgp_neighbor), verbose=False)['stdout']
    logging.debug('Command output:\n {}'.format(out))

    if action == ACTION_IN:
        if route in out:
            logging.info("Route:{} found - action:{}".format(route, action))
            return True
        else:
            logging.info("Route:{} not found - action:{}".format(route, action))
            return False
    else:
        if route in out:
            logging.info("Route:{} found - action:{}".format(route, action))
            return False
        else:
            logging.info("Route:{} not found - action:{}".format(route, action))
            return True


def validate_route_propagate_status(duthost, route, bgp_neighbor, vrf=DEFAULT, ip_ver=IP_VER, exist=True):
    """
    Verify ipv4 or ipv6 route propagate status
    :param duthost: duthost fixture
    :param route: ipv4 or ipv6 route
    :param bgp_neighbor: ipv4 or ipv6 bgp neighbor address
    :param vrf: vrf name
    :param ip_ver: ip version number
    :param exist: route expected status
    """
    if exist:
        pytest_assert(wait_until(30, 2, 0, check_propagate_route, duthost, route, bgp_neighbor, vrf, ip_ver),
                      "Vrf:{} - route:{} is not propagated to {}".format(vrf, route, bgp_neighbor))
    else:
        pytest_assert(wait_until(30, 2, 0, check_propagate_route, duthost, route, bgp_neighbor, vrf, ip_ver,
                                 ACTION_NOT_IN),
                      "Vrf:{} - route:{} is propagated to {}".format(vrf, route, bgp_neighbor))


def operate_orchagent(duthost, action=ACTION_STOP):
    """
    Stop or Continue orchagent process
    """
    if action == ACTION_STOP:
        logging.info('Suspend orchagent process to simulate a delay')
        cmd = 'sudo kill -SIGSTOP $(pidof orchagent)'
    else:
        logging.info('Recover orchagent process')
        cmd = 'sudo kill -SIGCONT $(pidof orchagent)'
    duthost.shell(cmd)
