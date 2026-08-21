import contextlib
import os
import re
import tempfile
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
from tests.common.helpers.constants import UPSTREAM_NEIGHBOR_MAP, DOWNSTREAM_ALL_NEIGHBOR_MAP, DEFAULT_NAMESPACE
from tests.common.helpers.bgp import (
    get_db_cli_prefix,
    get_db_cli_prefix_for_namespace,
    get_asic_namespace,
    namespace_cli_arg,
)
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.helpers.parallel import reset_ansible_local_tmp
from tests.common.helpers.parallel import parallel_run
from tests.common.utilities import wait_until
from tests.common.utilities import is_ipv6_only_topology
from tests.common.utilities import testbed_is_multi_vrf
from tests.common.utilities import get_neighbor_exabgp_vm_offset
from tests.bgp.traffic_checker import get_traffic_shift_state
from tests.bgp.constants import TS_NORMAL
from tests.common.devices.eos import EosHost
from tests.common.devices.sonic import SonicHost
from tests.common.helpers.bgp import flatten_bgp_neighbors

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
BGP_MONITOR_NAME = "BGPMonitor"
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
# frr_mgmt_framework (frrcfgd) mode: file on the DUT used to stash the peer-group
# AF inbound route-maps we override, so remove_allow_list can restore them.
ALLOW_LIST_FRR_STATE_FILE = '/tmp/allow_list_frr_state.json'
DROP_COMMUNITY = ''
DEFAULT_ACTION = ''
ANNOUNCE = 'announce'
DEFAULT = "default"
IP_VER = 4
QUEUED = "queued"
EMPTY = "empty"
ACTION_IN = "in"
ACTION_NOT_IN = "not"
ACTION_STOP = "stop"
WAIT_TIMEOUT = 120
TCPDUMP_WAIT_TIMEOUT = 20
LOCAL_PCAP_FILE_TEMPLATE = "%s_dump.pcap"


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


def get_no_export_output(vm_host, ipv6=False):
    """
    Get no export routes on the VM

    Args:
        vm_host: VM host object
        ipv6: Boolean flag to check IPv6 routes
    """
    if ipv6:
        ipv6_pattern = r'[0-9a-fA-F:]+\/\d+\s+[0-9a-fA-F:]+.*'
        if isinstance(vm_host, EosHost):
            out = vm_host.eos_command(commands=['show ipv6 bgp match community no-export'])["stdout"]
            return re.findall(ipv6_pattern, out[0])
        elif isinstance(vm_host, SonicHost):
            out = vm_host.command("vtysh -c 'show ipv6 bgp community no-export'")["stdout"]
            # For SonicHost, output is already a string, no need to index
            return re.findall(ipv6_pattern, out)
        else:
            raise TypeError(f"Unsupported host type: {type(vm_host)}. Expected EosHost or SonicHost.")
    else:
        ipv4_pattern = r'\d+\.\d+.\d+.\d+\/\d+\s+\d+\.\d+.\d+.\d+.*'
        if isinstance(vm_host, EosHost):
            out = vm_host.eos_command(commands=['show ip bgp community no-export'])["stdout"]
            return re.findall(ipv4_pattern, out[0])
        elif isinstance(vm_host, SonicHost):
            out = vm_host.command("vtysh -c 'show ip bgp community no-export'")["stdout"]
            # For SonicHost, output is already a string, no need to index
            return re.findall(ipv4_pattern, out)
        else:
            raise TypeError(f"Unsupported host type: {type(vm_host)}. Expected EosHost or SonicHost.")


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


def get_routes_not_announced_to_bgpmon(duthost, ptfhost, asic_namespace=None, expected_routes=None):
    """
    Get the routes that are not announced to bgpmon by checking dump of bgpmon on PTF.
    """
    def _dump_fie_exists(host):
        return host.stat(path=DUMP_FILE).get('stat', {}).get('exists', False)
    pytest_assert(wait_until(120, 10, 0, _dump_fie_exists, ptfhost),
                  "bgpmon dump file is not found: {}".format(DUMP_FILE))

    if expected_routes is None:
        rib_v4 = parse_rib(duthost, 4, asic_namespace=asic_namespace)
        rib_v6 = parse_rib(duthost, 6, asic_namespace=asic_namespace)
        routes_to_check = list(dict(list(rib_v4.items()) + list(rib_v6.items())).keys())
    else:
        routes_to_check = expected_routes

    def _all_routes_announced():
        bgpmon_routes = parse_exabgp_dump(ptfhost)
        return all(route in bgpmon_routes for route in routes_to_check)

    wait_until(WAIT_TIMEOUT, 10, 0, _all_routes_announced)
    bgpmon_routes = parse_exabgp_dump(ptfhost)
    return [route for route in routes_to_check if route not in bgpmon_routes]


def remove_bgp_neighbors(duthost, asic_index):
    """
    Remove the bgp neigbors for a particular BGP instance
    """
    namespace_prefix = namespace_cli_arg(get_asic_namespace(duthost, asic_index))
    db_cli = get_db_cli_prefix(duthost, asic_index)

    # Convert the json formatted result of sonic-cfggen into bgp_neighbors dict
    bgp_neighbors = json.loads(duthost.command("sudo sonic-cfggen {} -d --var-json {}"
                               .format(namespace_prefix, "BGP_NEIGHBOR"))["stdout"])
    cmd = 'sudo {db_cli} CONFIG_DB keys "BGP_NEI*" | xargs {db_cli} CONFIG_DB del'.format(db_cli=db_cli)
    duthost.shell(cmd)

    # Restart BGP instance on that asic
    duthost.asic_instance(asic_index).reset_service("bgp")
    duthost.restart_service_on_asic("bgp", asic_index)
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")

    return bgp_neighbors


def restore_bgp_neighbors(duthost, asic_index, bgp_neighbors):
    """
    Restore the bgp neigbors for a particular BGP instance
    """
    namespace_prefix = namespace_cli_arg(get_asic_namespace(duthost, asic_index))

    # Convert the bgp_neighbors dict into json format after adding the table name.
    bgp_neigh_dict = {"BGP_NEIGHBOR": bgp_neighbors}
    bgp_neigh_json = json.dumps(bgp_neigh_dict)
    duthost.shell("sudo sonic-cfggen {} -a '{}' --write-to-db".format(namespace_prefix, bgp_neigh_json))

    # Restart BGP instance on that asic
    duthost.asic_instance(asic_index).reset_service("bgp")
    duthost.restart_service_on_asic("bgp", asic_index)
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "BGP not started.")


def is_neighbor_sessions_established(duthost, neighbors):
    is_established = True

    # handle both multi-asic and single-asic
    bgp_facts = duthost.bgp_facts(num_npus=duthost.sonichost.num_asics())[
        "ansible_facts"
    ]
    for neighbor in neighbors:
        is_established &= (
            neighbor.ip in bgp_facts["bgp_neighbors"]
            and bgp_facts["bgp_neighbors"][neighbor.ip]["state"] == "established"
        )

    return is_established


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
    downstream_type = [t.upper() for t in DOWNSTREAM_ALL_NEIGHBOR_MAP[tbinfo["topo"]["type"]]]
    downstream_neighbors = \
        natsorted(
            [neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith(tuple(downstream_type))])
    downstream = downstream_neighbors[0]
    upstream_neighbors = natsorted([neighbor for neighbor in list(nbrhosts.keys()) if neighbor.endswith(upstream_type)])
    other_neighbors = downstream_neighbors[1:3]    # Only check a few neighbors to save time
    if upstream_neighbors:
        other_neighbors += upstream_neighbors[0:2]

    # On converged (multi-VRF) topologies ``VMs[downstream]['vm_offset']`` is the
    # collapsed *prime* offset, which maps to a different neighbor's exabgp
    # instance. The per-neighbor exabgp instances are keyed by the ORIGINAL
    # offset, so use that (via get_neighbor_exabgp_vm_offset) to post the
    # announce to the intended downstream's exabgp. On stock topologies this
    # returns the neighbor's own vm_offset, so behavior is unchanged.
    downstream_offset = get_neighbor_exabgp_vm_offset(nbrhosts, tbinfo, downstream)
    downstream_exabgp_port = EXABGP_BASE_PORT + downstream_offset
    downstream_exabgp_port_v6 = EXABGP_BASE_PORT_V6 + downstream_offset

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    downstream_namespace = DEFAULT_NAMESPACE
    for _, neigh in list(mg_facts['minigraph_neighbors'].items()):
        if downstream == neigh['name'] and neigh['namespace']:
            downstream_namespace = neigh['namespace']
            break

    is_v6_topo = is_ipv6_only_topology(tbinfo)

    setup_info = {
        'downstream': downstream,
        'downstream_namespace': downstream_namespace,
        'downstream_exabgp_port': downstream_exabgp_port,
        'downstream_exabgp_port_v6': downstream_exabgp_port_v6,
        'other_neighbors': other_neighbors,
        'is_v6_topo': is_v6_topo,
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
    r = requests.post(url, data=data, proxies={"http": None, "https": None})
    assert r.status_code == 200


def build_routes(tbinfo, prefix_list, expected_community):
    nhipv4 = tbinfo['topo']['properties']['configuration_properties']['common'].get('nhipv4')
    nhipv6 = tbinfo['topo']['properties']['configuration_properties']['common'].get('nhipv6')
    routes = []
    for list_name, prefixes in list(prefix_list.items()):
        logging.info('list_name: {}, prefixes: {}'.format(list_name, str(prefixes)))
        for prefix in prefixes:
            route = {}
            route['prefix'] = prefix
            if ipaddress.IPNetwork(prefix).version == 4:
                nhip = nhipv4
            else:
                nhip = nhipv6
            if not nhip:
                continue
            route['nexthop'] = nhip
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
    nbrhosts[downstream]['host'].config(lines=cmds, parents='router bgp {}'.format(downstream_asn))

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
    nbrhosts[downstream]['host'].config(lines=no_cmds, parents='router bgp {}'.format(downstream_asn))


# --------------------------------------------------------------------------- #
# BGP allow-list -- traditional (bgpcfgd) vs frr_mgmt_framework (frrcfgd)
#
# In traditional mode bgpcfgd owns the BGP_ALLOWED_PREFIXES convenience table and
# decomposes it into FRR prefix-lists, community-lists and a per-deployment
# route-map (see sonic-bgpcfgd/bgpcfgd/managers_allow_list.py). frrcfgd does NOT
# consume BGP_ALLOWED_PREFIXES, so in frr mode we reproduce exactly the FRR state
# bgpcfgd would render, but through frrcfgd's own CONFIG_DB schema.
#
# For one BGP_ALLOWED_PREFIXES entry, e.g.::
#
#   "DEPLOYMENT_ID|0|1010:1010": {prefixes_v4: ["172.16.30.0/24"],
#                                 prefixes_v6: ["2000:172:16:30::/64"],
#                                 default_action: "permit"}
#
# we write (mirroring bgpcfgd's names/seqs):
#
#   PREFIX_SET|PL_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_1010:1010_V4  {mode: IPv4}
#   PREFIX|PL_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_1010:1010_V4|10|172.16.30.0/24|exact
#                                                                   {action: permit}
#   COMMUNITY_SET|COMMUNITY_ALLOW_LIST_DEPLOYMENT_ID_0_COMMUNITY_1010:1010
#           {set_type: standard, match_action: all, community_member: [1010:1010],
#            action: permit}   -> "bgp community-list standard <name> permit 1010:1010"
#   ROUTE_MAP|ALLOW_LIST_DEPLOYMENT_ID_0_V4|10
#           {route_operation: permit, match_prefix_set: <PL>, match_community: <CL>}
#   ROUTE_MAP|ALLOW_LIST_DEPLOYMENT_ID_0_V4|30000   (no-community deployment entry)
#           {route_operation: permit, match_prefix_set: PL_..._empty_V4}
#   ROUTE_MAP|ALLOW_LIST_DEPLOYMENT_ID_0_V4|65535   (default rule)
#           {route_operation: permit,
#            set_community_inline: [<drop_community|no-export>, additive]}
#              -> "set community <c> additive"
#
# route_operation/seq -> "route-map <NAME> permit <seq>" (frrcfgd.py);
# match_prefix_set -> "match ip[v6] address prefix-list" with the af resolved from
# the referenced PREFIX_SET (frrcfgd.py); match_community -> "match community"; and
# set_community_inline (a space-joined list, so a trailing 'additive' element renders
# as "set community <c> additive") (frrcfgd.py).
#
# The route-map is attached inbound by overwriting route_map_in on every
# BGP_PEER_GROUP_AF that already has an inbound route-map (nbr_af_key_map
# route_map_in, frrcfgd.py) -- this replaces the peer-group's stock inbound
# map with our allow-list map for the duration of the test; the originals are
# stashed and restored by remove_allow_list. bgpcfgd instead wires the map in via
# a `call` from the stock inbound map; overwriting route_map_in is the frr-schema
# way to reach the same inbound filtering without editing the stock map's clauses.
# Default seq 65535 tags every not-explicitly-allowed prefix: with
# default_action=permit that is the drop_community (routes still forwarded but
# marked); with default_action=deny it is no-export (routes not re-advertised to
# eBGP neighbors) -- matching bgpcfgd's __get_default_action_community.
# --------------------------------------------------------------------------- #
def _allow_list_as_prefix_list(value):
    """Return the prefixes as a list, accepting either a python list or a
    comma-separated string (both shapes appear in BGP_ALLOWED_PREFIXES data).
    Entries are whitespace-stripped, so a value written as "a, b" does not produce a
    prefix with a leading space that no prefix-list would ever match."""
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = str(value).split(',')
    return [str(p).strip() for p in items if str(p).strip()]


def _get_allow_list_constants(duthost):
    """Read the whole constants.bgp.allow_list section from the DUT (once)."""
    constants = yaml.safe_load(duthost.shell('cat {}'.format(CONSTANTS_FILE))['stdout'])
    return constants.get('constants', {}).get('bgp', {}).get('allow_list', {}) or {}


def _get_allow_list_drop_community(duthost):
    """Read the allow-list drop_community from constants.yml on the DUT."""
    if DROP_COMMUNITY:
        return DROP_COMMUNITY
    return _get_allow_list_constants(duthost)['drop_community']


def _allow_list_default_pl_rules(al_constants, ver):
    """The ``default_pl_rules`` bgpcfgd prepends to EVERY generated allow-list
    prefix-list (BGPAllowListMgr.__load_constant_lists / __update_prefix_list).

    These are the guards, not decoration: the v4 set is
    ``deny 0.0.0.0/0 le 17`` + ``permit 127.0.0.1/32``, and the v6 set denies
    ``0::/0 le 59`` and ``0::/0 ge 65``. Omitting them made a configured /17-or-shorter
    prefix reachable and lost the loopback exception, so the frr-mode policy was strictly
    more permissive than the bgpcfgd one it is supposed to reproduce.
    """
    rules = al_constants.get('default_pl_rules') or {}
    return list(rules.get('v{}'.format(ver)) or [])


def _allow_list_prefix_rules(prefixes, ver):
    """Convert allow-list prefixes into bgpcfgd's prefix-list rule strings
    (BGPAllowListMgr.__to_prefix_list): a prefix that already carries ge/le is passed
    through, a host prefix is an exact permit, and anything shorter permits more-specifics
    up to the family's host length."""
    host_len = 32 if ver == '4' else 128
    rules = []
    for prefix in prefixes:
        if 'le' in prefix or 'ge' in prefix:
            rules.append('permit {}'.format(prefix))
            continue
        try:
            masklen = int(prefix.split('/')[1])
        except (IndexError, ValueError):
            rules.append('permit {}'.format(prefix))
            continue
        if masklen == host_len:
            rules.append('permit {}'.format(prefix))
        else:
            rules.append('permit {} le {}'.format(prefix, host_len))
    return rules


def _frr_prefix_key_parts(rule, ver):
    """Parse a bgpcfgd prefix-list rule ('deny 0.0.0.0/0 le 17') into the frrcfgd PREFIX
    row's (action, ip_prefix, masklength_range).

    masklength_range follows frrcfgd's own encoding: 'ge..le', 'ge..<host-len>',
    '<prefix-len>..le', or 'exact' when neither bound is present."""
    parts = rule.split()
    action, prefix = parts[0], parts[1]
    host_len = '32' if ver == '4' else '128'
    ge = parts[parts.index('ge') + 1] if 'ge' in parts else None
    le = parts[parts.index('le') + 1] if 'le' in parts else None
    plen = prefix.split('/')[1] if '/' in prefix else host_len
    if ge and le:
        mask_range = '{}..{}'.format(ge, le)
    elif ge:
        mask_range = '{}..{}'.format(ge, host_len)
    elif le:
        mask_range = '{}..{}'.format(plen, le)
    else:
        mask_range = 'exact'
    return action, prefix, mask_range


def _parse_allow_list_key(raw_key):
    """Split a BGP_ALLOWED_PREFIXES key into (deployment_id, community, neighbor_type).

    BGPAllowListMgr.set_handler accepts four forms, and the naming templates differ by
    whether a neighbor type is present::

        DEPLOYMENT_ID|<id>                                    -> community 'empty', no neighbor
        DEPLOYMENT_ID|<id>|<community>                        -> community only
        DEPLOYMENT_ID|<id>|NEIGHBOR_TYPE|<type>               -> neighbor only, community 'empty'
        DEPLOYMENT_ID|<id>|NEIGHBOR_TYPE|<type>|<community>   -> both

    Taking ``key.split('|')[2]`` as the community handled only the first two, and read the
    literal token 'NEIGHBOR_TYPE' as the community for the other two.
    """
    if not raw_key.startswith('DEPLOYMENT_ID|'):
        raise ValueError("Unsupported BGP_ALLOWED_PREFIXES key {!r}: expected it to start "
                         "with 'DEPLOYMENT_ID|'".format(raw_key))
    if '|NEIGHBOR_TYPE|' in raw_key:
        head, tail = raw_key.split('|NEIGHBOR_TYPE|', 1)
        deployment_id = head[len('DEPLOYMENT_ID|'):]
        neighbor_type, community = tail.split('|', 1) if '|' in tail else (tail, None)
    else:
        rest = raw_key[len('DEPLOYMENT_ID|'):]
        deployment_id, community = rest.split('|', 1) if '|' in rest else (rest, None)
        neighbor_type = None
    if not deployment_id.isdigit():
        raise ValueError("Unsupported BGP_ALLOWED_PREFIXES key {!r}: {!r} is not a numeric "
                         "deployment id".format(raw_key, deployment_id))
    return deployment_id, community, neighbor_type


def _allow_list_names(deployment_id, community, neighbor_type, ver):
    """The prefix-list / community-list / route-map names bgpcfgd would generate for this
    entry (BGPAllowListMgr's *_TMPL constants). The _WITH_NEIGH templates insert
    ``NEIGHBOR_<type>`` and are what makes a neighbor-type entry a distinct policy rather
    than a collision with the plain one."""
    comm_token = community if community else 'empty'
    if neighbor_type:
        return (
            'PL_ALLOW_LIST_DEPLOYMENT_ID_{}_NEIGHBOR_{}_COMMUNITY_{}_V{}'.format(
                deployment_id, neighbor_type, comm_token, ver),
            'COMMUNITY_ALLOW_LIST_DEPLOYMENT_ID_{}_NEIGHBOR_{}_COMMUNITY_{}'.format(
                deployment_id, neighbor_type, comm_token),
            'ALLOW_LIST_DEPLOYMENT_ID_{}_NEIGHBOR_{}_V{}'.format(
                deployment_id, neighbor_type, ver),
        )
    return (
        'PL_ALLOW_LIST_DEPLOYMENT_ID_{}_COMMUNITY_{}_V{}'.format(
            deployment_id, comm_token, ver),
        'COMMUNITY_ALLOW_LIST_DEPLOYMENT_ID_{}_COMMUNITY_{}'.format(
            deployment_id, comm_token),
        'ALLOW_LIST_DEPLOYMENT_ID_{}_V{}'.format(deployment_id, ver),
    )


def _build_allow_list_frr_config(allow_list, drop_community, al_constants):
    """Translate the test's BGP_ALLOWED_PREFIXES dict into the frrcfgd-native
    CONFIG_DB tables. Returns (tables, rms_by_af, created_keys).

    * tables       -- {table: {key: value}} to feed to sonic-cfggen -w
    * rms_by_af    -- {'ipv4_unicast': {<rm name>, ...}, 'ipv6_unicast': {...}} -- every
                      generated route-map for that address family. A set, not one name:
                      the input may carry several deployment ids / neighbor types, and
                      keeping a single slot per AF silently dropped all but the last.
    * created_keys -- [(table, key), ...] written by this helper
    """
    tables = {'PREFIX_SET': {}, 'PREFIX': {}, 'COMMUNITY_SET': {}, 'ROUTE_MAP': {}}
    created_keys = []
    rms_by_af = {'ipv4_unicast': set(), 'ipv6_unicast': set()}

    def add(table, key, value):
        tables[table][key] = value
        created_keys.append((table, key))

    # Group entries by the (deployment_id, neighbor_type) policy they belong to; each
    # policy gets one V4 + one V6 route-map, exactly as bgpcfgd names them.
    policies = {}
    for raw_key, data in list(allow_list.get('BGP_ALLOWED_PREFIXES', {}).items()):
        deployment_id, community, neighbor_type = _parse_allow_list_key(raw_key)
        policies.setdefault((deployment_id, neighbor_type), []).append((community, data))

    for (deployment_id, neighbor_type), entries in list(policies.items()):
        default_action = ''
        for af, ver, plist_key in (('ipv4', '4', 'prefixes_v4'), ('ipv6', '6', 'prefixes_v6')):
            _, _, rm_name = _allow_list_names(deployment_id, None, neighbor_type, ver)
            rms_by_af['{}_unicast'.format(af)].add(rm_name)
            # Community entries get seq 10.. (bgpcfgd 10..29990); no-community
            # deployment entries get seq 30000.. (bgpcfgd 30000..65530).
            cur_with = 10
            cur_without = 30000
            for community, data in entries:
                default_action = data.get('default_action', '') or default_action
                prefixes = _allow_list_as_prefix_list(data.get(plist_key))
                if not prefixes:
                    continue
                pl_name, cl_name, _ = _allow_list_names(
                    deployment_id, community, neighbor_type, ver)
                add('PREFIX_SET', pl_name, {'mode': 'IPv4' if af == 'ipv4' else 'IPv6'})
                # bgpcfgd renders constants' default_pl_rules FIRST, then the allow-list
                # prefixes, numbering the combined list from seq 10 in steps of 10.
                pl_seq = 10
                rules = (_allow_list_default_pl_rules(al_constants, ver)
                         + _allow_list_prefix_rules(prefixes, ver))
                for rule in rules:
                    action, prefix, mask_range = _frr_prefix_key_parts(rule, ver)
                    add('PREFIX', '{}|{}|{}|{}'.format(pl_name, pl_seq, prefix, mask_range),
                        {'action': action})
                    pl_seq += 10
                rm_entry = {'route_operation': 'permit', 'match_prefix_set': pl_name}
                if community:
                    add('COMMUNITY_SET', cl_name,
                        {'set_type': 'standard', 'match_action': 'all',
                         'community_member': [community], 'action': 'permit'})
                    rm_entry['match_community'] = cl_name
                    rm_seq = cur_with
                    cur_with += 10
                else:
                    rm_seq = cur_without
                    cur_without += 10
                add('ROUTE_MAP', '{}|{}'.format(rm_name, rm_seq), rm_entry)
            # Default rule (seq 65535): tag everything not explicitly allowed.
            drop = 'no-export' if default_action == 'deny' else drop_community
            add('ROUTE_MAP', '{}|65535'.format(rm_name),
                {'route_operation': 'permit', 'set_community_inline': [drop, 'additive']})

    return tables, rms_by_af, created_keys


def _config_db_json(duthost, namespace):
    """The DUT's whole running CONFIG_DB as a dict (one call, real JSON)."""
    return json.loads(duthost.shell(
        'sonic-cfggen {} -d --print-data'.format(namespace_cli_arg(namespace)))['stdout'])


def _route_map_calls(config_db, rm_name):
    """Every ``call_route_map`` target across the statements of route-map ``rm_name``."""
    calls = set()
    for key, row in list(config_db.get('ROUTE_MAP', {}).items()):
        if key.split('|')[0] != rm_name:
            continue
        called = row.get('call_route_map')
        if called:
            calls.add(called)
    return calls


def _get_af_route_maps_in(config_db, table):
    """Return {AF_key: (afi_safi, member, [current route_map_in])} for every entry
    of ``table`` (BGP_PEER_GROUP_AF or BGP_NEIGHBOR_AF) that has an inbound
    route-map. ``AF_key`` is the INNER key (``default|PEER_V4|ipv4_unicast``), not the
    full Redis key -- it is used both as a sonic-cfggen table key and, re-prefixed with
    the table name, for the direct CONFIG_DB writes in teardown. ``member`` is the
    peer-group name / neighbor IP, used to target the ``clear bgp ... soft in``
    re-evaluation."""
    result = {}
    for key, row in list(config_db.get(table, {}).items()):
        fields = key.split('|')
        if len(fields) < 3:
            continue
        member, afi_safi = fields[1], fields[2]
        rin = row.get('route_map_in')
        if not rin:
            continue
        if not isinstance(rin, list):
            rin = [r for r in str(rin).split(',') if r]
        result[key] = (afi_safi, member, rin)
    return result


def _apply_allow_list_frr(duthost, namespace, allow_list, allow_list_file_path):
    """frr_mgmt_framework path for apply_allow_list (see comment block above)."""
    al_constants = _get_allow_list_constants(duthost)
    drop_community = DROP_COMMUNITY or al_constants['drop_community']
    tables, rms_by_af, created_keys = _build_allow_list_frr_config(
        allow_list, drop_community, al_constants)

    config_db = _config_db_json(duthost, namespace)

    # Attach the allow-list route-map inbound on every inbound-filtered peer-group
    # AND neighbor AF (a neighbor-level route-map overrides the peer-group one in
    # FRR, and the frr migrator sets route_map_in at both levels, so we must cover
    # both), stashing the originals so remove_allow_list can restore them.
    #
    # Targeted, not blanket: an AF row is rewritten only when its current inbound
    # route-map CALLS the allow-list map generated for this policy -- the same linkage
    # bgpcfgd uses to decide which peer-groups a deployment id owns
    # (BGPAllowListMgr.__get_peer_group_to_restart). Overwriting every non-empty
    # route_map_in instead would replace inbound policy that has nothing to do with the
    # allow-list under test, and with more than one generated map there is no defensible
    # way to pick which one to attach.
    stash = {}
    peer_groups = set()
    neighbors = set()
    for table, targets in (('BGP_PEER_GROUP_AF', peer_groups),
                           ('BGP_NEIGHBOR_AF', neighbors)):
        for key, (afi_safi, member, original_in) in list(
                _get_af_route_maps_in(config_db, table).items()):
            candidates = rms_by_af.get(afi_safi) or set()
            called = set()
            for rm in original_in:
                called |= _route_map_calls(config_db, rm)
            matched = sorted(candidates & called)
            if not matched:
                continue
            stash['{}|{}'.format(table, key)] = original_in
            tables.setdefault(table, {})[key] = {'route_map_in': [matched[0]]}
            targets.add(member)

    pytest_assert(
        stash,
        "No BGP_PEER_GROUP_AF/BGP_NEIGHBOR_AF row has an inbound route-map that calls any of "
        "the generated allow-list route-maps {}. Attaching the allow-list to unrelated "
        "inbound policy instead would test something else, so this fails rather than "
        "guessing.".format(sorted(set().union(*rms_by_af.values())) if rms_by_af else []))

    # Rows this helper is about to overwrite that ALREADY existed (the mode-switch
    # translator creates the stock allow-list route-map statements, for instance). Their
    # original contents are stashed so teardown restores them instead of deleting them.
    pre_existing = {}
    for table, key in created_keys:
        row = config_db.get(table, {}).get(key)
        if row is not None:
            pre_existing['{}|{}'.format(table, key)] = row

    # Write the decomposed frr tables (and the route_map_in overrides) in one shot.
    duthost.copy(content=json.dumps(tables, indent=3), dest=allow_list_file_path)
    duthost.shell('sonic-cfggen {} -j {} -w'.format(namespace_cli_arg(namespace), allow_list_file_path))
    # Persist the teardown state (originals + the keys we created) on the DUT.
    duthost.copy(content=json.dumps({'stash': stash, 'created_keys': created_keys,
                                     'pre_existing': pre_existing}, indent=3),
                 dest=ALLOW_LIST_FRR_STATE_FILE)
    time.sleep(3)

    # Re-evaluate already-received routes so the new inbound policy takes effect on
    # live sessions (mirrors bgpcfgd's restart_peer_groups: clear ... soft in).
    for pg in sorted(peer_groups):
        duthost.shell('sudo vtysh -c "clear bgp peer-group {} soft in"'.format(pg),
                      module_ignore_errors=True)
    for nbr in sorted(neighbors):
        duthost.shell('sudo vtysh -c "clear bgp {} soft in"'.format(nbr),
                      module_ignore_errors=True)
    time.sleep(3)


def _remove_allow_list_frr(duthost, namespace):
    """frr_mgmt_framework path for remove_allow_list: restore the overridden
    peer-group inbound route-maps and delete the frr tables we created."""
    db_cli = get_db_cli_prefix_for_namespace(namespace)
    state_raw = duthost.shell('cat {}'.format(ALLOW_LIST_FRR_STATE_FILE),
                              module_ignore_errors=True)
    if state_raw.get('rc', 1) != 0:
        return
    state = json.loads(state_raw['stdout'])
    stash = state.get('stash', {})
    created_keys = state.get('created_keys', [])
    pre_existing = state.get('pre_existing', {})

    # Restore route_map_in first so peers no longer reference the allow-list map.
    peer_groups = set()
    neighbors = set()
    for key, original_in in list(stash.items()):
        table = key.split('|')[0]
        member = key.split('|')[2]
        (peer_groups if table == 'BGP_PEER_GROUP_AF' else neighbors).add(member)
        if original_in:
            duthost.shell("{} CONFIG_DB HSET \"{}\" \"route_map_in@\" \"{}\"".format(
                db_cli, key, ','.join(original_in)))
        else:
            duthost.shell('{} CONFIG_DB HDEL "{}" "route_map_in@"'.format(db_cli, key),
                          module_ignore_errors=True)

    # Delete the created tables. Order: ROUTE_MAP entries first (they reference the
    # prefix-/community-lists), then PREFIX/PREFIX_SET, then COMMUNITY_SET.
    order = {'ROUTE_MAP': 0, 'PREFIX': 1, 'PREFIX_SET': 2, 'COMMUNITY_SET': 3}
    for table, key in sorted(created_keys, key=lambda tk: order.get(tk[0], 9)):
        duthost.shell('{} CONFIG_DB del "{}|{}"'.format(db_cli, table, key),
                      module_ignore_errors=True)

    # ... then put back the rows that already existed and were overwritten rather than
    # created -- the mode-switch translator renders the stock allow-list route-map
    # statements, so deleting every key this helper wrote left the DUT missing config it
    # arrived with. Delete-then-rewrite (not a merge) so a field the test added does not
    # survive into the restored row.
    if pre_existing:
        restore = {}
        for full_key, row in list(pre_existing.items()):
            table, key = full_key.split('|', 1)
            restore.setdefault(table, {})[key] = row
        restore_file = ALLOW_LIST_FRR_STATE_FILE + '.restore'
        duthost.copy(content=json.dumps(restore, indent=3), dest=restore_file)
        duthost.shell('sonic-cfggen {} -j {} -w'.format(
            namespace_cli_arg(namespace), restore_file))
        duthost.shell('rm -rf {}'.format(restore_file), module_ignore_errors=True)

    duthost.shell('rm -rf {}'.format(ALLOW_LIST_FRR_STATE_FILE), module_ignore_errors=True)
    time.sleep(3)
    for pg in sorted(peer_groups):
        duthost.shell('sudo vtysh -c "clear bgp peer-group {} soft in"'.format(pg),
                      module_ignore_errors=True)
    for nbr in sorted(neighbors):
        duthost.shell('sudo vtysh -c "clear bgp {} soft in"'.format(nbr),
                      module_ignore_errors=True)
    time.sleep(3)


def apply_allow_list(duthost, namespace, allow_list, allow_list_file_path):
    if duthost.get_frr_mgmt_framework_config():
        _apply_allow_list_frr(duthost, namespace, allow_list, allow_list_file_path)
        return
    duthost.copy(content=json.dumps(allow_list, indent=3), dest=allow_list_file_path)
    duthost.shell('sonic-cfggen {} -j {} -w'.format(namespace_cli_arg(namespace), allow_list_file_path))
    time.sleep(3)


def remove_allow_list(duthost, namespace, allow_list_file_path):
    if duthost.get_frr_mgmt_framework_config():
        _remove_allow_list_frr(duthost, namespace)
        duthost.shell('rm -rf {}'.format(allow_list_file_path), module_ignore_errors=True)
        return
    db_cli = get_db_cli_prefix_for_namespace(namespace)
    allow_list_keys = duthost.shell(
        '{} CONFIG_DB keys "BGP_ALLOWED_PREFIXES*"'.format(db_cli)
    )['stdout_lines']
    for key in allow_list_keys:
        duthost.shell('{} CONFIG_DB del "{}"'.format(db_cli, key))

    duthost.shell('rm -rf {}'.format(allow_list_file_path))


def check_routes_on_from_neighbor(setup_info, nbrhosts):
    """
    Verify if there are routes on neighbor who announce them.
    """
    downstream = setup_info['downstream']
    for list_name, prefixes in list(PREFIX_LISTS.items()):
        if setup_info['is_v6_topo'] and "v6" not in list_name.lower():
            continue
        for prefix in prefixes:
            vrf = downstream if nbrhosts[downstream].get('is_multi_vrf_peer', False) else 'default'
            downstream_route = nbrhosts[downstream]['host'].get_route(prefix, vrf=vrf)
            route_entries = downstream_route['vrfs'][vrf]['bgpRouteEntries']
            pytest_assert(prefix in route_entries, 'Announced route {} not found on {}'.format(prefix, downstream))


def check_results(results):
    pytest_assert(len(list(results.keys())) > 0, 'No result on neighbors')
    failed_results = {}
    for node, node_prefix_results in list(results.items()):
        failed_results[node] = [r for r in node_prefix_results if r['failed']]

    pytest_assert(all([len(r) == 0 for r in list(failed_results.values())]),
                  'Unexpected routes on neighbors, failed_results={}'.format(json.dumps(failed_results, indent=2)))


def check_routes_presence(result, prefix):
    # Filter the route output
    matched_lines = [line for line in result["stdout"].splitlines() if prefix in line]

    if matched_lines:
        logging.info("Found prefix {} in BGP received-routes: {}".format(prefix, matched_lines))
    else:
        logging.warning("Prefix {} not found in BGP received-routes".format(prefix))


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
            if setup['is_v6_topo'] and "v6" not in list_name.lower():
                continue
            for prefix in prefixes:
                prefix_result = {'failed': False, 'prefix': prefix, 'reasons': []}
                vrf = node if nbrhosts[node].get('is_multi_vrf_peer', False) else 'default'
                neigh_route = nbrhosts[node]['host'].get_route(prefix, vrf=vrf)['vrfs'][vrf]['bgpRouteEntries']

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
            if setup['is_v6_topo'] and "v6" not in list_name.lower():
                continue
            for prefix in prefixes:
                prefix_result = {'failed': False, 'prefix': prefix, 'reasons': []}
                vrf = node if nbrhosts[node].get('is_multi_vrf_peer', False) else 'default'
                neigh_route = nbrhosts[node]['host'].get_route(prefix, vrf=vrf)['vrfs'][vrf]['bgpRouteEntries']

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


def checkout_bgp_mon_routes(duthost, ptfhost, asic_namespace=None, expected_routes=None):
    routes_not_announced = get_routes_not_announced_to_bgpmon(
        duthost, ptfhost, asic_namespace=asic_namespace, expected_routes=expected_routes
    )
    pytest_assert(routes_not_announced == [], "Not all routes are announced to bgpmon: {}".format(routes_not_announced))


def get_default_action():
    """
    Since the value of this constant has been changed in the helper, it cannot be directly imported
    """
    return DEFAULT_ACTION


def restart_bgp_session(duthost, neighbor=None, asic_namespace=None):
    """
    Restart bgp session. If neighbor is specified, only restart that specific neighbor's session.
    Otherwise restart all BGP sessions.

    Args:
        duthost: DUT host object
        neighbor (str, optional): BGP neighbor IP address. If None, restarts all sessions.
    """
    if neighbor:
        logging.info(f"Restart BGP session with neighbor {neighbor}")
        bgp_neigh_cmd = f'vtysh -c "clear bgp {neighbor}"'
        cmd = duthost.get_vtysh_cmd_for_namespace(bgp_neigh_cmd, asic_namespace)
        duthost.shell(cmd)
    else:
        if asic_namespace:
            asic_list = [asic_namespace]
        else:
            asic_list = duthost.get_frontend_asic_namespace_list()
        logging.info("Restart all BGP sessions")
        bgp_cmd = "vtysh -c 'clear bgp *'"
        for namespace in asic_list:
            cmd = duthost.get_vtysh_cmd_for_namespace(bgp_cmd, namespace)
            duthost.shell(cmd)


def get_ptf_recv_port(duthost, vm_name, tbinfo, multi_vrf_topo=False):
    """
    Get ptf receive port
    """
    if multi_vrf_topo:
        # When using multi-vrf topologies, the vm_name alone is not unique enough to be used as an
        # index into the lldp table.  In this scenario, only the host container is listed by name,
        # with multiple interfaces. So, in order to get the right dut interface, we need to figure
        # out which host and interface are being used for the passed peer.  The POSIX string for
        # whitespace is used to avoid python escaping backslashes in the pattern.
        vrf_data = tbinfo["topo"]["properties"]["convergence_data"]
        host_map = {vrf: host for host, vrfs in vrf_data["convergence_mapping"].items() for vrf in vrfs}
        host = host_map[vm_name]
        peer_config = vrf_data["converged_peers"][host]["vrf"][vm_name]
        host_if = [k for k in peer_config.keys() if "Ethernet" in k][0]
        pattern = "{}[[:space:]]*{}".format(host, host_if)
    else:
        pattern = vm_name

    ports_output = duthost.shell("show lldp table | grep -w {} | awk '{{print $1}}'".format(pattern))['stdout']
    ports = [line.strip() for line in ports_output.split('\n') if line.strip()]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    return [mg_facts['minigraph_ptf_indices'][port] for port in ports]


def get_eth_port(duthost, tbinfo):
    """
    Get ethernet port that connects to DOWNSTREAM VM
    """
    ds_type = [dt.upper() for dt in DOWNSTREAM_ALL_NEIGHBOR_MAP[tbinfo["topo"]["type"]]]
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    vm = [vm_name for vm_name in mg_facts['minigraph_devices'].keys() if vm_name.endswith(tuple(ds_type))][0]
    if is_ipv6_only_topology(tbinfo):
        port = duthost.shell("show ipv6 interface | grep -w {} | awk '{{print $1}}'".format(vm))['stdout']
    else:
        port = duthost.shell("show ip interface | grep -w {} | awk '{{print $1}}'".format(vm))['stdout']

    return port


def get_vm_offset(duthost, nbrhosts, tbinfo, is_random=True):
    """
    Get ports offset of exabgp and ptf receive port
    """
    multi_vrf_topo = tbinfo["topo"]["properties"].get("topo_is_multi_vrf", False)
    ds_type = [dt.upper() for dt in DOWNSTREAM_ALL_NEIGHBOR_MAP[tbinfo["topo"]["type"]]]
    port_offset_ptf_recv_port_list = []
    vm_name_list = [vm_name for vm_name in nbrhosts.keys() if vm_name.endswith(tuple(ds_type))]
    logging.info("get_vm_offset ---------")
    if is_random:
        vm_name_list = [random.choice(vm_name_list)]
    for vm_name in vm_name_list:
        if multi_vrf_topo:
            port_offset = tbinfo['topo']['properties']['convergence_data']['vm_offset_mapping'][vm_name]
        else:
            port_offset = tbinfo['topo']['properties']['topology']['VMs'][vm_name]['vm_offset']
        ptf_recv_port = get_ptf_recv_port(duthost, vm_name, tbinfo, multi_vrf_topo=multi_vrf_topo)
        logging.info("vm_offset of {} is: {}".format(vm_name, port_offset))
        port_offset_ptf_recv_port_list.append((port_offset, ptf_recv_port))
    return port_offset_ptf_recv_port_list


def get_exabgp_port(duthost, nbrhosts, tbinfo, exabgp_base_port, is_random=True):
    """
    Get exabgp port and ptf receive port
    """
    port_offset_ptf_recv_port_list = get_vm_offset(duthost, nbrhosts, tbinfo, is_random)
    port_offset_list, ptf_recv_port_list = zip(*port_offset_ptf_recv_port_list)
    return [_ + exabgp_base_port for _ in port_offset_list], ptf_recv_port_list


def get_vm_name_list(tbinfo, vm_level='T2'):
    """
    Get vm name, default return value would be T2 VM name
    """
    vm_name_list = []
    if testbed_is_multi_vrf(tbinfo):
        vms = list(tbinfo['topo']['properties']['configuration'].keys())
    else:
        vms = list(tbinfo['topo']['properties']['topology']['VMs'].keys())
    for vm in vms:
        if vm[-2:] == vm_level:
            vm_name_list.append(vm)
    return vm_name_list


def get_upstream_ptf_intfs(mg_facts, tbinfo):
    """
    Get ptf interface list that connect with T2 VMs
    """
    upstream_type = UPSTREAM_NEIGHBOR_MAP[tbinfo["topo"]["type"]].upper()
    upstream_ethernets = []
    for k, v in mg_facts["minigraph_neighbors"].items():
        if v['name'][-2:] == upstream_type:
            upstream_ethernets.append(k)

    ptf_interfaces = []
    for port in upstream_ethernets:
        ptf_interfaces.append(mg_facts['minigraph_ptf_indices'][port])
    return ptf_interfaces


def get_eth_name_from_ptf_port(mg_facts, ptf_ports):
    """
    Get eth name from ptf port
    """
    eth_name_list = []
    for k, v in mg_facts["minigraph_ptf_indices"].items():
        for port in ptf_ports:
            if v == port:
                eth_name_list.append(k)
    return eth_name_list


def get_bgp_neighbor_ip(duthost, vm_name, vrf=DEFAULT):
    """
    Get ipv4 and ipv6 bgp neighbor ip addresses
    """
    if vrf == DEFAULT:
        cmd_v4 = "show ip interface | grep -w {} | awk '{{print $2}}'"
        cmd_v6 = "show ipv6 interface | grep -w {} | awk '{{print $2}}'"
        bgp_neighbor_ip = duthost.shell(cmd_v4.format(vm_name))['stdout'].split('/')[0]
        bgp_neighbor_ipv6 = duthost.shell(cmd_v6.format(vm_name))['stdout'].split('/')[0]
    else:
        cmd_v4 = "show ip interface | grep -w {} | awk '{{print $3}}'"
        cmd_v6 = "show ipv6 interface | grep -w {} | awk '{{print $3}}'"
        bgp_neighbor_ip = duthost.shell(cmd_v4.format(vm_name))['stdout'].split('/')[0]
        bgp_neighbor_ipv6 = duthost.shell(cmd_v6.format(vm_name))['stdout'].split('/')[0]
    logging.info("BGP neighbor of {} is {}".format(vm_name, bgp_neighbor_ip))
    logging.info("IPv6 BGP neighbor of {} is {}".format(vm_name, bgp_neighbor_ipv6))

    return bgp_neighbor_ip, bgp_neighbor_ipv6


def get_vrf_route_json(duthost, route, vrf=DEFAULT, ip_ver=IP_VER, asic_namespace=None):
    """
    Get output of 'show ip route vrf xxx xxx json' or 'show ipv6 route vrf xxx xxx json'
    """
    if ip_ver == IP_VER:
        route_cmd = 'vtysh -c "show ip route vrf {} {} json"'
    else:
        route_cmd = 'vtysh -c "show ipv6 route vrf {} {} json"'
    cmd = duthost.get_vtysh_cmd_for_namespace(route_cmd, asic_namespace)
    logging.info('Execute command - ' + str(cmd.format(vrf, route)))
    out = json.loads(duthost.shell(cmd.format(vrf, route), verbose=False)['stdout'])
    logging.info('Command output:\n {}'.format(out))
    return out


def check_route_status(duthost, route, check_field, vrf=DEFAULT, ip_ver=IP_VER, expect_status=True,
                       asic_namespace=None):
    """
    Get 'offloaded' or 'queu' value of specific route
    """
    out = get_vrf_route_json(duthost, route, vrf, ip_ver, asic_namespace)
    if not out:
        if check_field == EMPTY:
            return False is expect_status
        else:
            return False
    check_field_status = out[route][0].get(check_field, None)
    if check_field_status:
        logging.info("Route:{} - {} status:{} - expect status:{}"
                     .format(route, check_field, check_field_status, expect_status))
        return True is expect_status
    else:
        logging.info("No {} value found in route:{}".format(check_field, out))
        return False is expect_status


def check_route_install_status(duthost, route, vrf=DEFAULT, ip_ver=IP_VER, check_point=QUEUED, action=ACTION_IN,
                               asic_namespace=None):
    """
    Verify route install status
    """
    if check_point == QUEUED:
        if action == ACTION_IN:
            pytest_assert(wait_until(120, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver,
                                     asic_namespace=asic_namespace),
                          "Vrf:{} - route:{} is not in {} state".format(vrf, route, check_point))
        else:
            pytest_assert(wait_until(120, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver, False,
                                     asic_namespace=asic_namespace),
                          "Vrf:{} - route:{} is in {} state".format(vrf, route, check_point))
    else:
        if action == ACTION_IN:
            pytest_assert(wait_until(60, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver,
                                     asic_namespace=asic_namespace),
                          "Vrf:{} - route:{} is not installed into FIB".format(vrf, route))
        else:
            pytest_assert(wait_until(60, 2, 0, check_route_status, duthost, route, check_point, vrf, ip_ver, False,
                                     asic_namespace=asic_namespace),
                          "Vrf:{} - route:{} is installed into FIB".format(vrf, route))


def check_propagate_route(vmhost, route_list, bgp_neighbor, ip_ver=IP_VER, action=ACTION_IN, vrf=DEFAULT):
    """
    Check whether ipv4 or ipv6 route is advertised to T2 VM
    """
    vrf = DEFAULT
    if vmhost.get('is_multi_vrf_peer', False):
        vrf = vmhost['multi_vrf_data']['vrf']

    if ip_ver == IP_VER:
        logging.info('Execute EOS command - "show ip bgp neighbors {} routes vrf {}"'.format(bgp_neighbor, vrf))
        if isinstance(vmhost['host'], EosHost):
            out = vmhost['host'].eos_command(
                commands=['show ip bgp neighbors {} routes vrf {}'.format(bgp_neighbor, vrf)])['stdout'][0]
        elif isinstance(vmhost['host'], SonicHost):
            out = vmhost['host'].shell('show ip bgp vrf {} neighbor {} routes'.format(vrf, bgp_neighbor),
                                       module_ignore_errors=True)['stdout']
    else:
        logging.info('Execute EOS command - "show ipv6 bgp peers {} routes vrf {}"'.format(bgp_neighbor, vrf))
        if isinstance(vmhost['host'], EosHost):
            out = vmhost['host'].eos_command(
                commands=['show ipv6 bgp peers {} routes vrf {}'.format(bgp_neighbor, vrf)])['stdout'][0]
        elif isinstance(vmhost['host'], SonicHost):
            out = vmhost['host'].shell('show ipv6 bgp vrf {} neighbor {} routes'.format(vrf, bgp_neighbor),
                                       module_ignore_errors=True)['stdout']
    logging.debug('Command output:\n {}'.format(out))

    if action == ACTION_IN:
        for route in route_list:
            if route in out:
                logging.debug("Route:{} found - action:{}".format(route, action))
            else:
                logging.info("Route:{} not found - action:{}".format(route, action))
                return False
    else:
        for route in route_list:
            if route in out:
                logging.info("Route:{} found - action:{}".format(route, action))
                return False
            else:
                logging.debug("Route:{} not found - action:{}".format(route, action))
    return True


def validate_route_propagate_status(vmhost, route_list, bgp_neighbor, vrf=DEFAULT, ip_ver=IP_VER, exist=True):
    """
    Verify ipv4 or ipv6 route propagate status
    :param vmhost: vm host object
    :param route_list: ipv4 or ipv6 route list
    :param bgp_neighbor: ipv4 or ipv6 bgp neighbor address
    :param vrf: vrf name
    :param ip_ver: ip version number
    :param exist: route expected status
    """
    if exist:
        pytest_assert(wait_until(30, 2, 0, check_propagate_route, vmhost, route_list, bgp_neighbor, ip_ver),
                      "Vrf:{} - route:{} is not propagated to Upstream VM {}".format(vrf, route_list, vmhost))
    else:
        pytest_assert(
            wait_until(30, 2, 0, check_propagate_route, vmhost, route_list, bgp_neighbor, ip_ver, ACTION_NOT_IN),
            "Vrf:{} - route:{} is propagated to Upstream VM {}".format(vrf, route_list, vmhost))


def check_fib_route(duthost, route_list, ip_ver=IP_VER):
    """
    Verify ipv4 or ipv6 routes are installed into fib
    """
    fib_type = 'ip' if ip_ver == IP_VER else 'ipv6'
    cmd = "show {} fib".format(fib_type)
    out = ""
    for asichost in duthost.asics:
        asic_cmd = "{} {}".format(asichost.ns_arg, cmd)
        out = out + " " + asichost.shell(asic_cmd)['stdout']

    for route in route_list:
        if route in out:
            logging.debug(f"Route:{route} installed into fib")
        else:
            logging.info(f"Route:{route} not found in fib")
            assert False
    logging.info(f"{route_list} are installed into fib successfully")


def operate_orchagent(duthost, action=ACTION_STOP):
    """
    Stop or Continue orchagent process
    """
    if action == ACTION_STOP:
        logging.info('Suspend orchagent process to simulate a delay')
        cmd = 'sudo kill -SIGSTOP $(pgrep -x orchagent)'
    else:
        logging.info('Recover orchagent process')
        cmd = 'sudo kill -SIGCONT $(pgrep -x orchagent)'
    duthost.shell(cmd)


def check_bgp_neighbor(duthost):
    """
    Validate all the bgp neighbors are established
    """
    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = flatten_bgp_neighbors(config_facts.get('BGP_NEIGHBOR', {}))
    pytest_assert(
        wait_until(300, 10, 0, duthost.check_bgp_session_state, bgp_neighbors),
        "bgp sessions {} are not up".format(bgp_neighbors)
    )


def is_tcpdump_running(duthost, cmd):
    check_cmd = "ps u -C tcpdump | grep '%s'" % cmd
    if cmd in duthost.shell(check_cmd)["stdout"]:
        return True
    return False


@contextlib.contextmanager
def capture_bgp_packages_to_file(duthost, iface, save_path, ns):
    """Capture bgp packets to file."""
    if iface == "any":
        # Scapy doesn't support LINUX_SLL2 (Linux cooked v2), and tcpdump on Bullseye
        # defaults to writing in that format when listening on any interface. Therefore,
        # have it use LINUX_SLL (Linux cooked) instead.
        start_pcap = "tcpdump -y LINUX_SLL -i %s -w %s port 179" % (iface, save_path)
    else:
        start_pcap = "tcpdump -i %s -w %s port 179" % (iface, save_path)
    # for multi-asic dut, add 'ip netns exec asicx' to the beggining of tcpdump cmd
    stop_pcap = "sudo pkill -f '%s%s'" % (
        duthost.asic_instance_from_namespace(ns).ns_arg,
        start_pcap,
    )
    start_pcap_cmd = "nohup {}{} &".format(
        duthost.asic_instance_from_namespace(ns).ns_arg, start_pcap
    )

    duthost.file(path=save_path, state="absent")

    duthost.shell(start_pcap_cmd)
    # wait until tcpdump process created
    if not wait_until(
        WAIT_TIMEOUT,
        5,
        1,
        lambda: is_tcpdump_running(duthost, start_pcap),
    ):
        pytest.fail("Could not start tcpdump")
    # sleep and wait for tcpdump ready to sniff packets
    time.sleep(TCPDUMP_WAIT_TIMEOUT)

    try:
        yield
    finally:
        duthost.shell(stop_pcap, module_ignore_errors=True)


def fetch_and_delete_pcap_file(bgp_pcap, log_dir, duthost, request):
    if log_dir:
        local_pcap_filename = os.path.join(
            log_dir, LOCAL_PCAP_FILE_TEMPLATE % request.node.name
        )
    else:
        local_pcap_file = tempfile.NamedTemporaryFile(delete=False)
        local_pcap_filename = local_pcap_file.name
    duthost.fetch(src=bgp_pcap, dest=local_pcap_filename, flat=True)
    duthost.file(path=bgp_pcap, state="absent")
    return local_pcap_filename


def get_tsa_chassisdb_config(duthost):
    """
    @summary: Returns the dut's CHASSIS_APP_DB value for BGP_DEVICE_GLOBAL.STATE.tsa_enabled flag
    """
    tsa_conf = duthost.shell('sonic-db-cli CHASSIS_APP_DB HGET \'BGP_DEVICE_GLOBAL|STATE\' tsa_enabled')['stdout']
    return tsa_conf


def get_sup_cfggen_tsa_value(suphost):
    """
    @summary: Returns the supervisor sonic-cfggen value for BGP_DEVICE_GLOBAL.STATE.tsa_enabled flag
    """
    tsa_conf = suphost.shell('sonic-cfggen -d -v BGP_DEVICE_GLOBAL.STATE.tsa_enabled')['stdout']
    return tsa_conf


def verify_dut_configdb_tsa_value(duthost):
    """
    @summary: Returns the line cards' asic CONFIG_DB value for BGP_DEVICE_GLOBAL.STATE.tsa_enabled flag
    """
    tsa_config = list()
    tsa_enabled = False
    for asic_index in duthost.get_frontend_asic_ids():
        db_cli = get_db_cli_prefix(duthost, asic_index)
        output = duthost.shell(
            "{} CONFIG_DB HGET 'BGP_DEVICE_GLOBAL|STATE' 'tsa_enabled'".format(db_cli)
        )['stdout']
        tsa_config.append(output)
    if 'true' in tsa_config:
        tsa_enabled = True

    return tsa_enabled


def initial_tsa_check_before_and_after_test(duthosts):
    """
    @summary: Common method to make sure the supervisor and line cards are in normal state before and after the test
    """
    for duthost in duthosts:
        if duthost.is_supervisor_node():
            # Initially make sure both supervisor and line cards are in BGP operational normal state
            if get_tsa_chassisdb_config(duthost) != 'false' or get_sup_cfggen_tsa_value(duthost) != 'false':
                duthost.shell('TSB')
                duthost.shell('sudo config save -y')
                pytest_assert('false' == get_tsa_chassisdb_config(duthost),
                              "Supervisor {} tsa_enabled config is enabled".format(duthost.hostname))

    def run_tsb_on_linecard_and_verify(lc):
        is_chassis = not lc.dut_basic_facts()['ansible_facts']['dut_basic_facts'].get("is_chassis_config_absent")
        if verify_dut_configdb_tsa_value(lc) is not False or \
                (is_chassis and get_tsa_chassisdb_config(lc) != 'false') or \
                get_traffic_shift_state(lc, cmd='TSC no-stats') != TS_NORMAL:
            lc.shell('TSB')
            lc.shell('sudo config save -y')
            # Ensure that the DUT is not in maintenance already before start of the test
            pytest_assert(wait_until(30, 5, 0, lambda: TS_NORMAL == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in normal state")

    # Issue TSB on the line card before proceeding further
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(run_tsb_on_linecard_and_verify, linecard)


def eos_bgp_neighbor_config_parents(tbinfo, nbrhosts, logical_neighbor_name, neigh_remote_as):
    """
    Parents list for ansible eos_config under neighbor BGP (default or multi-VRF / converged cEOS).

    Prefer nbrhosts[logical]['is_multi_vrf_peer'] from conftest; if absent, derive from
    topo_is_multi_vrf + convergence_data (covers stale tbinfo/nbrhosts cache mismatches).
    """
    nbr = nbrhosts.get(logical_neighbor_name) or {}
    if nbr.get("is_multi_vrf_peer") and nbr.get("multi_vrf_data"):
        mvd = nbr["multi_vrf_data"]
        return [
            "router bgp {}".format(mvd["primary_host_asn"]),
            "vrf {}".format(mvd["vrf"]),
        ]

    props = tbinfo.get("topo", {}).get("properties", {})
    if props.get("topo_is_multi_vrf") and props.get("convergence_data", {}).get("convergence_mapping"):
        conv_map = props["convergence_data"]["convergence_mapping"]
        cfg = props.get("configuration", {})
        for prime_name, logical_names in conv_map.items():
            if logical_neighbor_name in logical_names and prime_name in cfg:
                primary_asn = cfg[prime_name]["bgp"]["asn"]
                return ["router bgp {}".format(primary_asn), "vrf {}".format(logical_neighbor_name)]

    return ["router bgp {}".format(neigh_remote_as)]
