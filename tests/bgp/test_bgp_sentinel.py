import re
import json
import time
import pytest
import logging
import ipaddress
from jinja2 import Template
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import (
    wait_until,
    wait_tcp_connection,
    get_upstream_neigh_type,
    is_ipv6_only_topology,
)
from bgp_helpers import BGPSENTINEL_CONFIG_FILE
from bgp_helpers import BGP_SENTINEL_PORT_V4, BGP_SENTINEL_NAME_V4
from bgp_helpers import BGP_SENTINEL_PORT_V6, BGP_SENTINEL_NAME_V6
from bgp_helpers import BGPMON_TEMPLATE_FILE, BGPMON_CONFIG_FILE, BGP_MONITOR_NAME
from tests.common.helpers.generators import generate_ip_through_default_route
from netaddr import IPNetwork


pytestmark = [
    pytest.mark.topology('t1'),
    pytest.mark.device_type('vs'),
]

BGP_SENTINEL_TMPL = '''\
{
    "BGP_SENTINELS": {
        "BGPSentinel": {
            "ip_range": {{ v4_listen_range }},
            "name": "BGPSentinel",
            "src_address": "{{ v4_src_address }}"
        },
        "BGPSentinelV6": {
            "ip_range": {{ v6_listen_range }},
            "name": "BGPSentinelV6",
            "src_address": "{{ v6_src_address }}"
        }
    }
}'''

BGP_SENTINEL_V6_ONLY_TMPL = '''\
{
    "BGP_SENTINELS": {
        "BGPSentinelV6": {
            "ip_range": {{ v6_listen_range }},
            "name": "BGPSentinelV6",
            "src_address": "{{ v6_src_address }}"
        }
    }
}'''


logger = logging.getLogger(__name__)


def is_bgp_sentinel_supported(duthost):
    """ Get bgp sentinel config that contains src_address and ip_range

    Sample output in t1:
    ['\n neighbor BGPSentinel peer-group,
     '\n neighbor BGPSentinel remote-as 65100,
     '\n neighbor BGPSentinel update-source 10.1.0.32,
     '\n neighbor BGPSentinelV6 peer-group,
     '\n neighbor BGPSentinelV6 remote-as 65100,
     '\n neighbor BGPSentinelV6 update-source fc00:1::32,
     '\n bgp listen range 100.1.0.0/24 peer-group BGPSentinel,
     '\n bgp listen range 2064:100::/59 peer-group BGPSentinelV6']
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # As long as BGPSentinel exist in the output, it means bgp sentinel is supported
    bgp_sentinel_pattern = r"\s+neighbor BGPSentinel\s+"
    return False if re.search(bgp_sentinel_pattern, output['stdout']) is None else True


def is_bgp_monv6_supported(duthost):
    """ Get bgp monv6 config that contains src_address and ip_range

    Sample output in t1:
    ['\n neighbor BGPMON_V6 peer-group,
     '\n neighbor BGPMON_V6 passive,
     '\n neighbor fc00:1::32 peer-group BGPMON_V6,
     '\n neighbor BGPMON_V6 activate,
     '\n neighbor BGPMON_V6 addpath-tx-all-paths,
     '\n neighbor BGPMON_V6 soft-reconfiguration inbound,
     '\n neighbor BGPMON_V6 route-map FROM_BGPMON_V6 in,
     '\n neighbor BGPMON_V6 route-map TO_BGPMON_V6 out,]
    """
    cmds = "show runningconfiguration bgp"
    output = duthost.shell(cmds)
    pytest_assert(not output['rc'], "'{}' failed with rc={}".format(cmds, output['rc']))

    # As long as BGPMON_V6 exist in the output, it means BGPMON_V6 is supported
    bgp_sentinel_pattern = r"\s+neighbor BGPMON_V6\s+"
    return False if re.search(bgp_sentinel_pattern, output['stdout']) is None else True


def get_dut_listen_range(tbinfo):
    # Find spine route and get the bp_interface's network
    ipv4_subnet, ipv6_subnet = None, None
    spine_bp_addr = {}
    upstream_nbr_type = get_upstream_neigh_type(tbinfo, is_upper=True)
    is_ipv6_only = is_ipv6_only_topology(tbinfo)

    for k, v in tbinfo['topo']['properties']['configuration'].items():
        if ((upstream_nbr_type == 'T0' and 'tor' in v['properties']) or
                (upstream_nbr_type == 'T2' and 'spine' in v['properties'])):
            bp_if = v['bp_interface']
            if not is_ipv6_only:
                ipv4_addr = ipaddress.ip_interface(bp_if['ipv4'].encode().decode())
                ipv4_subnet = str(ipv4_addr.network)
            ipv6_addr = ipaddress.ip_interface(bp_if['ipv6'].encode().decode())
            ipv6_subnet = str(ipv6_addr.network)
            spine_bp_addr[k] = {}
            if not is_ipv6_only:
                spine_bp_addr[k]['ipv4'] = str(ipv4_addr.ip)
            spine_bp_addr[k]['ipv6'] = str(ipv6_addr.ip)

    return ipv4_subnet, ipv6_subnet, spine_bp_addr


def is_bgp_sentinel_session_established(duthost, ibgp_sessions):
    bgp_facts = duthost.bgp_facts()['ansible_facts']
    if set(ibgp_sessions) <= set(bgp_facts['bgp_neighbors'].keys()):
        for nbr in ibgp_sessions:
            if bgp_facts['bgp_neighbors'][nbr]['state'] != 'established':
                return False
        return True
    return False


def add_route_to_dut_lo(ptfhost, spine_bp_addr, lo_ipv4_addr, lo_ipv6_addr, is_ipv6_only=False, ptf_bp_v6=None):
    ipv4_nh, ipv6_nh = None, None
    for _, v in spine_bp_addr.items():
        # Add ptf route to dut lo address
        if not is_ipv6_only and ipv4_nh is None:
            ptfhost.shell("ip route add {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            time.sleep(5)
            ipv4_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv4_addr), module_ignore_errors=True)
            if ipv4_res['rc'] != 0:
                ptfhost.shell("ip route del {} via {}".format(lo_ipv4_addr, v['ipv4']), module_ignore_errors=True)
            else:
                ipv4_nh = v['ipv4']

        if ipv6_nh is None:
            if is_ipv6_only:
                gateway = v['ipv6']
                ptfhost.shell(
                    "ip -6 route add {}/128 via {}".format(lo_ipv6_addr, gateway),
                    module_ignore_errors=True,
                )
                time.sleep(5)
                ipv6_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv6_addr), module_ignore_errors=True)
                if ipv6_res['rc'] != 0:
                    ptfhost.shell(
                        "ip -6 route del {}/128 via {}".format(lo_ipv6_addr, gateway),
                        module_ignore_errors=True,
                    )
                else:
                    ipv6_nh = v['ipv6']
            else:
                ptfhost.shell("ip route add {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
                time.sleep(5)
                ipv6_res = ptfhost.shell("ping {} -c 3 -I backplane".format(lo_ipv6_addr), module_ignore_errors=True)
                if ipv6_res['rc'] != 0:
                    ptfhost.shell("ip route del {} via {}".format(lo_ipv6_addr, v['ipv6']), module_ignore_errors=True)
                else:
                    ipv6_nh = v['ipv6']

    return ipv4_nh, ipv6_nh


@pytest.fixture(scope="module")
def dut_lo_addr(rand_selected_dut):
    duthost = rand_selected_dut
    lo_facts = duthost.setup()['ansible_facts']['ansible_Loopback0']
    lo_ipv4_addr = lo_facts.get('ipv4', {}).get('address')
    lo_ipv6_addr = None
    for item in lo_facts.get('ipv6', []):
        if item['address'].startswith('fe80'):
            continue
        lo_ipv6_addr = item['address']
        break
    return lo_ipv4_addr, lo_ipv6_addr


def cleanup_leftovers_bgp_config(duthost, tbinfo, ptf_bp_v6):
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinel'", asic_index='all')
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinelV6'", asic_index='all')
    duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(ptf_bp_v6), asic_index='all')


@pytest.fixture(scope="module", params=['BGPSentinel', 'BGPMonV6'])
def dut_setup_teardown(rand_selected_dut, tbinfo, dut_lo_addr, request):
    duthost = rand_selected_dut
    lo_ipv4_addr, lo_ipv6_addr = dut_lo_addr
    ipv4_subnet, ipv6_subnet, spine_bp_addr = get_dut_listen_range(tbinfo)
    is_ipv6_only = is_ipv6_only_topology(tbinfo)
    ptf_bp_v6 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv6'].lower()

    cleanup_leftovers_bgp_config(duthost, tbinfo, ptf_bp_v6)

    if is_ipv6_only:
        ptf_bp_v4 = generate_ip_through_default_route(duthost)
        ptf_bp_v4 = str(IPNetwork(ptf_bp_v4).ip)
    else:
        ptf_bp_v4 = tbinfo['topo']['properties']['configuration_properties']['common']['nhipv4']

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    if request.param == 'BGPSentinel':
        # render template and write to DB, check running configuration for BGP_sentinel
        if is_ipv6_only:
            bgp_sentinel_tmpl = Template(BGP_SENTINEL_V6_ONLY_TMPL)
            duthost.copy(
                content=bgp_sentinel_tmpl.render(
                    v6_listen_range=json.dumps([ipv6_subnet, ptf_bp_v6 + '/128']),
                    v6_src_address=lo_ipv6_addr,
                ),
                dest=BGPSENTINEL_CONFIG_FILE,
            )
        else:
            bgp_sentinel_tmpl = Template(BGP_SENTINEL_TMPL)
            duthost.copy(
                content=bgp_sentinel_tmpl.render(
                    v4_listen_range=json.dumps([ipv4_subnet, ptf_bp_v4 + '/32']),
                    v4_src_address=lo_ipv4_addr,
                    v6_listen_range=json.dumps([ipv6_subnet, ptf_bp_v6 + '/128']),
                    v6_src_address=lo_ipv6_addr,
                ),
                dest=BGPSENTINEL_CONFIG_FILE,
            )

        duthost.shell("sonic-cfggen -j {} -w".format(BGPSENTINEL_CONFIG_FILE))

    elif request.param == 'BGPMonV6':
        # render template and write to DB, check running configuration for BGPMonV6
        bgpmon_args = {
            'db_table_name': 'BGP_MONITORS',
            'peer_addr': ptf_bp_v6,
            'asn': dut_asn,
            'local_addr': "fc00:1::32",
            'peer_name': BGP_MONITOR_NAME,
        }
        bgpmon_template = Template(open(BGPMON_TEMPLATE_FILE).read())
        duthost.copy(content=bgpmon_template.render(**bgpmon_args), dest=BGPMON_CONFIG_FILE)
        duthost.shell("sonic-cfggen -j {} -w".format(BGPMON_CONFIG_FILE))

    duthost.shell("vtysh -c \"configure terminal\" -c \"ipv6 nht resolve-via-default\"")

    yield lo_ipv4_addr, lo_ipv6_addr, spine_bp_addr, ptf_bp_v4, ptf_bp_v6, request.param

    if request.param == 'BGPSentinel':
        # Cleanup bgp sentinel configuration
        duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinel'", asic_index='all')
        duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_SENTINELS|BGPSentinelV6'", asic_index='all')
        duthost.file(path=BGPSENTINEL_CONFIG_FILE, state='absent')
    elif request.param == 'BGPMonV6':
        # Cleanup bgp monitorV6 configuration
        duthost.run_sonic_db_cli_cmd("CONFIG_DB del 'BGP_MONITORS|{}'".format(ptf_bp_v6), asic_index='all')
        duthost.file(path=BGPMON_CONFIG_FILE, state='absent')


def cleanup_leftovers_exbgp_instances(ptfhost, is_ipv6_only):
    if not is_ipv6_only:
        ptfhost.exabgp(name=BGP_SENTINEL_NAME_V4, state="absent")
    ptfhost.exabgp(name=BGP_SENTINEL_NAME_V6, state="absent")


@pytest.fixture(scope="module")
def ptf_setup_teardown(dut_setup_teardown, rand_selected_dut, ptfhost, tbinfo):
    duthost = rand_selected_dut
    lo_ipv4_addr, lo_ipv6_addr, spine_bp_addr, ptf_bp_v4, ptf_bp_v6, case_type = dut_setup_teardown
    is_ipv6_only = is_ipv6_only_topology(tbinfo)

    if not is_ipv6_only:
        if case_type == 'BGPSentinel':
            if not is_bgp_sentinel_supported(duthost):
                pytest.skip("BGP sentinel is not supported on this image")
        elif case_type == 'BGPMonV6':
            if not is_bgp_monv6_supported(duthost):
                pytest.skip("BGPMonV6 is not supported on this image")

    dut_asn = tbinfo['topo']['properties']['configuration_properties']['common']['dut_asn']

    cleanup_leftovers_exbgp_instances(ptfhost, is_ipv6_only)

    # Start exabgp process to simulate bgp sentinel
    if not is_ipv6_only:
        ptfhost.exabgp(
            name=BGP_SENTINEL_NAME_V4,
            state="started",
            local_ip=ptf_bp_v4,
            router_id=ptf_bp_v4,
            peer_ip=lo_ipv4_addr,
            local_asn=dut_asn,
            peer_asn=dut_asn,
            port=BGP_SENTINEL_PORT_V4,
        )

        if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_SENTINEL_PORT_V4, timeout_s=60):
            raise RuntimeError("Failed to start BGPSentinel neighbor %s" % lo_ipv4_addr)

    ptfhost.exabgp(
        name=BGP_SENTINEL_NAME_V6,
        state="started",
        local_ip=ptf_bp_v6,
        router_id=ptf_bp_v4,
        peer_ip=lo_ipv6_addr,
        local_asn=dut_asn,
        peer_asn=dut_asn,
        port=BGP_SENTINEL_PORT_V6,
    )

    if not wait_tcp_connection(ptfhost, ptfhost.mgmt_ip, BGP_SENTINEL_PORT_V6, timeout_s=60):
        raise RuntimeError("Failed to start BGPSentinelV6 neighbor %s" % lo_ipv6_addr)

    ipv4_nh, ipv6_nh = add_route_to_dut_lo(
        ptfhost, spine_bp_addr, lo_ipv4_addr, lo_ipv6_addr, is_ipv6_only, ptf_bp_v6
    )
    if case_type == 'BGPMonV6':
        ipv4_nh = None

    yield lo_ipv4_addr, lo_ipv6_addr, ipv4_nh, ipv6_nh, ptf_bp_v4, ptf_bp_v6

    # Remove ptf route to dut lo address
    if ipv4_nh is not None:
        ptfhost.shell("ip route del {} via {}".format(lo_ipv4_addr, ipv4_nh), module_ignore_errors=True)
    if ipv6_nh is not None:
        if is_ipv6_only:
            ptfhost.shell("ip -6 route del {}/128".format(lo_ipv6_addr), module_ignore_errors=True)
        else:
            ptfhost.shell("ip route del {} via {}".format(lo_ipv6_addr, ipv6_nh), module_ignore_errors=True)

    cleanup_leftovers_exbgp_instances(ptfhost, is_ipv6_only)


@pytest.fixture(scope="module")
def common_setup_teardown(rand_selected_dut, ptf_setup_teardown, ptfhost, tbinfo):
    ptfip = ptfhost.mgmt_ip
    duthost = rand_selected_dut
    is_ipv6_only = is_ipv6_only_topology(tbinfo)
    logger.info("ptfip=%s" % ptfip)

    lo_ipv4_addr, lo_ipv6_addr, ipv4_nh, ipv6_nh, ptf_bp_v4, ptf_bp_v6 = ptf_setup_teardown

    if is_ipv6_only:
        if ipv6_nh is None:
            pytest.skip("Failed to add IPv6 route to dut lo address")
    else:
        if ipv4_nh is None and ipv6_nh is None:
            pytest.skip("Failed to add route to dut lo address")

    ibgp_sessions = []
    if ipv4_nh is not None:
        ibgp_sessions.append(ptf_bp_v4)
    if ipv6_nh is not None:
        ibgp_sessions.append(ptf_bp_v6)

    # wait for bgp sentinel and dut to establish ibgp session
    pytest_assert(wait_until(30, 5, 5, is_bgp_sentinel_session_established, duthost, ibgp_sessions),
                  "BGP Sentinel session has not setup successfully")

    yield ptfip, lo_ipv4_addr, lo_ipv6_addr, ipv4_nh, ipv6_nh, ibgp_sessions, ptf_bp_v4, ptf_bp_v6


def check_routes_advertised_to_ibgp_peers(duthost, ibgp_sessions, is_ipv6_only=False):
    """Check if the DUT advertises V4/V6 routes to the sentinel/monitor sessions."""
    def _is_advertised_route_count_valid(address_family, peer, advertised):
        summary_cmd = "vtysh -c 'show bgp {} unicast summary json'".format(address_family)
        bgp_summary = json.loads(duthost.shell(summary_cmd)["stdout"])
        pfx_snt = max([peer_info.get("pfxSnt", 0)
                       for peer_info in bgp_summary.get("peers", {}).values()] or [0])

        if pfx_snt > 0:
            is_valid = len(advertised) / float(pfx_snt) > 0.5
            if not is_valid:
                logger.debug("Sentinel peer %s got %d/%d %s routes, expected majority",
                             peer, len(advertised), pfx_snt, address_family)
            return is_valid

        is_valid = len(advertised) > 0
        if not is_valid:
            logger.debug("No %s routes advertised to peer %s", address_family, peer)
        return is_valid

    for peer in ibgp_sessions:
        peer_addr = ipaddress.ip_address(peer.encode().decode())
        if peer_addr.version == 4 and not is_ipv6_only:
            cmd = "vtysh -c 'show bgp ipv4 neighbors {} advertised-routes json'".format(peer)
            output = json.loads(duthost.shell(cmd)['stdout'])
            advertised = output.get('advertisedRoutes', {})
            logger.debug("IPv4 advertised routes to %s: %d", peer, len(advertised))
            if not _is_advertised_route_count_valid("ipv4", peer, advertised):
                return False

        if peer_addr.version == 6:
            cmd = "vtysh -c 'show bgp ipv6 neighbors {} advertised-routes json'".format(peer)
            output = json.loads(duthost.shell(cmd)['stdout'])
            advertised = output.get('advertisedRoutes', {})
            logger.debug("IPv6 advertised routes to %s: %d", peer, len(advertised))
            if not _is_advertised_route_count_valid("ipv6", peer, advertised):
                return False

    return True


@pytest.mark.parametrize("reset_type", ["soft", "hard"])
def test_bgp_sentinel(rand_selected_dut, common_setup_teardown, reset_type, tbinfo):
    duthost = rand_selected_dut
    # TODO: common_setup_teardown may be over-providing values for this test; trim fixture output if safe.
    _, _, _, _, _, ibgp_sessions, _, _ = common_setup_teardown
    is_ipv6_only = is_ipv6_only_topology(tbinfo)

    # Check routes are advertised to iBGP peers before any reset
    pytest_assert(check_routes_advertised_to_ibgp_peers(duthost, ibgp_sessions, is_ipv6_only),
                  "Routes not advertised before {} reset".format(reset_type))

    for ibgp_nbr in ibgp_sessions:
        if reset_type == "soft":
            cmd = "vtysh -c 'clear bgp {} soft'".format(ibgp_nbr)
        elif reset_type == "hard":
            cmd = "vtysh -c 'clear bgp {}'".format(ibgp_nbr)
        duthost.shell(cmd)

    # Wait for bgp sentinel and dut to re-establish ibgp session
    pytest_assert(wait_until(30, 5, 5, is_bgp_sentinel_session_established, duthost, ibgp_sessions),
                  "BGP Sentinel session has not setup successfully after {} reset".format(reset_type))

    # Check routes are still advertised to iBGP peers after reset
    pytest_assert(wait_until(30, 5, 5, check_routes_advertised_to_ibgp_peers,
                             duthost, ibgp_sessions, is_ipv6_only),
                  "Routes not advertised after {} reset".format(reset_type))
