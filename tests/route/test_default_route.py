import pytest
import ipaddress
import logging


from tests.common.storage_backend.backend_utils import skip_test_module_over_backend_topologies     # noqa F401
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
from tests.common.utilities import find_duthost_on_role
from tests.common.utilities import get_upstream_neigh_type
from tests.syslog.syslog_utils import is_mgmt_vrf_enabled


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


def get_upstream_neigh(tb, device_neigh_metadata):
    """
    Get the information for upstream neighbors present in the testbed

    returns dict: {"upstream_neigh_name" : (ipv4_intf_ip, ipv6_intf_ip)}
    """
    upstream_neighbors = {}
    neigh_type = get_upstream_neigh_type(tb['topo']['type'])
    logging.info("testbed topo {} upstream neigh type {}".format(
        tb['topo']['name'], neigh_type))

    topo_cfg_facts = tb['topo']['properties'].get('configuration', None)
    if topo_cfg_facts is None:
        return upstream_neighbors

    for neigh_name, neigh_cfg in list(topo_cfg_facts.items()):
        if neigh_type not in neigh_name:
            continue
        if neigh_type == 'T3' and device_neigh_metadata[neigh_name]['type'] == 'AZNGHub':
            continue
        interfaces = neigh_cfg.get('interfaces', {})
        ipv4_addr = None
        ipv6_addr = None
        for intf, intf_cfg in list(interfaces.items()):
            if 'Port-Channel' in intf:
                if 'ipv4' in intf_cfg:
                    ipv4_addr = interfaces[intf]['ipv4'].split('/')[0]
                if 'ipv6' in intf_cfg:
                    ipv6_addr = interfaces[intf]['ipv6'].split('/')[0]
            elif 'Ethernet' in intf:
                if 'ipv4' in intf_cfg:
                    ipv4_addr = interfaces[intf]['ipv4']
                if 'ipv6' in intf_cfg:
                    ipv6_addr = interfaces[intf]['ipv6']
            else:
                continue

        upstream_neighbors.update({neigh_name: (ipv4_addr, ipv6_addr)})
    return upstream_neighbors


def get_uplink_ns(tbinfo, bgp_name_to_ns_mapping, device_neigh_metadata):
    neigh_type = get_upstream_neigh_type(tbinfo['topo']['type'])
    asics = set()
    for name, asic in list(bgp_name_to_ns_mapping.items()):
        if neigh_type not in name:
            continue
        if neigh_type == 'T3' and device_neigh_metadata[name]['type'] == 'AZNGHub':
            continue
        asics.add(asic)
    return asics


def verify_default_route_in_app_db(duthost, tbinfo, af, uplink_ns, device_neigh_metadata):
    """
    Verify the nexthops for the default routes match the ip interfaces
    configured on the peer device
    """
    default_route = duthost.get_default_route_from_app_db(af)
    pytest_assert(default_route, "default route not present in APP_DB")
    logging.info("default route from app db {}".format(default_route))

    nexthops = set()
    if uplink_ns:
        # multi-asic case: Now we have all routes on all asics, get the uplink routes only
        for ns in uplink_ns:
            nexthop_list = list(default_route[ns].values())[
                0]['value']['nexthop'].split(',')
            nexthops.update(set(nexthop_list))
    else:
        key = list(default_route.keys())[0]
        nexthop_list = default_route[key].get('value', {}).get('nexthop', None)
        nexthops.update(set(nexthop_list.split(',')))

    pytest_assert(nexthops is not None, "Default route has not nexthops")
    logging.info("nexthops in app_db {}".format(nexthops))

    upstream_neigh = get_upstream_neigh(tbinfo, device_neigh_metadata)
    pytest_assert(upstream_neigh is not None,
                  "No upstream neighbors in the testbed")

    if af == 'ipv4':
        upstream_neigh_ip = set([upstream_neigh[neigh][0]
                                for neigh in upstream_neigh])
    elif af == 'ipv6':
        upstream_neigh_ip = set([upstream_neigh[neigh][1]
                                for neigh in upstream_neigh])

    logging.info("peer intf ip from tb {}".format(upstream_neigh_ip))
    pytest_assert(len(nexthops) == len(upstream_neigh_ip),
                  "Default route nexthops doesn't match the testbed topology")


def test_default_route_set_src(duthosts, tbinfo):
    """
    check if ipv4 and ipv6 default src address match Loopback0 address

    """
    duthost = find_duthost_on_role(
        duthosts, get_upstream_neigh_type(tbinfo['topo']['type']), tbinfo)
    asichost = duthost.asic_instance(0 if duthost.is_multi_asic else None)

    config_facts = asichost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']

    lo_ipv4 = None
    lo_ipv6 = None
    los = config_facts.get("LOOPBACK_INTERFACE", {})
    logger.info("Loopback IPs: {}".format(los))
    for k, v in list(los.items()):
        if k == "Loopback0":
            for ipstr in list(v.keys()):
                ip = ipaddress.ip_interface(ipstr)
                if ip.version == 4:
                    lo_ipv4 = ip
                elif ip.version == 6:
                    lo_ipv6 = ip

    pytest_assert(lo_ipv4, "cannot find ipv4 Loopback0 address")
    pytest_assert(lo_ipv6, "cannot find ipv6 Loopback0 address")

    rtinfo = asichost.get_ip_route_info(ipaddress.ip_network("0.0.0.0/0"))
    pytest_assert(rtinfo['set_src'],
                  "default route do not have set src. {}".format(rtinfo))
    pytest_assert(rtinfo['set_src'] == lo_ipv4.ip,
                  "default route set src to wrong IP {} != {}".format(rtinfo['set_src'], lo_ipv4.ip))

    rtinfo = asichost.get_ip_route_info(ipaddress.ip_network("::/0"))
    pytest_assert(
        rtinfo['set_src'], "default v6 route do not have set src. {}".format(rtinfo))
    pytest_assert(rtinfo['set_src'] == lo_ipv6.ip,
                  "default v6 route set src to wrong IP {} != {}".format(rtinfo['set_src'], lo_ipv6.ip))


def test_default_ipv6_route_next_hop_global_address(duthosts, tbinfo):
    """
    check if ipv6 default route nexthop address uses global address

    """
    duthost = find_duthost_on_role(
        duthosts, get_upstream_neigh_type(tbinfo['topo']['type']), tbinfo)
    asichost = duthost.asic_instance(0 if duthost.is_multi_asic else None)

    rtinfo = asichost.get_ip_route_info(ipaddress.ip_network("::/0"))
    pytest_assert(len(rtinfo['nexthops']) > 0,
                  "cannot find ipv6 nexthop for default route")
    for nh in rtinfo['nexthops']:
        pytest_assert(not nh[0].is_link_local,
                      "use link local address {} for nexthop".format(nh[0]))


def test_default_route_with_bgp_flap(duthosts, tbinfo):
    """
    Check the default route present in app_db has the correct nexthops ip
    Check the default route is removed when the bgp sessions are shutdown

    """

    pytest_require('t1-backend' not in tbinfo['topo']['name'],
                   "Skip this testcase since this topology {} has no default routes"
                   .format(tbinfo['topo']['name']))

    duthost = find_duthost_on_role(
        duthosts, get_upstream_neigh_type(tbinfo['topo']['type']), tbinfo)

    config_facts = duthost.config_facts(
        host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})

    uplink_ns = None
    # Get uplink namespaces/asics for multi-asic
    if duthost.is_multi_asic:
        bgp_name_to_ns_mapping = duthost.get_bgp_name_to_ns_mapping()
        uplink_ns = get_uplink_ns(
            tbinfo, bgp_name_to_ns_mapping, config_facts['DEVICE_NEIGHBOR_METADATA'])

    af_list = ['ipv4', 'ipv6']

    try:
        # verify the default route is correct in the app db
        for af in af_list:
            verify_default_route_in_app_db(
                duthost, tbinfo, af, uplink_ns, config_facts['DEVICE_NEIGHBOR_METADATA'])

        duthost.command("sudo config bgp shutdown all")
        if not wait_until(120, 2, 0, duthost.is_bgp_state_idle):
            pytest.fail(
                'BGP Shutdown Timeout: BGP sessions not shutdown after 120 seconds')

        # give some more time for default route to be removed
        if not wait_until(120, 2, 0, duthost.is_default_route_removed_from_app_db, uplink_ns):
            pytest.fail(
                'Default route is not removed from APP_DB')
    finally:
        duthost.command("sudo config bgp startup all")
        if not wait_until(300, 10, 0, duthost.check_bgp_session_state, list(bgp_neighbors.keys())):
            pytest.fail("not all bgp sessions are up after config reload")


def test_ipv6_default_route_table_enabled_for_mgmt_interface(duthosts, tbinfo):
    """
    check if ipv6 default route nexthop address uses global address

    """
    duthost = find_duthost_on_role(
        duthosts, get_upstream_neigh_type(tbinfo['topo']['type']), tbinfo)

    # When management-vrf enabled, IPV6 route of management interface will not add to 'default' route table
    if is_mgmt_vrf_enabled(duthost):
        logging.info("Ignore IPV6 default route table test because management-vrf enabled")
        return

    ipv6_rules = duthost.command("ip -6 rule list")["stdout"]
    pytest_assert("32767:\tfrom all lookup default" in ipv6_rules,
                  "IPV6 rules does not include default route table: {}".format(ipv6_rules))
