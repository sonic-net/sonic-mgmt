import pytest
import logging
import ipaddress
import random
import json

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import is_ipv4_address


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

def test_bgp_gr_helper_routes_perserved(duthosts, rand_one_dut_hostname, nbrhosts, setup_bgp_graceful_restart, tbinfo):
    """
    Verify that DUT routes are preserved when peer performed graceful restart
    """
    duthost = duthosts[rand_one_dut_hostname]

    if not duthost.check_bgp_default_route():
        pytest.skip("there is no nexthop for bgp default route")

    config_facts  = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    po = config_facts.get('PORTCHANNEL', {})
    dev_nbr = config_facts.get('DEVICE_NEIGHBOR', {})

    rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network(u'0.0.0.0/0'))

    rtinfo_v6 = duthost.get_ip_route_info(ipaddress.ip_network(u'::/0'))

    ifnames_v4 = [nh[1] for nh in rtinfo_v4['nexthops']]
    ifnames_v6 = [nh[1] for nh in rtinfo_v6['nexthops']]

    logger.info("ifnames_v4: %s" % ifnames_v4)
    logger.info("ifnames_v6: %s" % ifnames_v6)

    ifnames_common = [ ifname for ifname in ifnames_v4 if ifname in ifnames_v6 ]
    if len(ifnames_common) == 0:
        pytest.skip("No common ifnames between ifnames_v4 and ifname_v6: %s and %s" % (ifnames_v4, ifnames_v6))

    ifname = ifnames_common[0]

    # get neighbor device connected ports
    nbr_ports = []
    if ifname.startswith("PortChannel"):
        for member in po[ifname]['members']:
            nbr_ports.append(dev_nbr[member]['port'])
    else:
        nbr_ports.append(dev_nbr[ifname]['port'])
    logger.info("neighbor device connected ports {}".format(nbr_ports))

    # get nexthop ip
    for nh in rtinfo_v4['nexthops']:
        if nh[1] == ifname:
            bgp_nbr_ipv4 = nh[0]

    for nh in rtinfo_v6['nexthops']:
        if nh[1] == ifname:
            bgp_nbr_ipv6 = nh[0]

    # get the bgp neighbor
    bgp_nbr = bgp_neighbors[str(bgp_nbr_ipv4)]
    nbr_hostname = bgp_nbr['name']
    nbrhost = nbrhosts[nbr_hostname]['host']
    topo = tbinfo['topo']['properties']['configuration_properties']
    exabgp_ips = [topo['common']['nhipv4'], topo['common']['nhipv6']]
    exabgp_sessions = ['exabgp_v4', 'exabgp_v6']
    pytest_assert(nbrhost.check_bgp_session_state(exabgp_ips, exabgp_sessions), \
            "exabgp sessions {} are not up before graceful restart".format(exabgp_sessions))

    # shutdown Rib agent, starting gr process
    logger.info("shutdown rib process on neighbor {}".format(nbr_hostname))
    nbrhost.kill_bgpd()

    # wait till DUT enter NSF state
    pytest_assert(wait_until(60, 5, duthost.check_bgp_session_nsf, bgp_nbr_ipv4), \
            "neighbor {} does not enter NSF state".format(bgp_nbr_ipv4))
    pytest_assert(wait_until(60, 5, duthost.check_bgp_session_nsf, bgp_nbr_ipv6), \
            "neighbor {} does not enter NSF state".format(bgp_nbr_ipv6))

    # confirm ip route still there
    rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network(u'0.0.0.0/0'))
    pytest_assert(ipaddress.ip_address(bgp_nbr_ipv4) in [ nh[0] for nh in rtinfo_v4['nexthops'] ], \
        "cannot find nexthop {} in the new default route nexthops. {}".format(bgp_nbr_ipv4, rtinfo_v4))

    rtinfo_v6 = duthost.get_ip_route_info(ipaddress.ip_network(u'::/0'))
    pytest_assert(ipaddress.ip_address(bgp_nbr_ipv6) in [ nh[0] for nh in rtinfo_v6['nexthops'] ], \
        "cannot find nexthop {} in the new default route nexthops. {}".format(bgp_nbr_ipv6, rtinfo_v6))

    # shutdown the connected ports from nbr
    for nbr_port in nbr_ports:
        nbrhost.shutdown(nbr_port)

    try:
        # start Rib agent
        logger.info("startup rib process on neighbor {}".format(nbr_hostname))
        nbrhost.start_bgpd()

        # wait for exabgp sessions to establish
        pytest_assert(wait_until(300, 10, nbrhost.check_bgp_session_state, exabgp_ips, exabgp_sessions), \
            "exabgp sessions {} are not coming back".format(exabgp_sessions))
    except:
        raise
    finally:
        # unshut the connected ports from nbr
        for nbr_port in nbr_ports:
            nbrhost.no_shutdown(nbr_port)

    # confirm bgp session up
    graceful_restarted_bgp_sessions = [str(bgp_nbr_ipv4), str(bgp_nbr_ipv6)]
    pytest_assert(wait_until(300, 10, duthost.check_bgp_session_state, graceful_restarted_bgp_sessions), \
            "graceful restarted bgp sessions {} are not coming back".format(graceful_restarted_bgp_sessions))

    # Verify no route changes in the application db
    # TODO


def test_bgp_gr_helper_all_routes_preserved(duthosts, rand_one_dut_hostname, nbrhosts, setup_bgp_graceful_restart, tbinfo):
    """Verify that routes received from one neighbor are all preserved during peer graceful restart."""

    def _find_test_bgp_neighbors(test_neighbor_name, bgp_neighbors):
        """Find test BGP neighbor peers."""
        test_bgp_neighbors = []
        for bgp_neighbor, neighbor_details in bgp_neighbors.items():
            if test_neighbor_name == neighbor_details['name']:
                test_bgp_neighbors.append(bgp_neighbor)
        return test_bgp_neighbors

    def _get_rib(duthost):
        """Return DUT rib."""
        routes = {}
        for namespace in duthost.get_frontend_asic_namespace_list():
            bgp_cmd_ipv4 = "vtysh -c \"show bgp ipv4 json\""
            bgp_cmd_ipv6 = "vtysh -c \"show bgp ipv6 json\""
            cmd = duthost.get_vtysh_cmd_for_namespace(bgp_cmd_ipv4, namespace)
            routes.update(json.loads(duthost.shell(cmd, verbose=False)['stdout'])["routes"])
            cmd = duthost.get_vtysh_cmd_for_namespace(bgp_cmd_ipv6, namespace)
            routes.update(json.loads(duthost.shell(cmd, verbose=False)['stdout'])["routes"])
        return routes

    def _get_learned_bgp_routes_from_neighbor(duthost, bgp_neighbor):
        """Get all learned routes from the BGP neighbor."""
        routes = {}
        if is_ipv4_address(unicode(bgp_neighbor)):
            cmd = "vtysh -c 'show bgp ipv4 neighbor %s routes json'" % bgp_neighbor
        else:
            cmd = "vtysh -c 'show bgp ipv6 neighbor %s routes json'" % bgp_neighbor
        for namespace in duthost.get_frontend_asic_namespace_list():
            cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
            routes.update(json.loads(duthost.shell(cmd, verbose=False)["stdout"])["routes"])
        return routes

    def _verify_prefix_counters_from_neighbor_after_graceful_restart(duthost, bgp_neighbor):
        """Verify that all routes received from neighbor are stale after graceful restart."""
        if is_ipv4_address(unicode(bgp_neighbor)):
            cmd = "vtysh -c 'show bgp ipv4 neighbor %s prefix-counts json'" % bgp_neighbor
        else:
            cmd = "vtysh -c 'show bgp ipv6 neighbor %s prefix-counts json'" % bgp_neighbor
        for namespace in duthost.get_frontend_asic_namespace_list():
            cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
            cmd_result = json.loads(duthost.shell(cmd, verbose=False)["stdout"])
            logging.debug("Prefix counters for bgp neighbor %s in namespace %s:\n%s\n", bgp_neighbor, namespace, cmd_result)
            assert cmd_result["ribTableWalkCounters"]["Stale"] == cmd_result["ribTableWalkCounters"]["All RIB"]

    def _verify_bgp_neighbor_routes_after_graceful_restart(neighbor_routes, rib):
        for prefix, nexthops in neighbor_routes.items():
            if prefix not in rib:
                pytest.fail("Route to prefix %s doesn't exist after graceful restart." % prefix)
            nexthop_expected = nexthops[0]
            bgp_neighbor_expected = nexthop_expected["peerId"]
            for nexthop in rib[prefix]:
                if nexthop["peerId"] == bgp_neighbor_expected:
                    if nexthop.get("stale", False) is False:
                        pytest.fail(
                            "Route to prefix %s should be stale after graceful restart, before: %s, after: %s" % (prefix, nexthop_expected, rib[prefix])
                        )
                    break
            else:
                pytest.fail(
                    "Route to prefix doesn't originate from BGP neighbor %s, before: %s, after: %s" % (bgp_neighbor_expected, nexthop_expected, rib[prefix])
                )

    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})

    test_interface = random.sample([k for k, v in dev_nbrs.items() if not v['name'].startswith("Server")], 1)[0]
    test_neighbor_name = dev_nbrs[test_interface]['name']
    test_neighbor_host = nbrhosts[test_neighbor_name]['host']

    # get neighbor BGP peers
    test_bgp_neighbors = _find_test_bgp_neighbors(test_neighbor_name, bgp_neighbors)

    logging.info("Select neighbor %s to verify that all bgp routes are preserved during graceful restart", test_neighbor_name)

    # get all routes received from neighbor before GR
    all_neighbor_routes_before_gr = {}
    for test_bgp_neighbor in test_bgp_neighbors:
        all_neighbor_routes_before_gr.update(_get_learned_bgp_routes_from_neighbor(duthost, test_bgp_neighbor))
    # limit testing routes to 100 entries to save time
    test_route_count = min(100, len(all_neighbor_routes_before_gr))
    neighbor_routes_before_gr = dict(random.sample(all_neighbor_routes_before_gr.items(), test_route_count))

    try:
        # shutdown Rib agent, starting GR process
        logger.info("shutdown rib process on neighbor {}".format(test_neighbor_name))
        test_neighbor_host.kill_bgpd()

        # wait till DUT enters NSF state
        for test_bgp_neighbor in test_bgp_neighbors:
            pytest_assert(
                wait_until(60, 5, duthost.check_bgp_session_nsf, test_bgp_neighbor),
                "neighbor {} does not enter NSF state".format(test_bgp_neighbor)
            )

        # confirm routes from the neighbor still there
        rib_after_gr = _get_rib(duthost)
        for test_bgp_neighbor in test_bgp_neighbors:
            _verify_prefix_counters_from_neighbor_after_graceful_restart(duthost, test_bgp_neighbor)
        _verify_bgp_neighbor_routes_after_graceful_restart(neighbor_routes_before_gr, rib_after_gr)
    finally:
        # start Rib agent
        logging.info("start rib process on neighbor %s", test_neighbor_name)
        test_neighbor_host.start_bgpd()

    if not wait_until(300, 10, duthost.check_bgp_session_state, test_bgp_neighbors):
        pytest.fail("Not all bgp sessions are up after starting BGP on neighbor %s." % test_neighbor_name)
