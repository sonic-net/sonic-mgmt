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


def test_bgp_gr_helper_routes_perserved(duthosts, rand_one_dut_hostname, nbrhosts,
                                        setup_bgp_graceful_restart, tbinfo, cct=8):
    """Verify that routes received from one neighbor are all preserved during peer graceful restart."""

    def _find_test_bgp_neighbors(test_neighbor_name, bgp_neighbors):
        """Find test BGP neighbor peers."""
        test_bgp_neighbors = []
        for bgp_neighbor, neighbor_details in list(bgp_neighbors.items()):
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
        if is_ipv4_address(bgp_neighbor.encode().decode()):
            cmd = "vtysh -c 'show bgp ipv4 neighbor %s routes json'" % bgp_neighbor
        else:
            cmd = "vtysh -c 'show bgp ipv6 neighbor %s routes json'" % bgp_neighbor
        for namespace in duthost.get_frontend_asic_namespace_list():
            cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
            routes.update(json.loads(duthost.shell(cmd, verbose=False)["stdout"])["routes"])
        return routes

    def _get_prefix_counters(duthost, bgp_neighbor, namespace):
        """Get Rib route counters for neighbor."""
        if is_ipv4_address(bgp_neighbor.encode().decode()):
            cmd = "vtysh -c 'show bgp ipv4 neighbor %s prefix-counts json'" % bgp_neighbor
        else:
            cmd = "vtysh -c 'show bgp ipv6 neighbor %s prefix-counts json'" % bgp_neighbor
        cmd = duthost.get_vtysh_cmd_for_namespace(cmd, namespace)
        cmd_result = json.loads(duthost.shell(cmd, verbose=False)["stdout"])
        return cmd_result

    def _verify_prefix_counters_from_neighbor_during_graceful_restart(duthost, bgp_neighbors):
        """Verify that all routes received from neighbor are stale during graceful restart."""
        for bgp_neighbor in bgp_neighbors:
            for namespace in duthost.get_frontend_asic_namespace_list():
                counters = _get_prefix_counters(duthost, bgp_neighbor, namespace)
                logging.debug("Prefix counters for bgp neighbor %s in namespace %s:\n%s\n",
                              bgp_neighbor, namespace, counters)
                assert counters["ribTableWalkCounters"]["Stale"] == counters["ribTableWalkCounters"]["All RIB"]

    def _verify_bgp_neighbor_routes_during_graceful_restart(neighbor_routes, rib):
        for prefix, nexthops in list(neighbor_routes.items()):
            logging.debug("Check prefix %s, nexthops:\n%s\n", prefix, json.dumps(nexthops))
            if prefix not in rib:
                pytest.fail("Route to prefix %s doesn't exist during graceful restart." % prefix)
            nexthop_expected = nexthops[0]
            bgp_neighbor_expected = nexthop_expected["peerId"]
            for nexthop in rib[prefix]:
                if nexthop["peerId"] == bgp_neighbor_expected:
                    if nexthop.get("stale", False) is False:
                        logging.error("Rib route entry to prefix %s:\n%s\n", prefix, json.dumps(rib[prefix]))
                        pytest.fail("Route to prefix %s should be stale during graceful restart." % prefix)
                    break
            else:
                logging.error("Rib route entry to prefix %s:\n%s\n", prefix, json.dumps(rib[prefix]))
                pytest.fail("Route to prefix doesn't originate from BGP neighbor %s." % bgp_neighbor_expected)

    def _verify_prefix_counters_from_neighbor_after_graceful_restart(duthost, bgp_neighbors):
        """Verify routes from neighbor are relearned and out of stale after graceful restart."""
        for bgp_neighbor in bgp_neighbors:
            for namespace in duthost.get_frontend_asic_namespace_list():
                counters = _get_prefix_counters(duthost, bgp_neighbor, namespace)
                logging.debug("Prefix counters for bgp neighbor %s in namespace %s:\n%s\n",
                              bgp_neighbor, namespace, json.dumps(counters))
                if not (counters["ribTableWalkCounters"]["Stale"] == 0 and
                        counters["ribTableWalkCounters"]["Valid"] > 0):
                    return False
        return True

    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL_MEMBER', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    configurations = tbinfo['topo']['properties']['configuration_properties']
    exabgp_ips = [configurations['common']['nhipv4'], configurations['common']['nhipv6']]
    exabgp_sessions = ['exabgp_v4', 'exabgp_v6']

    # select neighbor to test
    if duthost.check_bgp_default_route():
        # if default route is present, select from default route nexthops
        rtinfo_v4 = duthost.get_ip_route_info(ipaddress.ip_network("0.0.0.0/0"))
        rtinfo_v6 = duthost.get_ip_route_info(ipaddress.ip_network("::/0"))

        ifnames_v4 = [nh[1] for nh in rtinfo_v4['nexthops']]
        ifnames_v6 = [nh[1] for nh in rtinfo_v6['nexthops']]

        ifnames_common = [ifname for ifname in ifnames_v4 if ifname in ifnames_v6]
        if len(ifnames_common) == 0:
            pytest.skip("No common ifnames between ifnames_v4 and ifname_v6: %s and %s" % (ifnames_v4, ifnames_v6))
        test_interface = ifnames_common[0]
    else:
        # if default route is not present, randomly select a neighbor to test
        test_interface = random.sample(
            [k for k, v in list(dev_nbrs.items()) if not v['name'].startswith("Server")], 1
        )[0]

    # get neighbor device connected ports
    nbr_ports = []
    if test_interface.startswith("PortChannel"):
        for member in list(portchannels[test_interface].keys()):
            nbr_ports.append(dev_nbrs[member]['port'])
        test_neighbor_name = dev_nbrs[member]['name']
    else:
        nbr_ports.append(dev_nbrs[test_interface]['port'])
        test_neighbor_name = dev_nbrs[test_interface]['name']

    test_neighbor_host = nbrhosts[test_neighbor_name]['host']

    # get neighbor BGP peers
    test_bgp_neighbors = _find_test_bgp_neighbors(test_neighbor_name, bgp_neighbors)

    logging.info("Select neighbor %s to verify that all bgp routes are preserved during graceful restart",
                 test_neighbor_name)

    # get all routes received from neighbor before GR
    all_neighbor_routes_before_gr = {}
    for test_bgp_neighbor in test_bgp_neighbors:
        all_neighbor_routes_before_gr.update(_get_learned_bgp_routes_from_neighbor(duthost, test_bgp_neighbor))

    # verify exabgp sessions to the neighbor are up before GR process
    pytest_assert(
        test_neighbor_host.check_bgp_session_state(exabgp_ips, exabgp_sessions),
        "exabgp sessions {} are not up before graceful restart".format(exabgp_sessions)
    )

    try:
        # shutdown Rib agent, starting GR process
        logger.info("shutdown rib process on neighbor {}".format(test_neighbor_name))
        test_neighbor_host.kill_bgpd()

        # wait till DUT enters NSF state
        for test_bgp_neighbor in test_bgp_neighbors:
            pytest_assert(
                wait_until(60, 5, 0, duthost.check_bgp_session_nsf, test_bgp_neighbor),
                "neighbor {} does not enter NSF state".format(test_bgp_neighbor)
            )

        # confirm routes from the neighbor still there
        rib_after_gr = _get_rib(duthost)
        _verify_bgp_neighbor_routes_during_graceful_restart(all_neighbor_routes_before_gr, rib_after_gr)

        # confirm routes from the neighbor are in STALE state
        _verify_prefix_counters_from_neighbor_during_graceful_restart(duthost, test_bgp_neighbors)

    except Exception:
        test_neighbor_host.start_bgpd()
        raise

    try:
        # shutdown the connected ports from nbr
        logging.info("shutdown the ports connected to neighbor %s: %s", test_neighbor_name, nbr_ports)
        for nbr_port in nbr_ports:
            test_neighbor_host.shutdown(nbr_port)

        # start Rib agent
        logging.info("startup rib process on neighbor {}".format(test_neighbor_name))
        test_neighbor_host.start_bgpd()

        # wait for exabgp sessions to establish
        pytest_assert(
            wait_until(300, 10, 0, test_neighbor_host.check_bgp_session_state, exabgp_ips, exabgp_sessions),
            "exabgp sessions {} are not coming back".format(exabgp_sessions)
        )

    finally:
        # unshut the connected ports from nbr
        logging.info("unshut the ports connected to neighbor %s: %s", test_neighbor_name, nbr_ports)
        for nbr_port in nbr_ports:
            test_neighbor_host.no_shutdown(nbr_port)

    # confirm BGP session are up
    pytest_assert(
        wait_until(300, 10, 0, duthost.check_bgp_session_state, test_bgp_neighbors),
        "graceful restarted bgp sessions {} are not coming back".format(test_bgp_neighbors)
    )

    # confirm routes from the neighbor are restored
    pytest_assert(
        wait_until(300, 10, 0, _verify_prefix_counters_from_neighbor_after_graceful_restart,
                   duthost, test_bgp_neighbors),
        "after graceful restart, Rib is not restored"
    )

    # Verify no route changes in the application db
    # TODO
