import pytest
import logging
import ipaddress
import random
import json

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.utilities import is_ipv4_address
from tests.common.utilities import is_ipv6_only_topology
from tests.common.devices.csonic import CsonicHost


pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs'),
    pytest.mark.disable_memory_utilization
]

logger = logging.getLogger(__name__)


def get_csonic_prime_peer_names(nbrhosts, selected_neighbor):
    """Return logical peers sharing the selected converged cSONiC daemon."""
    selected_host = nbrhosts[selected_neighbor]['host']
    if not isinstance(selected_host, CsonicHost) or not selected_host.bgp_vrf:
        return [selected_neighbor]
    return sorted(
        name for name, neighbor in nbrhosts.items()
        if isinstance(neighbor.get('host'), CsonicHost)
        and neighbor['host'].container_name == selected_host.container_name
    )


def verify_shared_prime_routes_during_graceful_restart(
        prime_neighbor_routes, rib, prime_bgp_neighbors):
    """Verify prefix preservation for a shared-daemon GR disruption.

    Equivalent ECMP paths learned from several logical peers can be compacted in
    the global BGP RIB while every per-neighbor accepted-route counter remains
    stale. Require every prefix learned from the prime to retain at least one
    stale prime path; the caller separately checks each logical peer's exact
    prefix counters against its pre-restart count.
    """
    expected_prefixes = set()
    for neighbor_routes in prime_neighbor_routes.values():
        expected_prefixes.update(neighbor_routes)
    prime_bgp_neighbors = set(prime_bgp_neighbors)

    for prefix in expected_prefixes:
        if prefix not in rib:
            pytest.fail(
                "Route to prefix {} doesn't exist during prime-wide graceful "
                "restart.".format(prefix))
        prime_paths = [
            path for path in rib[prefix]
            if path.get('peerId') in prime_bgp_neighbors
        ]
        if not prime_paths:
            logging.error(
                "Rib route entry to prefix %s has no shared-prime path:\n%s\n",
                prefix, json.dumps(rib[prefix]))
            pytest.fail(
                "Route to prefix {} has no path from the restarting prime."
                .format(prefix))
        if any(not path.get('stale', False) for path in prime_paths):
            logging.error(
                "Rib route entry to prefix %s has a non-stale prime path:\n%s\n",
                prefix, json.dumps(rib[prefix]))
            pytest.fail(
                "Route to prefix {} should have only stale paths from the "
                "restarting prime.".format(prefix))


def shared_prime_prefix_counter_snapshots_match(previous, current):
    """Return whether every peer's non-empty counter snapshot is unchanged."""
    return (
        previous is not None
        and previous == current
        and all(counters.get("All RIB", 0) > 0
                for counters in current.values())
    )


def shared_prime_prefix_counters_preserved(
        counters, expected_counters, during_restart):
    """Return whether one logical peer retained its pre-restart route counts."""
    walk_counters = counters["ribTableWalkCounters"]
    expected_all_rib = expected_counters["All RIB"]
    if during_restart:
        if (walk_counters["Stale"] != expected_all_rib or
                walk_counters["All RIB"] != expected_all_rib):
            return False
        return all(
            walk_counters.get(name, 0) == value
            for name, value in expected_counters.items()
            if name != "All RIB"
        )
    return (walk_counters["Stale"] == 0 and
            all(
                walk_counters.get(name, 0) >= value
                for name, value in expected_counters.items()
            ))


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

    def _snapshot_rib_counters(duthost, bgp_neighbors):
        """Record each session's route counters before shared-prime GR."""
        snapshots = {}
        for bgp_neighbor in bgp_neighbors:
            for namespace in duthost.get_frontend_asic_namespace_list():
                counters = _get_prefix_counters(
                    duthost, bgp_neighbor, namespace)["ribTableWalkCounters"]
                snapshots[(bgp_neighbor, namespace)] = {
                    name: counters[name]
                    for name in ("All RIB", "Valid", "Useable", "Used")
                    if name in counters
                }
        return snapshots

    def _snapshot_shared_prime_state_when_stable(duthost, bgp_neighbors):
        """Capture routes only after every peer's counters stop changing."""
        state = {
            "previous_counters": None,
            "routes": None,
            "counters": None,
        }

        def _capture_if_stable():
            counters = _snapshot_rib_counters(duthost, bgp_neighbors)
            if not shared_prime_prefix_counter_snapshots_match(
                    state["previous_counters"], counters):
                state["previous_counters"] = counters
                return False

            routes = {
                bgp_neighbor: _get_learned_bgp_routes_from_neighbor(
                    duthost, bgp_neighbor)
                for bgp_neighbor in bgp_neighbors
            }
            counters_after_routes = _snapshot_rib_counters(
                duthost, bgp_neighbors)
            state["previous_counters"] = counters_after_routes
            if not shared_prime_prefix_counter_snapshots_match(
                    counters, counters_after_routes):
                return False

            state["routes"] = routes
            state["counters"] = counters_after_routes
            return True

        pytest_assert(
            wait_until(300, 10, 0, _capture_if_stable),
            "shared-prime BGP prefix counters did not stabilize before GR"
        )
        return state["routes"], state["counters"]

    def _verify_prefix_counters_from_neighbor_during_graceful_restart(
            duthost, bgp_neighbors, expected_all_rib=None):
        """Verify that all routes received from neighbor are stale during graceful restart."""
        for bgp_neighbor in bgp_neighbors:
            for namespace in duthost.get_frontend_asic_namespace_list():
                counters = _get_prefix_counters(duthost, bgp_neighbor, namespace)
                logging.debug("Prefix counters for bgp neighbor %s in namespace %s:\n%s\n",
                              bgp_neighbor, namespace, counters)
                walk_counters = counters["ribTableWalkCounters"]
                assert walk_counters["Stale"] == walk_counters["All RIB"]
                if expected_all_rib is not None:
                    expected = expected_all_rib[(bgp_neighbor, namespace)]
                    assert shared_prime_prefix_counters_preserved(
                        counters, expected, during_restart=True)

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

    def _verify_prefix_counters_from_neighbor_after_graceful_restart(
            duthost, bgp_neighbors, expected_all_rib=None):
        """Verify routes from neighbor are relearned and out of stale after graceful restart."""
        for bgp_neighbor in bgp_neighbors:
            for namespace in duthost.get_frontend_asic_namespace_list():
                counters = _get_prefix_counters(duthost, bgp_neighbor, namespace)
                logging.debug("Prefix counters for bgp neighbor %s in namespace %s:\n%s\n",
                              bgp_neighbor, namespace, json.dumps(counters))
                walk_counters = counters["ribTableWalkCounters"]
                if expected_all_rib is None:
                    if not (walk_counters["Stale"] == 0 and
                            walk_counters["Valid"] > 0):
                        return False
                else:
                    expected = expected_all_rib[(bgp_neighbor, namespace)]
                    if not shared_prime_prefix_counters_preserved(
                            counters, expected, during_restart=False):
                        return False
        return True

    duthost = duthosts[rand_one_dut_hostname]

    config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
    bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
    portchannels = config_facts.get('PORTCHANNEL_MEMBER', {})
    dev_nbrs = config_facts.get('DEVICE_NEIGHBOR', {})
    configurations = tbinfo['topo']['properties']['configuration_properties']
    is_v6_topo = is_ipv6_only_topology(tbinfo)
    if is_v6_topo:
        exabgp_ips = [configurations['common']['nhipv6']]
        exabgp_sessions = ['exabgp_v6']
    else:
        exabgp_ips = [configurations['common']['nhipv4'], configurations['common']['nhipv6']]
        exabgp_sessions = ['exabgp_v4', 'exabgp_v6']
    vrf = "default"

    # select neighbor to test
    if duthost.check_bgp_default_route(ipv4=not is_v6_topo):
        # if default route is present, select from default route nexthops
        if is_v6_topo:
            rtinfo_v6 = duthost.get_ip_route_info(ipaddress.ip_network("::/0"))
            ifnames_v6 = [nh[1] for nh in rtinfo_v6['nexthops']]

            test_interface = ifnames_v6[0]
        else:
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

    nbrhost = nbrhosts[test_neighbor_name]
    if nbrhost.get('is_multi_vrf_peer', False):
        # cEOS uses the logical peer name as its VRF, while cSONiC maps it to a
        # SONiC-safe runtime name.  The converger metadata is authoritative for
        # both backends.
        vrf = nbrhost['multi_vrf_data']['vrf']
        exabgp_ips = [nbrhost['multi_vrf_data']['ptf_bp_config'].get("ipv4"),
                      nbrhost['multi_vrf_data']['ptf_bp_config'].get("ipv6")]
        exabgp_ips = list(filter(None, exabgp_ips))
        exabgp_ips = [ip.split("/")[0] for ip in exabgp_ips]
    test_neighbor_host = nbrhost['host']

    # A converged cSONiC prime has one bgpd shared by all logical VRFs. Killing
    # it is therefore a prime-wide disruption, not per-logical-peer isolation.
    # Track every collateral DUT session explicitly, including the selected
    # logical peer used for route-preservation assertions.
    prime_peer_names = get_csonic_prime_peer_names(
        nbrhosts, test_neighbor_name)
    prime_bgp_neighbors = []
    for peer_name in prime_peer_names:
        prime_bgp_neighbors.extend(
            _find_test_bgp_neighbors(peer_name, bgp_neighbors))
    prime_bgp_neighbors = sorted(set(prime_bgp_neighbors))
    is_shared_csonic_prime = len(prime_peer_names) > 1

    logging.info(
        "Select neighbor %s for graceful restart; prime-wide logical peers=%s, "
        "DUT sessions=%s", test_neighbor_name, prime_peer_names,
        prime_bgp_neighbors)

    # Keep route and accepted-prefix snapshots per DUT session. Shared-prime
    # peers advertise overlapping prefixes; the global BGP RIB may compact
    # equivalent stale ECMP paths, while per-session counters retain exact
    # collateral-route accounting. Wait for every peer's counters to stabilize
    # before and after the route reads so an in-progress update burst cannot
    # create a false pre/during mismatch.
    if is_shared_csonic_prime:
        (prime_neighbor_routes_before_gr,
         prime_prefix_counters_before_gr) = (
            _snapshot_shared_prime_state_when_stable(
                duthost, prime_bgp_neighbors))
    else:
        prime_neighbor_routes_before_gr = {
            prime_bgp_neighbor: _get_learned_bgp_routes_from_neighbor(
                duthost, prime_bgp_neighbor)
            for prime_bgp_neighbor in prime_bgp_neighbors
        }
        prime_prefix_counters_before_gr = None

    # verify exabgp sessions to the neighbor are up before GR process
    pytest_assert(
        test_neighbor_host.check_bgp_session_state(exabgp_ips, exabgp_sessions, vrf=vrf),
        "exabgp sessions {} are not up before graceful restart".format(exabgp_sessions)
    )

    try:
        # shutdown Rib agent, starting GR process
        logger.info("shutdown rib process on neighbor {}".format(test_neighbor_name))
        test_neighbor_host.kill_bgpd()

        # Wait until every DUT session on the shared prime enters NSF. This
        # records the expected collateral effect of a prime-wide bgpd stop.
        for prime_bgp_neighbor in prime_bgp_neighbors:
            pytest_assert(
                wait_until(60, 5, 0, duthost.check_bgp_session_nsf,
                           prime_bgp_neighbor),
                "prime-wide neighbor {} does not enter NSF state".format(
                    prime_bgp_neighbor)
            )

        # A shared cSONiC daemon can compact equivalent stale ECMP paths in both
        # the global and per-neighbor accepted-route views. FRR also removes the
        # pre-policy Adj-RIB-In when the peer enters NSF, so neither route view
        # can preserve exact peer-to-prefix identity during the outage. Verify
        # traffic-preserving stale coverage globally, then use each disconnected
        # session's exact Stale/All RIB counters to prove no peer lost routes;
        # a disconnected peer cannot add replacement routes during this window.
        rib_after_gr = _get_rib(duthost)
        if is_shared_csonic_prime:
            verify_shared_prime_routes_during_graceful_restart(
                prime_neighbor_routes_before_gr, rib_after_gr,
                prime_bgp_neighbors)
        else:
            for neighbor_routes in prime_neighbor_routes_before_gr.values():
                _verify_bgp_neighbor_routes_during_graceful_restart(
                    neighbor_routes, rib_after_gr)

        _verify_prefix_counters_from_neighbor_during_graceful_restart(
            duthost, prime_bgp_neighbors, prime_prefix_counters_before_gr)

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
            wait_until(300, 10, 0, test_neighbor_host.check_bgp_session_state, exabgp_ips, exabgp_sessions, vrf=vrf),
            "exabgp sessions {} are not coming back".format(exabgp_sessions)
        )

    finally:
        # unshut the connected ports from nbr
        logging.info("unshut the ports connected to neighbor %s: %s", test_neighbor_name, nbr_ports)
        for nbr_port in nbr_ports:
            test_neighbor_host.no_shutdown(nbr_port)

    # Confirm all collateral sessions on the shared prime recover, not only the
    # selected logical peer whose ports were toggled.
    pytest_assert(
        wait_until(300, 10, 0, duthost.check_bgp_session_state,
                   prime_bgp_neighbors),
        "prime-wide graceful restarted BGP sessions {} are not coming back"
        .format(prime_bgp_neighbors)
    )

    # confirm routes from the neighbor are restored
    pytest_assert(
        wait_until(
            300, 10, 0,
            _verify_prefix_counters_from_neighbor_after_graceful_restart,
            duthost, prime_bgp_neighbors, prime_prefix_counters_before_gr),
        "after prime-wide graceful restart, collateral RIBs are not restored"
    )

    # Verify no route changes in the application db
    # TODO
