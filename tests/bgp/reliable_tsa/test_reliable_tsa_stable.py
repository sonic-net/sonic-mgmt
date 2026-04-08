import logging
import threading

import pytest

from tests.common import reboot, config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.reboot import wait_for_startup
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.platform.processes_utils import wait_critical_processes, _all_critical_processes_healthy
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.bgp.bgp_helpers import get_tsa_chassisdb_config, get_sup_cfggen_tsa_value, verify_dut_configdb_tsa_value
from tests.bgp.traffic_checker import get_traffic_shift_state
from tests.bgp.route_checker import parse_routes_on_neighbors, check_and_log_routes_diff, \
    verify_current_routes_announced_to_neighs, assert_only_loopback_routes_announced_to_neighs
from tests.bgp.constants import TS_NORMAL, TS_MAINTENANCE
from tests.bgp.test_startup_tsa_tsb_service import get_tsa_tsb_service_uptime, get_tsa_tsb_service_status, \
    get_startup_tsb_timer, enable_disable_startup_tsa_tsb_service     # noqa: F401

pytestmark = [
    pytest.mark.topology('t2')
]

logger = logging.getLogger(__name__)

CONTAINER_CHECK_INTERVAL_SECS = 2
CONTAINER_STOP_THRESHOLD_SECS = 60
CONTAINER_RESTART_THRESHOLD_SECS = 300
BGP_CRIT_PROCESS = "bgpcfgd"
supported_tsa_configs = ['false', 'true']
lock = threading.Lock()


def nbrhosts_to_dut(duthost, nbrhosts, dut_nbrhosts):
    """
    @summary: Fetch the neighbor hosts' details for duthost and update the dut_nbrhosts dict
    """
    mg_facts = duthost.minigraph_facts(host=duthost.hostname)['ansible_facts']
    all_nbrhosts = {}
    for host in nbrhosts.keys():
        if host in mg_facts['minigraph_devices']:
            new_nbrhost = {host: nbrhosts[host]}
            all_nbrhosts.update(new_nbrhost)

    with lock:
        dut_nbrhosts[duthost] = all_nbrhosts


def run_tsb_on_linecard(linecard):
    if verify_dut_configdb_tsa_value(linecard) is not False or get_tsa_chassisdb_config(linecard) != 'false' or \
            get_traffic_shift_state(linecard, cmd='TSC no-stats') != TS_NORMAL:
        linecard.shell('TSB')
        linecard.shell('sudo config save -y')
        # Ensure that the DUT is not in maintenance already before start of the test
        pytest_assert(wait_until(30, 5, 0, lambda: TS_NORMAL == get_traffic_shift_state(linecard, 'TSC no-stats')),
                      "DUT is not in normal state")


def set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname):
    """
    @summary: Common method to make sure the supervisor and line cards are in normal state before and after the test
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    if get_tsa_chassisdb_config(suphost) != 'false' or get_sup_cfggen_tsa_value(suphost) != 'false':
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

    # Issue TSB on line card before proceeding further
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(run_tsb_on_linecard, linecard)


def verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes):
    """
    @summary: Verify all routes are announced to neighbors in TSB
    """
    for linecard in duthosts.frontend_nodes:
        # Wait until all routes are announced to neighbors
        cur_v4_routes = {}
        cur_v6_routes = {}
        # Verify that all routes advertised to neighbor at the start of the test
        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard, dut_nbrhosts[linecard],
                          orig_v4_routes[linecard], cur_v4_routes, 4):
            if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                             orig_v4_routes[linecard], cur_v4_routes, 4):
                pytest.fail("Not all ipv4 routes are announced to neighbors")

        if not wait_until(300, 3, 0, verify_current_routes_announced_to_neighs, linecard, dut_nbrhosts[linecard],
                          orig_v6_routes[linecard], cur_v6_routes, 6):
            if not check_and_log_routes_diff(linecard, dut_nbrhosts[linecard],
                                             orig_v6_routes[linecard], cur_v6_routes, 6):
                pytest.fail("Not all ipv6 routes are announced to neighbors")


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_sup_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                    enable_disable_startup_tsa_tsb_service, nbrhosts,     # noqa: F811
                                                    traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor and line cards are in TSB initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from supervisor and verify line cards' BGP operational state changes to TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Verify DUT is in maintenance state
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_sup_on_tsb_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor is on TSB and line cards are in TSA initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state maintains TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Ensure that the DUT is in maintenance state
            pytest_assert(
                wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                "DUT is not in maintenance state",
            )

        # Convert line cards to BGP operational TSA state for the current test as initial config
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state with supervisor TSA action")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Verify DUT continues to be in maintenance state even with supervisor TSA action
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_act_when_sup_on_tsa_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor is on TSA and line cards are in TSB configuration initially but with
    BGP operational TSA states
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state changes to TSB from TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")

        # Confirm all the line cards are in BGP operational TSA state due to supervisor TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        # Verify line cards change the state to TSB from TSA after supervisor TSB
        def verify_linecard_after_sup_tsb(lc):
            # Verify DUT changes to normal state with supervisor TSB action
            pytest_assert(wait_until(30, 5, 0, lambda: TS_NORMAL == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in normal state with supervisor TSB action")
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsb, linecard)
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsb_act_when_sup_and_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                        enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                        nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSB action when supervisor and line cards are in TSA configuration initially
    Verify supervisor config state changes to TSB and Line card BGP TSA operational state is maintained
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))
    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")

        # Similarly keep line cards in TSA mode to start with as part of the test
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Issue TSB on the supervisor
        suphost.shell('TSB')
        suphost.shell('sudo config save -y')
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsb(lc):
            # Verify DUT continues to be in maintenance state even with supervisor TSB action
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Verify line cards maintains the BGP operational TSA state but with chassisdb tsa-enabled config as 'false'
        # in sync with supervisor
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsb, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_when_sup_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                    enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                    nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state changes to TSA from TSB
    Verify supervisor card continues to be in TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'false' config
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_when_sup_on_tsa_duts_on_tsb_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor is on TSA and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state maintains its TSA state
    Verify supervisor card continues to be in TSA config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            # Verify line card config TSA enabled is still false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))

        # Confirm all the line cards are in BGP operational TSA state due to supervisor TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state continues to be in TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'true' config
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_act_when_sup_on_tsb_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                           enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                           nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor is on TSB and line cards are in TSA initially
    Verify line card config state changes to TSB and BGP TSA operational state changes to TSB from TSA
    Verify supervisor card continues to be in TSB config
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state and all routes are
    announced back to neighbors when the line cards are back to TSB.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Keep supervisor in TSB mode to start with as part of the test
        # And keep the line cards in TSA and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        def run_tsb_on_linecard_and_verify(lc):
            lc.shell('TSB')
            lc.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in normal state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_NORMAL == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in normal state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSB from line card and verify line cards' BGP operational state changes to TSB
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsb_on_linecard_and_verify, linecard)

        # Make sure all routes are advertised back to neighbors after TSB on line cards
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
    finally:
        # Bring back the supervisor and line cards to the normal state at the end of test
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)


@pytest.mark.disable_loganalyzer
def test_dut_tsb_act_when_sup_and_duts_on_tsa_initially(duthosts, localhost, enum_supervisor_dut_hostname,
                                                        enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                        nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSB action when supervisor and line cards are in TSA configuration initially
    Verify line card config state changes to TSB but the line card BGP TSA operational state is maintained
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Keep supervisor in TSA mode to start with as part of the test
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")

        # Similarly keep line cards in TSA mode to start with as part of the test
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        def run_tsb_on_linecard_and_verify(lc):
            lc.shell('TSB')
            lc.shell('sudo config save -y')
            # Verify line card config changed to tsa_enabled false
            pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                          "DUT {} tsa_enabled config is enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

        # Issue TSB from line card and verify line cards' BGP operational state maintained at TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsb_on_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced after TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'true' config
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_with_sup_reboot(duthosts, localhost, enum_supervisor_dut_hostname,
                                     enable_disable_startup_tsa_tsb_service,                # noqa: F811
                                     nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor and line cards are in TSB initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state changes to TSA from TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do 'config save' and reboot supervisor.
    After reboot, make sure the BGP TSA operational states are same as before reboot.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    tsa_tsb_timer = dict()
    int_status_result, crit_process_check = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    orig_v4_routes, orig_v6_routes = dict(), dict()
    up_bgp_neighbors = dict()
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        # Issue TSA from supervisor and verify line cards' BGP operational state changes to TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_tsa(lc):
            # Verify DUT is in maintenance state.
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))
            # Not verifying loopback routes here check since its been checked multiple times with previous test cases

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_tsa, linecard)

        # Get a dut uptime before reboot
        sup_uptime_before = suphost.get_up_time()
        # Reboot supervisor and wait for startup_tsa_tsb service to start on line cards
        logger.info("Cold reboot on supervisor node: %s", suphost.hostname)
        reboot(suphost, localhost, wait=240)
        logging.info("Wait until all critical processes are fully started")
        wait_critical_processes(suphost)

        sup_uptime = suphost.get_up_time()
        logger.info('DUT {} up since {}'.format(suphost.hostname, sup_uptime))
        rebooted = float(sup_uptime_before.strftime("%s")) != float(sup_uptime.strftime("%s"))
        assert rebooted, "Device {} did not reboot".format(suphost.hostname)
        # verify chassisdb config is same as before reboot
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_linecard_after_sup_reboot(lc):
            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")

            # Verify DUT is in the same maintenance state like before supervisor reboot
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state when startup_tsa_tsb service is running")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

            logging.info("Wait until all critical processes are fully started")

            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_res = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_res

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_after_sup_reboot, linecard)

        def verify_linecard_tsa_tsb(lc):
            # Verify startup_tsa_tsb service stopped after expected time
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is not stopped even after configured timer expiry")

            # Ensure dut comes back to normal state after timer expiry
            if not get_tsa_tsb_service_status(lc, 'running'):
                # Verify dut continues to be in TSA even after startup_tsa_tsb service is stopped
                pytest_assert(wait_until(30, 5, 0,
                                         lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                              "DUT is not in normal state after startup_tsa_tsb service is stopped")
                pytest_assert('true' == get_tsa_chassisdb_config(lc),
                              "{} tsa_enabled config is not enabled".format(lc.hostname))
                # Verify line card config changed to TSB after startup-tsa-tsb service expiry
                pytest_assert(verify_dut_configdb_tsa_value(lc) is False,
                              "DUT {} tsa_enabled config is enabled".format(lc.hostname))

        # Once all line cards are in maintenance state, proceed further
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_linecard_tsa_tsb, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and
                    TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats')):
                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True, exec_tsb=True)

        # Make sure linecards are in Normal state, if not do config-reload on the dut
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_sup_tsa_act_when_duts_on_tsa_with_sup_config_reload(duthosts, localhost, enum_supervisor_dut_hostname,
                                                             enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                             nbrhosts, traffic_shift_community, tbinfo):
    """
    Test supervisor TSA action when supervisor is on TSB and line cards are in TSA initially
    Verify supervisor config state changes to TSA and Line card BGP TSA operational state maintained at TSA
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do config_reload on the supervisor.
    After config_relaod, make sure the BGP TSA operational states are same as before.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    up_bgp_neighbors = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")

        # Convert line cards to BGP operational TSA state for the current test as initial config
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        # Now Issue TSA from supervisor and make sure it changes from TSB->TSA
        suphost.shell('TSA')
        suphost.shell('sudo config save -y')
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_tsa_after_sup_tsa(lc):
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state with supervisor TSA action")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is not enabled".format(lc.hostname))

            up_bgp_neighbors_of_linecard = lc.get_bgp_neighbors_per_asic("established")
            with lock:
                up_bgp_neighbors[lc] = up_bgp_neighbors_of_linecard

        # Verify DUT continues to be in maintenance state even with supervisor TSA action
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_tsa_after_sup_tsa, linecard)

        # Do config_reload on the supervisor and verify configs are same as before
        config_reload(suphost, wait=300, safe_reload=True)
        pytest_assert('true' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is not enabled".format(suphost.hostname))

        def verify_line_card_after_sup_config_reload(lc):
            # Verify DUT is in the same maintenance state like before supervisor config reload
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state after supervisor config reload")
            pytest_assert('true' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled chassisdb config is not enabled".format(lc.hostname))
            # Before verifying loopback address, make sure IBGP neighbors are in established state
            pytest_assert(wait_until(900, 20, 0, lc.check_bgp_session_state_all_asics,
                                     up_bgp_neighbors[lc], "established"))

        # Verify line cards traffic shift states are same as before config_reload
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(verify_line_card_after_sup_config_reload, linecard)

        for linecard in duthosts.frontend_nodes:
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")
    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)


@pytest.mark.disable_loganalyzer
def test_dut_tsa_act_with_reboot_when_sup_dut_on_tsb_init(duthosts, localhost, enum_supervisor_dut_hostname,
                                                          enable_disable_startup_tsa_tsb_service,     # noqa: F811
                                                          nbrhosts, traffic_shift_community, tbinfo):
    """
    Test line card TSA action when supervisor and line cards are in TSB initially
    Verify line card config state changes to TSA and BGP TSA operational state changes to TSA from TSB
    Verify supervisor card continues to be in TSB
    Make sure only loopback routes are advertised to neighbors during line cards' TSA state.
    Then, do 'config save' and reboot the line cards.
    After reboot, make sure the BGP TSA operational states are same as before reboot on line cards.
    """
    suphost = duthosts[enum_supervisor_dut_hostname]
    if get_tsa_chassisdb_config(suphost) not in supported_tsa_configs:
        pytest.skip("Reliable TSA feature is not supported in this image on dut {}".format(suphost.hostname))

    tsa_tsb_timer = dict()
    int_status_result, crit_process_check = dict(), dict()
    for linecard in duthosts.frontend_nodes:
        tsa_tsb_timer[linecard] = get_startup_tsb_timer(linecard)
        int_status_result[linecard] = True
        crit_process_check[linecard] = True

    dut_nbrhosts = dict()
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for linecard in duthosts.frontend_nodes:
            executor.submit(nbrhosts_to_dut, linecard, nbrhosts, dut_nbrhosts)

    up_bgp_neighbors = dict()
    orig_v4_routes, orig_v6_routes = dict(), dict()
    # Initially make sure both supervisor and line cards are in BGP operational normal state
    set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)
    try:
        # Get the original routes present on the neighbors for each line card
        for linecard in duthosts.frontend_nodes:
            up_bgp_neighbors[linecard] = linecard.get_bgp_neighbors_per_asic("established")
            # Get all routes on neighbors
            orig_v4_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 4)
            orig_v6_routes[linecard] = parse_routes_on_neighbors(linecard, dut_nbrhosts[linecard], 6)

        def run_tsa_on_linecard_and_verify(lc):
            lc.shell('TSA')
            lc.shell('sudo config save -y')
            # Verify line card config changed to TSA enabled true
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))
            # Ensure that the DUT is in maintenance state
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))

        # Issue TSA from line card and verify line cards' BGP operational state changes to TSA
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(run_tsa_on_linecard_and_verify, linecard)

        def reboot_linecard_and_verify(lc):
            logger.info("Cold reboot on node: %s", lc.hostname)
            reboot(lc, localhost, wait=240)

            wait_for_startup(lc, localhost, delay=10, timeout=300)

            # Ensure startup_tsa_tsb service started on expected time since dut rebooted
            dut_uptime = lc.get_up_time()
            logging.info('DUT {} up since {}'.format(lc.hostname, dut_uptime))
            service_uptime = get_tsa_tsb_service_uptime(lc)
            time_diff = (service_uptime - dut_uptime).total_seconds()
            pytest_assert(int(time_diff) < 300,
                          "startup_tsa_tsb service started much later than the expected time after dut reboot")
            # Verify startup_tsa_tsb service is not started and in exited due to manual TSA
            pytest_assert(wait_until(tsa_tsb_timer[lc], 20, 0, get_tsa_tsb_service_status, lc, 'exited'),
                          "startup_tsa_tsb service is in running state after dut reboot which is not expected")
            # Verify DUT is in maintenance state.
            pytest_assert(wait_until(30, 5, 0, lambda: TS_MAINTENANCE == get_traffic_shift_state(lc, 'TSC no-stats')),
                          "DUT is not in maintenance state")
            # Ensure line card chassisdb config is in sync with supervisor
            pytest_assert('false' == get_tsa_chassisdb_config(lc),
                          "{} tsa_enabled config is enabled".format(lc.hostname))
            # Verify line card config changed is still TSA enabled true after reboot
            pytest_assert(verify_dut_configdb_tsa_value(lc) is True,
                          "DUT {} tsa_enabled config is not enabled".format(lc.hostname))

            # Make sure the ports, interfaces are UP and running after reboot
            logging.info("Wait until all critical processes are fully started")
            crit_process_check_res = wait_until(600, 20, 0, _all_critical_processes_healthy, lc)
            int_status_check_result = wait_until(1200, 20, 0, check_interface_status_of_up_ports, lc)
            with lock:
                crit_process_check[lc] = crit_process_check_res
                int_status_result[lc] = int_status_check_result

            # verify bgp sessions are established
            pytest_assert(
                wait_until(
                    900, 10, 0, lc.check_bgp_session_state_all_asics, up_bgp_neighbors[lc], "established"),
                "All BGP sessions are not up, no point in continuing the test")

        # Verify dut reboot scenario for one of the line card to make sure tsa config is in sync
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(reboot_linecard_and_verify, linecard)

        for linecard in duthosts.frontend_nodes:
            # Verify only loopback routes are announced to neighbors when the linecards are in TSA
            assert_only_loopback_routes_announced_to_neighs(duthosts, linecard, dut_nbrhosts[linecard],
                                                            traffic_shift_community,
                                                            "Failed to verify routes on nbr in TSA")

        # Verify supervisor still has tsa_enabled 'false' config
        pytest_assert('false' == get_tsa_chassisdb_config(suphost),
                      "Supervisor {} tsa_enabled config is enabled".format(suphost.hostname))

    finally:
        # Bring back the supervisor and line cards to the normal state
        set_tsb_on_sup_duts_before_and_after_test(duthosts, enum_supervisor_dut_hostname)

        def config_reload_linecard_if_unhealthy(lc):
            if not (int_status_result[lc] and crit_process_check[lc] and
                    TS_NORMAL == get_traffic_shift_state(lc, cmd='TSC no-stats')):
                logging.info("DUT is not in normal state after supervisor cold reboot, doing config-reload")
                config_reload(lc, safe_reload=True, check_intf_up_ports=True, exec_tsb=True)

        # Make sure linecards are in Normal state, if not do config-reload on the dut to recover
        with SafeThreadPoolExecutor(max_workers=8) as executor:
            for linecard in duthosts.frontend_nodes:
                executor.submit(config_reload_linecard_if_unhealthy, linecard)

        # Verify all routes are advertised back to neighbors when duts are in TSB
        verify_route_on_neighbors_when_duts_on_tsb(duthosts, dut_nbrhosts, orig_v4_routes, orig_v6_routes)
