import logging
import pytest

from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until
# Constants
from bgp_helpers import TEST_COMMUNITY, ALLOW_LIST_PREFIX_JSON_FILE, PREFIX_LISTS
# Functions
from bgp_helpers import apply_allow_list, remove_allow_list, check_routes_on_neighbors_empty_allow_list
from bgp_helpers import check_routes_on_from_neighbor, checkout_bgp_mon_routes, check_routes_on_neighbors
# Fixtures
from bgp_helpers import bgp_allow_list_setup, prepare_eos_routes    # noqa F401

pytestmark = [
    pytest.mark.topology("m0"),
    pytest.mark.device_type("vs")
]

logger = logging.getLogger(__name__)

DEPLOYMENT_ID = "0"
ALLOW_LIST_M0 = {
    "BGP_ALLOWED_PREFIXES": {
        "DEPLOYMENT_ID|{}|NEIGHBOR_TYPE|OpticalLonghaulTerminal|{}".format(DEPLOYMENT_ID, TEST_COMMUNITY): {
            "prefixes_v4": PREFIX_LISTS["ALLOWED_WITH_COMMUNITY"],
            "prefixes_v6": PREFIX_LISTS["ALLOWED_WITH_COMMUNITY_V6"],
        },
        "DEPLOYMENT_ID|{}|NEIGHBOR_TYPE|OpticalLonghaulTerminal".format(DEPLOYMENT_ID): {
            "prefixes_v4": PREFIX_LISTS["ALLOWED"],
            "prefixes_v6": PREFIX_LISTS["ALLOWED_V6"],
        }
    }
}


def set_neighbor_metadata(duthost, neighbor, type):
    """
    Modify neighbor type on config_db
    """
    duthost.shell("sonic-db-cli CONFIG_DB hset \"DEVICE_NEIGHBOR_METADATA|{}\" type \"{}\"".format(neighbor, type))
    duthost.stop_service("bgp")
    duthost.shell("systemctl reset-failed bgp")
    duthost.start_service("bgp")
    pytest_assert(wait_until(100, 10, 10, duthost.is_service_fully_started_per_asic_or_host, "bgp"), "bgp not started")


@pytest.fixture(scope="module", autouse=True)
def m0_setup_teardown(duthost, bgp_allow_list_setup, topo_scenario):
    pytest_require(topo_scenario == "m0_l3_scenario", "Only support m0_l3_scenario in test_bgp_allow_list_m0_olt")
    set_neighbor_metadata(duthost, bgp_allow_list_setup["downstream"], "OpticalLonghaulTerminal")
    yield
    set_neighbor_metadata(duthost, bgp_allow_list_setup["downstream"], "BmcMgmtToRRouter")


@pytest.fixture
def load_remove_allow_list(duthosts, bgp_allow_list_setup, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]
    allow_list = ALLOW_LIST_M0
    namespace = bgp_allow_list_setup["downstream_namespace"]
    apply_allow_list(duthost, namespace, allow_list, ALLOW_LIST_PREFIX_JSON_FILE)

    yield

    remove_allow_list(duthost, namespace, ALLOW_LIST_PREFIX_JSON_FILE)


def check_routes_on_m0(duthost, namespace, is_exist=False):
    """
    Check routes on DUT. If is_exist is True, assert that allowed routes is accepted by DUT. If is_exist is False,
    assert that all routes are denied by DUT.
    """
    for is_allowed, prefixes in PREFIX_LISTS.items():
        for prefix in prefixes:
            dut_route = duthost.get_route(prefix, namespace)
            if is_exist:
                # Routes not in allow list should be denied
                pytest_assert(not dut_route or "DISALLOWED" not in is_allowed,
                              "Disallowed route {} is found on DUT".format(prefix))
            else:
                # All routes show be denied
                pytest_assert(not dut_route, "Route {} is found on DUT".format(prefix))


def check_without_bgp_allow_list(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts, ptfhost):
    duthost = duthosts[rand_one_dut_hostname]
    # All routes should be found on from neighbor.
    check_routes_on_from_neighbor(bgp_allow_list_setup, nbrhosts)
    # All routes should be denied in M0 dut, which is different from T1.
    check_routes_on_m0(duthost, bgp_allow_list_setup["downstream_namespace"], False)
    # Since routes are denied on the DUT, there will be no such routes on neighbors either, which is somewhat similar
    # to T1 with "deny" default_action
    check_routes_on_neighbors_empty_allow_list(nbrhosts, bgp_allow_list_setup, permit=False)
    checkout_bgp_mon_routes(duthost, ptfhost)


def test_default_allow_list_preconfig(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts, ptfhost,
                                      bgpmon_setup_teardown, m0_setup_teardown):
    """
    Verify bgp policy before applying bgp_allow_list
    """
    check_without_bgp_allow_list(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts, ptfhost)


def test_allow_list(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts, ptfhost, load_remove_allow_list,
                    bgpmon_setup_teardown, m0_setup_teardown):
    duthost = duthosts[rand_one_dut_hostname]
    # All routes should be found on from neighbor
    check_routes_on_from_neighbor(bgp_allow_list_setup, nbrhosts)
    # After applying allow_list, routes not in allow_list should be denied
    check_routes_on_m0(duthost, bgp_allow_list_setup["downstream_namespace"], True)
    # Routes in allow_list should be forwarded and keep ori community, routes not in allow_list should not be forwarded,
    # which is somewhat similar to T1 with "deny" default_action
    check_routes_on_neighbors(nbrhosts, bgp_allow_list_setup, False)
    checkout_bgp_mon_routes(duthost, ptfhost)


def test_default_allow_list_postconfig(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts, ptfhost,
                                       bgpmon_setup_teardown, m0_setup_teardown):
    """
    Verify bgp policy after removing bgp_allow_list
    """
    check_without_bgp_allow_list(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts, ptfhost)