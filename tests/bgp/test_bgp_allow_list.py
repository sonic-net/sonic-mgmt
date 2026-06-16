'''This script is to test the BGP Allow List feature of SONiC.
'''
import logging
import time
import pytest

from tests.common.helpers.assertions import pytest_assert
# Constants
from bgp_helpers import ALLOW_LIST_PREFIX_JSON_FILE, PREFIX_LISTS, TEST_COMMUNITY, DUMP_FILE
# Functions
from bgp_helpers import apply_allow_list, remove_allow_list, check_routes_on_from_neighbor, get_default_action
from bgp_helpers import check_routes_on_neighbors_empty_allow_list, check_routes_on_neighbors
# Fixtures
from bgp_helpers import bgp_allow_list_setup, prepare_eos_routes    # noqa:F401

pytestmark = [
    pytest.mark.topology('t1', 'm1', 'c0'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)

DEPLOYMENT_ID = '0'
ALLOW_LIST = {
    'BGP_ALLOWED_PREFIXES': {
        'DEPLOYMENT_ID|{}|{}'.format(DEPLOYMENT_ID, TEST_COMMUNITY): {
            'prefixes_v4': PREFIX_LISTS['ALLOWED_WITH_COMMUNITY'],
            'prefixes_v6': PREFIX_LISTS['ALLOWED_WITH_COMMUNITY_V6'],
            'default_action': ''
        },
        'DEPLOYMENT_ID|{}'.format(DEPLOYMENT_ID): {
            'prefixes_v4': PREFIX_LISTS['ALLOWED'],
            'prefixes_v6': PREFIX_LISTS['ALLOWED_V6'],
            'default_action': ''
        }
    }
}


@pytest.fixture
def load_remove_allow_list(duthosts, bgp_allow_list_setup, rand_one_dut_hostname, request):     # noqa:F811
    allowed_list_prefixes = ALLOW_LIST['BGP_ALLOWED_PREFIXES']
    for _, value in list(allowed_list_prefixes.items()):
        value['default_action'] = request.param

    duthost = duthosts[rand_one_dut_hostname]
    namespace = bgp_allow_list_setup['downstream_namespace']
    apply_allow_list(duthost, namespace, ALLOW_LIST, ALLOW_LIST_PREFIX_JSON_FILE)

    yield request.param

    remove_allow_list(duthost, namespace, ALLOW_LIST_PREFIX_JSON_FILE)


def check_routes_on_dut(duthost, setup_info):
    """
    Verify routes on dut
    """
    for list_name, prefixes in list(PREFIX_LISTS.items()):
        if setup_info['is_v6_topo'] and "v6" not in list_name.lower():
            continue
        for prefix in prefixes:
            dut_route = duthost.get_route(prefix, setup_info['downstream_namespace'])
            pytest_assert(dut_route, 'Route {} is not found on DUT'.format(prefix))


def check_bgpmon_received_test_routes(ptfhost, setup_info, timeout=120):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if ptfhost.stat(path=DUMP_FILE).get('stat', {}).get('exists', False):
            break
        time.sleep(10)

    pytest_assert(ptfhost.stat(path=DUMP_FILE).get('stat', {}).get('exists', False),
                  'bgpmon dump file is not found: {}'.format(DUMP_FILE))
    time.sleep(20)

    bgpmon_routes = set(
        line.strip()
        for line in ptfhost.shell('cat {}'.format(DUMP_FILE), verbose=False)['stdout_lines']
        if line.strip()
    )

    expected = []
    for list_name, prefixes in list(PREFIX_LISTS.items()):
        if setup_info['is_v6_topo'] and "v6" not in list_name.lower():
            continue
        expected.extend(prefixes)

    missing = [p for p in expected if p not in bgpmon_routes]
    pytest_assert(missing == [], 'Not all allow list test routes are announced to bgpmon: {}'.format(missing))


def test_default_allow_list_preconfig(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts,  # noqa:F811
                                      ptfhost, bgpmon_setup_teardown):
    """
    Before applying allow list, verify bgp policy by default config
    """
    permit = True if get_default_action() == "permit" else False
    duthost = duthosts[rand_one_dut_hostname]
    # All routes should be found on from neighbor.
    check_routes_on_from_neighbor(bgp_allow_list_setup, nbrhosts)
    # All routes should be found in dut.
    check_routes_on_dut(duthost, bgp_allow_list_setup)
    # If permit is True, all routes should be forwarded and added drop_community and keep ori community.
    # If permit if False, all routes should not be forwarded.
    check_routes_on_neighbors_empty_allow_list(nbrhosts, bgp_allow_list_setup, permit)
    check_bgpmon_received_test_routes(ptfhost, bgp_allow_list_setup)


@pytest.mark.parametrize('load_remove_allow_list', ["permit", "deny"], indirect=['load_remove_allow_list'])
def test_allow_list(duthosts, rand_one_dut_hostname, bgp_allow_list_setup, nbrhosts,    # noqa:F811
                    load_remove_allow_list, ptfhost, bgpmon_setup_teardown):
    permit = True if load_remove_allow_list == "permit" else False
    duthost = duthosts[rand_one_dut_hostname]
    # All routes should be found on from neighbor.
    check_routes_on_from_neighbor(bgp_allow_list_setup, nbrhosts)
    # All routes should be found in dut.
    check_routes_on_dut(duthost, bgp_allow_list_setup)
    # If permit is True, all routes should be forwarded. Routs that in allow list should not be add drop_community
    # and keep ori community.
    # If permit is False, Routes in allow_list should be forwarded and keep ori community, routes not in allow_list
    # should not be forwarded.
    check_routes_on_neighbors(nbrhosts, bgp_allow_list_setup, permit)
    check_bgpmon_received_test_routes(ptfhost, bgp_allow_list_setup)


def test_default_allow_list_postconfig(duthosts, rand_one_dut_hostname, bgp_allow_list_setup,   # noqa:F811
                                       nbrhosts, ptfhost, bgpmon_setup_teardown):
    """
    After removing allow list, verify bgp policy
    """
    test_default_allow_list_preconfig(duthosts, rand_one_dut_hostname, bgp_allow_list_setup,    # noqa:F811
                                      nbrhosts, ptfhost, bgpmon_setup_teardown)
