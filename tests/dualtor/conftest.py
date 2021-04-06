import pytest
import logging
import time

from tests.common.dualtor.dual_tor_utils import get_crm_nexthop_counter # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.fixtures.ptfhost_utils import run_garp_service


CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300


@pytest.fixture
def set_crm_polling_interval(rand_selected_dut):
    """
    A function level fixture to set crm polling interval to 1 second
    """
    wait_time = 2
    logging.info("Setting crm polling interval to {} seconds".format(CRM_POLL_INTERVAL))
    rand_selected_dut.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logging.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    logging.info("Setting crm polling interval to {} seconds".format(CRM_DEFAULT_POLL_INTERVAL))
    rand_selected_dut.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))


@pytest.fixture
def verify_crm_nexthop_counter_not_increased(rand_selected_dut, set_crm_polling_interval):
    """
    A function level fixture to verify crm nexthop counter not increased
    """
    original_counter = get_crm_nexthop_counter(rand_selected_dut)
    logging.info("Before test: crm nexthop counter = {}".format(original_counter))
    yield
    time.sleep(CRM_POLL_INTERVAL)
    diff = get_crm_nexthop_counter(rand_selected_dut) - original_counter
    logging.info("Before test: crm nexthop counter = {}".format(original_counter + diff))
    py_assert(diff <= 0, "crm nexthop counter is increased by {}.".format(diff))


def pytest_addoption(parser):
    """
    Adds pytest options that are used by dual ToR tests
    """

    dual_tor_group = parser.getgroup("Dual ToR test suite options")

    dual_tor_group.addoption(
        "--mux-stress-count",
        action="store",
        default=2,
        type=int,
        help="The number of iterations for mux stress test"
    )


@pytest.fixture(scope="module", autouse=True)
def common_setup_teardown(request, tbinfo):
    if 'dualtor' in tbinfo['topo']['name']:
        request.getfixturevalue('run_garp_service')
