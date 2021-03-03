import pytest
import logging
import time

from tests.common.dualtor.dual_tor_utils import get_crm_nexthop_counter, lower_tor_host # lgtm[py/unused-import]
from tests.common.helpers.assertions import pytest_assert as py_assert


CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300


@pytest.fixture
def set_crm_polling_interval(lower_tor_host):
    """
    A function level fixture to set crm polling interval to 1 second
    """
    wait_time = 2
    lower_tor_host.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logging.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    lower_tor_host.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))


@pytest.fixture
def verify_crm_nexthop_counter_not_increased(lower_tor_host):
    """
    A function level fixture to verify crm nexthop counter not increased
    """
    original_counter = get_crm_nexthop_counter(lower_tor_host)
    yield
    diff = get_crm_nexthop_counter(lower_tor_host) - original_counter
    py_assert(diff == 0, "crm nexthop counter is increased by {}.".format(diff))
