import pytest
import logging
import time
from tests.common.dualtor.mux_simulator_control import mux_server_url, toggle_all_simulator_ports_to_upper_tor # lgtm[py/unused-import]
from tests.common.dualtor.dual_tor_utils import lower_tor_host, upper_tor_host # lgtm[py/unused-import]

CRM_POLL_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300

@pytest.fixture(scope='module', autouse=True)
def set_crm_polling_interval(lower_tor_host):
    """
    A session level fixture to set crm polling interval to 1 second
    """
    wait_time = 2
    lower_tor_host.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logging.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    lower_tor_host.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    logging.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

