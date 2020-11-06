import pytest
import time
import logging

from test_route_perf import CRM_POLL_INTERVAL
from test_route_perf import CRM_DEFAULT_POLL_INTERVAL
from tests.common.errors import RunAnsibleModuleFail
from tests.common import config_reload

logger = logging.getLogger(__name__)

# Pytest configuration used by the route tests.
def pytest_addoption(parser):
    # Add options to pytest that are used by route tests

    route_group = parser.getgroup("Route test suite options")

    route_group.addoption("--num_routes", action="store", default=10000, type=int,
                     help="Number of routes for add/delete")

@pytest.fixture(params=[4, 6])
def ip_versions(request):
    """
    Parameterized fixture for IP versions.
    """
    yield request.param

@pytest.fixture(scope='function', autouse=True)
def reload_dut(duthost, request):
    yield
    if request.node.rep_call.failed:
        #Issue a config_reload to clear statically added route table and ip addr
        logging.info("Reloading config..")
        config_reload(duthost)

@pytest.fixture(autouse=True)
def ignore_expected_loganalyzer_exceptions(duthost, loganalyzer):
    """
        Ignore expected failures logs during test execution.

        The route_checker script will compare routes in APP_DB and ASIC_DB, and an ERROR will be
        recorded if mismatch. The testcase will add 10,000 routes to APP_DB, and route_checker may
        detect mismatch during this period. So a new pattern is added to ignore possible error logs.

        Args:
            duthost: DUT fixture
            loganalyzer: Loganalyzer utility fixture
    """
    ignoreRegex = [
        ".*ERR route_check.py:.*",
        ".*ERR.* \'routeCheck\' status failed.*"
    ]
    if loganalyzer:
        # Skip if loganalyzer is disabled
        loganalyzer.ignore_regex.extend(ignoreRegex)

@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthost):
    """ Set CRM polling interval to 1 second """
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)
    yield
    duthost.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)