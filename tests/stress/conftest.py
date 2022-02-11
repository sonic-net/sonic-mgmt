import logging
import pytest

from tests.common.utilities import wait_until
from utils import get_crm_resources, check_queue_status, sleep_to_wait

CRM_POLLING_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300
MAX_WAIT_TIME = 120

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module')
def get_function_conpleteness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthost):
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

    yield

    duthost.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


@pytest.fixture(scope='module')
def withdraw_and_announce_existing_routes(duthost, localhost, tbinfo):
    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]

    logger.info("withdraw existing ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "inq") == True)
    sleep_to_wait(CRM_POLLING_INTERVAL * 100)
    ipv4_route_used_before = get_crm_resources(duthost, "ipv4_route", "used")
    ipv6_route_used_before = get_crm_resources(duthost, "ipv6_route", "used")
    logger.info("ipv4 route used {}".format(ipv4_route_used_before))
    logger.info("ipv6 route used {}".format(ipv6_route_used_before))

    yield ipv4_route_used_before, ipv6_route_used_before

    logger.info("announce existing ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "outq") == True)
    sleep_to_wait(CRM_POLLING_INTERVAL * 5)
    logger.info("ipv4 route used {}".format(get_crm_resources(duthost, "ipv4_route", "used")))
    logger.info("ipv6 route used {}".format(get_crm_resources(duthost, "ipv6_route", "used")))

