import logging
import time

import pytest

from tests.common import config_reload
from tests.common.utilities import wait_until
from utils import get_crm_resource_status, check_queue_status, sleep_to_wait

CRM_POLLING_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300
MAX_WAIT_TIME = 120

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module')
def get_function_conpleteness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)

    yield

    duthost.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


@pytest.fixture(scope="module")
def cleanup_neighbors_dualtor(duthosts, ptfhost, tbinfo):
    """Cleanup neighbors on dualtor testbed."""
    if "dualtor" in tbinfo["topo"]["name"]:
        ptfhost.shell("supervisorctl stop garp_service", module_ignore_errors=True)
        ptfhost.shell("supervisorctl stop arp_responder", module_ignore_errors=True)
        duthosts.shell("sonic-clear arp")
        duthosts.shell("sonic-clear ndp")


@pytest.fixture(scope='module')
def withdraw_and_announce_existing_routes(duthosts, localhost, tbinfo, enum_rand_one_per_hwsku_frontend_hostname,
                                          enum_rand_one_frontend_asic_index, cleanup_neighbors_dualtor):            # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    namespace = asichost.namespace

    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]

    logger.info("withdraw existing ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "inq") is True)
    sleep_to_wait(CRM_POLLING_INTERVAL * 100)
    ipv4_route_used_before = get_crm_resource_status(duthost, "ipv4_route", "used", namespace)
    ipv6_route_used_before = get_crm_resource_status(duthost, "ipv6_route", "used", namespace)
    logger.info("ipv4 route used {}".format(ipv4_route_used_before))
    logger.info("ipv6 route used {}".format(ipv6_route_used_before))

    yield ipv4_route_used_before, ipv6_route_used_before

    logger.info("announce existing ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/")

    wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "outq") is True)
    sleep_to_wait(CRM_POLLING_INTERVAL * 5)
    logger.info("ipv4 route used {}".format(get_crm_resource_status(duthost, "ipv4_route", "used", namespace)))
    logger.info("ipv6 route used {}".format(get_crm_resource_status(duthost, "ipv6_route", "used", namespace)))


@pytest.fixture(scope="module", autouse=True)
def check_system_memmory(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    for index in range(1, 4):
        cmd = 'echo {} >  /proc/sys/vm/drop_caches'.format(index)
        duthost.shell(cmd, module_ignore_errors=True)

    cmd = "show system-memory"
    cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.debug("CMD {}: before test {}".format(cmd, cmd_response.get('stdout', None)))

    yield
    cmd = "show system-memory"
    cmd_response = duthost.shell(cmd, module_ignore_errors=True)
    logger.debug("CMD {}: after test {}".format(cmd, cmd_response.get('stdout', None)))

    config_reload(duthost, safe_reload=True, check_intf_up_ports=True)
