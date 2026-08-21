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
def get_function_completeness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


def apply_crm_polling_interval(duthost, interval=CRM_POLLING_INTERVAL, wait_time=2):
    """Set the CRM polling interval and give the counters a moment to refresh.

    Factored out so it can be re-applied after anything that reloads config: `config reload`
    wipes the CRM counters AND resets the polling interval to the 300s default, so a module
    that set 1s at setup silently goes back to 300s afterwards. Every short retry/wait in this
    module is sized in CRM_POLLING_INTERVAL units, so at 300s those waits cover a fraction of
    a single poll cycle.
    """
    duthost.command("crm config polling interval {}".format(interval))
    logger.info("Waiting {} sec for CRM counters to become updated".format(wait_time))
    time.sleep(wait_time)


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    apply_crm_polling_interval(duthost)

    yield

    apply_crm_polling_interval(duthost, CRM_DEFAULT_POLL_INTERVAL)


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

    # Re-apply the 1s CRM polling interval. The autouse set_polling_interval fixture ran at
    # module setup, but frr_config_mode resolves after it and its mode switch performs a
    # `config reload`, which wipes the CRM counters and resets the interval to the 300s
    # default. Every wait below is sized in CRM_POLLING_INTERVAL units, so at 300s they cover
    # a fraction of one poll cycle. This is deliberately here rather than as a dependency of
    # set_polling_interval: that fixture is autouse for all of tests/stress, and making it
    # depend on frr_config_mode would parametrize every stress module over the config modes.
    apply_crm_polling_interval(duthost)

    logger.info("withdraw existing ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")

    result = wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, lambda: check_queue_status(duthost, "inq") is True)
    if not result:
        logger.warning("Failed to process all withdraw requests in {} seconds".format(MAX_WAIT_TIME))

    # Require real CRM values before taking the baseline. get_crm_resource_status() returns
    # None while CRM is repopulating, and a None baseline is not merely unhelpful: routes_stable()
    # below would then read None == None as "stable" and let the fixture return (None, None),
    # which only surfaces much later as the test's own count assertion.
    def _baseline_ready():
        return (get_crm_resource_status(duthost, "ipv4_route", "used", namespace) is not None
                and get_crm_resource_status(duthost, "ipv6_route", "used", namespace) is not None)

    if not wait_until(MAX_WAIT_TIME, CRM_POLLING_INTERVAL, 0, _baseline_ready):
        pytest.fail("CRM route counters are still unavailable after {}s; cannot take a route "
                    "baseline (check the CRM polling interval -- a config reload resets it to "
                    "{}s)".format(MAX_WAIT_TIME, CRM_DEFAULT_POLL_INTERVAL))

    ipv4_route_used_before = get_crm_resource_status(duthost, "ipv4_route", "used", namespace)
    ipv6_route_used_before = get_crm_resource_status(duthost, "ipv6_route", "used", namespace)

    def routes_stable():
        nonlocal ipv4_route_used_before, ipv6_route_used_before
        ipv4_route_used_now = get_crm_resource_status(duthost, "ipv4_route", "used", namespace)
        ipv6_route_used_now = get_crm_resource_status(duthost, "ipv6_route", "used", namespace)
        if ipv4_route_used_now is None or ipv6_route_used_now is None:
            # An unavailable read is not a stable one -- never let None == None pass as stable.
            return False
        ipv4_stable = ipv4_route_used_now == ipv4_route_used_before
        ipv6_stable = ipv6_route_used_now == ipv6_route_used_before
        ipv4_route_used_before = ipv4_route_used_now
        ipv6_route_used_before = ipv6_route_used_now
        return ipv4_stable and ipv6_stable

    full_wait_time = MAX_WAIT_TIME + CRM_POLLING_INTERVAL * 100
    result = wait_until(full_wait_time, CRM_POLLING_INTERVAL, CRM_POLLING_INTERVAL, routes_stable)
    if not result:
        pytest.fail("Routes failed to withdraw in {} seconds".format(full_wait_time))

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
