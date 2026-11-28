import logging
import time

import pytest

from tests.common import config_reload
from tests.common.utilities import wait_until
from utils import (
    get_crm_route_counts,
    check_queue_status,
    sleep_to_wait,
    get_topo_scale_factor,
    wait_crm_route_counts_settled,
    CRM_SETTLE_TIME,
)

CRM_POLLING_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300
MAX_WAIT_TIME = 120

logger = logging.getLogger(__name__)


@pytest.fixture(scope='module')
def get_function_completeness_level(pytestconfig):
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
                                          enum_rand_one_frontend_asic_index, cleanup_neighbors_dualtor,
                                          request):                                                               # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)
    namespace = asichost.namespace

    ptf_ip = tbinfo["ptf_ip"]
    topo_name = tbinfo["topo"]["name"]

    # Scale BGP-drain timeout and post-withdraw settle by topology peer count;
    # defaults are tuned for ~5-peer mintopo and are too short for maxtopo
    # (~50 peers), where the SAI/HW pipeline is still draining when the
    # baseline is sampled. See test_announce_withdraw_route for context.
    scale = get_topo_scale_factor(tbinfo)

    settle_time = CRM_SETTLE_TIME * scale
    # The counts before the withdraw are the announced target for the loop and the ceiling the withdrawn
    # baseline has to drop below.
    announced_route_counts = get_crm_route_counts(duthost, namespace)
    if announced_route_counts is None:
        pytest.fail("CRM did not report route counts before the withdraw")
    logger.info("CRM route used before withdraw: ipv4 {} ipv6 {}".format(*announced_route_counts))

    def restore_routes():
        logger.info("announce existing ipv4 and ipv6 routes")
        localhost.announce_routes(
            topo_name=topo_name, ptf_ip=ptf_ip, action="announce", path="../ansible/")

        wait_until(
            MAX_WAIT_TIME * scale,
            CRM_POLLING_INTERVAL,
            0,
            lambda: check_queue_status(duthost, "outq") is True,
        )
        sleep_to_wait(CRM_POLLING_INTERVAL * 5)
        logger.info("route used after re-announce: {}".format(get_crm_route_counts(duthost, namespace)))

    request.addfinalizer(restore_routes)

    logger.info("withdraw existing ipv4 and ipv6 routes")
    localhost.announce_routes(topo_name=topo_name, ptf_ip=ptf_ip, action="withdraw", path="../ansible/")

    result = wait_until(MAX_WAIT_TIME * scale, CRM_POLLING_INTERVAL, 0,
                        lambda: check_queue_status(duthost, "inq") is True)
    if not result:
        logger.warning("Failed to process all withdraw requests in {} seconds".format(MAX_WAIT_TIME))

    # Require the counts to drop below the pre-withdraw reading as well as settle. Stillness is not enough:
    # on a topology with many peers a prefix is learnt from all of them, so its route entry stays until the
    # last path is withdrawn, and the counts sit flat near the full table for minutes. A vs DUT has no ASIC,
    # so its counts are not held to the pre-withdraw reading and only need to settle.
    full_wait_time = (MAX_WAIT_TIME + CRM_POLLING_INTERVAL * 100) * scale
    below = announced_route_counts if duthost.facts["asic_type"] != "vs" else None
    baseline = wait_crm_route_counts_settled(duthost, namespace, full_wait_time, settle_time, below=below)
    if baseline is None:
        if below is None:
            pytest.fail("CRM route counts did not settle within {} seconds".format(full_wait_time))
        pytest.fail("CRM route counts did not settle below the pre-withdraw counts ipv4 {} ipv6 {} "
                    "within {} seconds".format(below[0], below[1], full_wait_time))
    ipv4_route_used_before, ipv6_route_used_before = baseline
    logger.info("ipv4 route used {}".format(ipv4_route_used_before))
    logger.info("ipv6 route used {}".format(ipv6_route_used_before))

    yield {
        "announced": announced_route_counts,
        "withdrawn": (ipv4_route_used_before, ipv6_route_used_before),
    }


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
