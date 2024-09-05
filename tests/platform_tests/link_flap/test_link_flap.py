"""
Tests the link flap in SONiC.
"""
import logging
import pytest

from tests.platform_tests.link_flap.link_flap_utils import toggle_one_link, \
    check_orch_cpu_utilization, build_test_candidates
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]


def get_port_list(duthost, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    return list(mg_facts["minigraph_ports"].keys())


@pytest.mark.usefixtures("bgp_sessions_config")
def test_link_flap(request, duthosts, rand_one_dut_hostname, tbinfo, fanouthosts, get_loop_times):
    """
    Validates that link flap works as expected
    """
    duthost = duthosts[rand_one_dut_hostname]
    orch_cpu_threshold = request.config.getoption("--orch_cpu_threshold")

    # Record memory status at start
    memory_output = duthost.shell("show system-memory")["stdout"]
    logger.info("Memory Status at start: %s", memory_output)

    # Record Redis Memory at start
    start_time_redis_memory = duthost.shell(
        r"redis-cli info memory | grep used_memory_human | sed -e 's/.*:\(.*\)M/\1/'")["stdout"]
    logger.info("Redis Memory: %s M", start_time_redis_memory)

    # Make Sure Orch CPU < orch_cpu_threshold before starting test.
    logger.info("Make Sure orchagent CPU utilization is less that %d before link flap", orch_cpu_threshold)
    pytest_assert(wait_until(100, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                  "Orch CPU utilization {} > orch cpu threshold {} before link flap"
                  .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                          orch_cpu_threshold))

    loop_times = get_loop_times

    candidates = build_test_candidates(duthost, fanouthosts, 'all_ports')
    pytest_require(candidates, "Didn't find any port that is admin up and present in the connection graph")

    for loop_time in range(0, loop_times):
        watch = False
        check_status = False
        if loop_time == 0 or loop_time == loop_times - 1:
            watch = True
            check_status = True

        for dut_port, fanout, fanout_port in candidates:
            toggle_one_link(duthost, dut_port, fanout, fanout_port, watch=watch, check_status=check_status)

    # Record memory status at end
    memory_output = duthost.shell("show system-memory")["stdout"]
    logger.info("Memory Status at end: %s", memory_output)

    # Record orchagent CPU utilization at end
    orch_cpu = duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"]
    logger.info("Orchagent CPU Util at end: %s", orch_cpu)

    # Record Redis Memory at end
    end_time_redis_memory = duthost.shell(
        r"redis-cli info memory | grep used_memory_human | sed -e 's/.*:\(.*\)M/\1/'")["stdout"]
    logger.info("Redis Memory at start: %s M", start_time_redis_memory)
    logger.info("Redis Memory at end: %s M", end_time_redis_memory)

    # Calculate diff in Redis memory
    incr_redis_memory = float(end_time_redis_memory) - float(start_time_redis_memory)
    logger.info("Redis absolute  difference: %d", incr_redis_memory)

    # Check redis memory only if it is increased else default to pass
    if incr_redis_memory > 0.0:
        percent_incr_redis_memory = (incr_redis_memory / float(start_time_redis_memory)) * 100
        logger.info("Redis Memory percentage Increase: %d", percent_incr_redis_memory)
        incr_redis_memory_threshold = 10 if tbinfo["topo"]["type"] in ["m0", "mx"] else 5
        pytest_assert(percent_incr_redis_memory < incr_redis_memory_threshold,
                      "Redis Memory Increase more than expected: {}".format(percent_incr_redis_memory))

    # Orchagent CPU should consume < orch_cpu_threshold at last.
    logger.info("watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold)
    pytest_assert(wait_until(45, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                  "Orch CPU utilization {} > orch cpu threshold {} before link flap"
                  .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                          orch_cpu_threshold))
