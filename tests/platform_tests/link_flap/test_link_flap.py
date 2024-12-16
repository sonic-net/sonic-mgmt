"""
Tests the link flap in SONiC.
"""
import logging
import pytest

from tests.platform_tests.link_flap.link_flap_utils import check_orch_cpu_utilization, build_test_candidates, \
    get_avg_redis_mem_usage, validate_redis_memory_increase
from tests.common.platform.device_utils import toggle_one_link
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
    start_time_redis_memory = get_avg_redis_mem_usage(duthost, 5, 5)
    logging.info("Redis Memory: %f M", start_time_redis_memory)

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
    end_time_redis_memory = get_avg_redis_mem_usage(duthost, 5, 5)
    logging.info("Redis Memory at start: %f M", start_time_redis_memory)
    logging.info("Redis Memory at end: %f M", end_time_redis_memory)

    result = validate_redis_memory_increase(tbinfo, start_time_redis_memory, end_time_redis_memory)
    pytest_assert(result, "Redis Memory increases more than expected: start {}, end {}"
                  .format(start_time_redis_memory, end_time_redis_memory))

    # Orchagent CPU should consume < orch_cpu_threshold at last.
    logger.info("watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold)
    pytest_assert(wait_until(120, 5, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                  "Orch CPU utilization {} > orch cpu threshold {} before link flap"
                  .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"],
                          orch_cpu_threshold))
