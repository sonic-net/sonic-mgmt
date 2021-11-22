"""
Tests the link flap in SONiC.
"""
import logging

import pytest
import random

from tests.platform_tests.link_flap.link_flap_utils import build_test_candidates, toggle_one_link, check_orch_cpu_utilization, check_bgp_routes, check_portchannel_status
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
]

LOOP_TIMES_LEVEL_MAP = {
    'debug': 1,
    'basic': 10,
    'confident': 50,
    'thorough': 100,
    'diagnose': 200
}


def get_port_list(duthost, tbinfo):
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    logging.info(mg_facts["minigraph_port_indices"].keys())
    return mg_facts["minigraph_port_indices"].keys()


@pytest.mark.platform('physical')
def test_link_flap(request, duthosts, rand_one_dut_hostname, tbinfo, fanouthosts, get_function_conpleteness_level):
    """
    Validates that link flap works as expected
    """
    duthost = duthosts[rand_one_dut_hostname]
    orch_cpu_threshold = request.config.getoption("--orch_cpu_threshold")

    # Record memory status at start
    memory_output = duthost.shell("show system-memory")["stdout"]
    logging.info("Memory Status at start: %s", memory_output)

    # Record Redis Memory at start
    start_time_redis_memory = duthost.shell("redis-cli info memory | grep used_memory_human | sed -e 's/.*:\(.*\)M/\\1/'")["stdout"]
    logging.info("Redis Memory: %s M", start_time_redis_memory)

     # Make Sure Orch CPU < orch_cpu_threshold before starting test.
    logging.info("Make Sure orchagent CPU utilization is less that %d before link flap", orch_cpu_threshold)
    pytest_assert(wait_until(100, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                "Orch CPU utilization {} > orch cpu threshold {} before link flap"
                .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"], orch_cpu_threshold))

    normalized_level = get_function_conpleteness_level
    if normalized_level is None:
        normalized_level = "debug"

    loop_times = LOOP_TIMES_LEVEL_MAP[normalized_level]

    port_lists = get_port_list(duthost, tbinfo)
    logging.info(port_lists)

    candidates = []
    for port in port_lists:
        candidate = build_test_candidates(duthost, fanouthosts, port, normalized_level)
        if candidate:
            candidates.append(candidates)

    for loop_time in range(0, loop_times):
        if loop_time == 0 or loop_time == loop_times - 1:
            watch = True
            check_status = True
        else:
            watch = False
            cheeck_status = False

        for dut_port, fanout, fanout_port in candidates:
            toggle_one_link(duthost, dut_port, fanout, fanout_port, watch=watch, check_status=check_status)

    # Record memory status at end
    memory_output = duthost.shell("show system-memory")["stdout"]
    logging.info("Memory Status at end: %s", memory_output)

    # Record orchagent CPU utilization at end
    orch_cpu = duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"]
    logging.info("Orchagent CPU Util at end: %s", orch_cpu)

    # Record Redis Memory at end
    end_time_redis_memory = duthost.shell("redis-cli info memory | grep used_memory_human | sed -e 's/.*:\(.*\)M/\\1/'")["stdout"]
    logging.info("Redis Memory at start: %s M", start_time_redis_memory)
    logging.info("Redis Memory at end: %s M", end_time_redis_memory)

    # Calculate diff in Redis memory
    incr_redis_memory = float(end_time_redis_memory) - float(start_time_redis_memory)
    logging.info("Redis absolute  difference: %d", incr_redis_memory)

    # Check redis memory only if it is increased else default to pass
    if incr_redis_memory > 0.0:
        percent_incr_redis_memory = (incr_redis_memory / float(start_time_redis_memory)) * 100
        logging.info("Redis Memory percentage Increase: %d", percent_incr_redis_memory)
        pytest_assert(percent_incr_redis_memory < 5, "Redis Memory Increase more than expected: {}".format(percent_incr_redis_memory))

    # Orchagent CPU should consume < orch_cpu_threshold at last.
    logging.info("watch orchagent CPU utilization when it goes below %d", orch_cpu_threshold)
    pytest_assert(wait_until(45, 2, 0, check_orch_cpu_utilization, duthost, orch_cpu_threshold),
                "Orch CPU utilization {} > orch cpu threshold {} before link flap"
                .format(duthost.shell("show processes cpu | grep orchagent | awk '{print $9}'")["stdout"], orch_cpu_threshold))

