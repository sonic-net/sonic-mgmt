"""
This test file is created for T2 chassis specific reboot test, need to skip for all T0/T1
"""
import pytest
import random
import logging
import time
from multiprocessing.pool import ThreadPool
import concurrent.futures
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.reboot import wait_for_startup, wait_for_shutdown,\
                                sync_reboot_history_queue_with_dut
from tests.platform_tests.test_reboot import check_interfaces_and_services


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t2')
]


def chassis_cold_reboot(dut, pool, localhost):
    logging.info(
        "Sync reboot cause history queue with T2 reboot cause history queue")
    sync_reboot_history_queue_with_dut(dut)

    def execute_reboot_command():
        logging.info("Run cold reboot on {}".format(dut))
        return dut.command("reboot")

    def wait_for_shutdown_command():
        logging.info("Wait for device to go down")
        wait_for_shutdown(dut, localhost, delay=10, timeout=300, reboot_res=None)
        return "shutdown success"

    pool.apply_async(execute_reboot_command)
    shutdown_res = pool.apply_async(wait_for_shutdown_command)

    # Append the last reboot type to the queue
    logging.info("Append the latest reboot type to the queue")
    dut.reboot_type_history_queue.append("cold")

    return shutdown_res


def get_core_dump(duthost):
    """
    This function get core dump on any of the linecards.
    Note that even we have core dump check pre/post testing, that check will not fail a test
    This check specifically fail the test if new core dump is found
    """
    if "20191130" in duthost.os_version:
        return duthost.shell('ls /var/core/ | grep -v python || true')['stdout'].split()
    else:
        return duthost.shell('ls /var/core/')['stdout'].split()


def test_parallel_reboot(duthosts, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to perform cold reboot on different linecards within 30 seconds,
    we consider it as parallel reboot.

    First, perform "parallel reboot" on all LCs, record initial dump files
    Then, make sure LCs are up and healthy
    Lastly, check if new core dumps are generated.

    We put the check in the end to make sure no core dump generated either
    during device down/up, or config initializing
    """

    core_dumps = {}
    # Perform reboot on multiple LCs within 30sec
    dut_reboot_res = {}
    pool = ThreadPool()
    for dut in duthosts.frontend_nodes:

        # collect core dump before reboot
        core_dumps[dut.hostname] = get_core_dump(dut)

        # Perform cold reboot on all linecards, with an internal within 30sec to mimic a parallel reboot scenario
        # Change this to threaded reboot, to avoid ansible command timeout in 60sec, we have seen some T2 platform
        # reboot exceed 60 sec, and causes test to error out
        shutdown_res = chassis_cold_reboot(dut, pool, localhost)
        dut_reboot_res[dut.hostname] = shutdown_res

        # Wait for 0 ~ 30sec
        rand_interval = random.randint(0, 30)
        time.sleep(rand_interval)

    logging.info("DEBUGGING - Wait for all reboots to complete")
    for hostname, result in dut_reboot_res.items():
        try:
            reboot_res = result.get(timeout=300)
            logging.info("Reboot and shutdown result: {} on {}".format(reboot_res, hostname))
        except Exception as e:
            logging.error("Reboot and shutdown failed on {} with exception: {}".format(hostname, e))

    # Make sure duts/critical/links/bgps are up
    for dut in duthosts:
        # 1. Make sure all LCs are up and links are up
        wait_for_startup(dut, localhost, delay=10, timeout=600)

        interfaces = conn_graph_facts.get("device_conn", {}).get(dut.hostname, {})
        check_interfaces_and_services(dut, interfaces, xcvr_skip_list)

        # 2. Verify sessions are established
        config_facts = dut.config_facts(host=dut.hostname, source="running")['ansible_facts']
        bgp_neighbors = config_facts.get('BGP_NEIGHBOR', {})
        pytest_assert(wait_until(30, 5, 0, dut.check_bgp_session_state, list(bgp_neighbors.keys())),
                      "Not all BGP sessions are established on DUT")

    # Check if new core dumps are generated
    for dut in duthosts.frontend_nodes:
        post_core_dump = get_core_dump(dut)
        new_core_dumps = (set(post_core_dump) - set(core_dumps[dut.hostname]))

        if new_core_dumps:
            pytest_assert(False, "New core dump found on  {} during reboot! {}".format(dut.hostname, new_core_dumps))
        else:
            logging.info("No new core dump found on  {} during reboot".format(dut.hostname))
