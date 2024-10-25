"""
This test file is created for T2 chassis specific reboot test, need to skip for all T0/T1
"""
import pytest
import random
import logging
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.reboot import wait_for_startup,\
                                sync_reboot_history_queue_with_dut,\
                                REBOOT_TYPE_HISTOYR_QUEUE
from tests.platform_tests.test_reboot import check_interfaces_and_services


pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('t2')
]


def chassis_cold_reboot(dut, localhost):
    logging.info(
        "Sync reboot cause history queue with T2 reboot cause history queue")
    sync_reboot_history_queue_with_dut(dut)

    logging.info("Run cold reboot on {}".format(dut))
    dut.command("reboot")

    # Append the last reboot type to the queue
    logging.info("Append the latest reboot type to the queue")
    REBOOT_TYPE_HISTOYR_QUEUE.append("cold")


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
    for dut in duthosts:
        if dut.is_supervisor_node():
            continue

        # collect core dump before reboot
        core_dumps[dut.hostname] = get_core_dump(dut)

        # Perform cold reboot on all linecards, with an internal within 30sec to mimic a parallel reboot scenario
        chassis_cold_reboot(dut, localhost)

        # Wait for 0 ~ 30sec
        rand_interval = random.randint(0, 30)
        time.sleep(rand_interval)

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
    for dut in duthosts:
        if dut.is_supervisor_node():
            continue
        post_core_dump = get_core_dump(dut)
        new_core_dumps = (set(post_core_dump) - set(core_dumps[dut.hostname]))

        if new_core_dumps:
            pytest_assert(False, "New core dump found on  {} during reboot! {}".format(dut.hostname, new_core_dumps))
        else:
            logging.info("No new core dump found on  {} during reboot".format(dut.hostname))
