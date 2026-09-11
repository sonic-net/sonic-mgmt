"""
Test case to perform cold reboot and check for PCIe Bus Errors in console logs and syslog.

This test verifies that no PCIe Bus Errors occur during the reboot process by:
1. Establishing a console connection before reboot
2. Performing a cold reboot
3. Collecting console logs during the reboot
4. Checking syslog after reboot
5. Asserting that "PCIe Bus Error" is not present in the console output or syslog
"""
import logging
import os
import pytest
import time
from multiprocessing.pool import ThreadPool

from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa: F401
from tests.common.reboot import REBOOT_TYPE_COLD, wait_for_shutdown, wait_for_startup, perform_reboot, reboot_ctrl_dict
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import create_duthost_console, creds_on_dut
from tests.common.fixtures.conn_graph_facts import get_graph_facts
from tests.common.platform.processes_utils import wait_critical_processes

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)


def try_create_dut_console(duthost, localhost, conn_graph_facts, creds):     # noqa: F811
    """
    Attempt to create a console connection to the DUT.

    @param duthost: The AnsibleHost object of DUT
    @param localhost: The Localhost object
    @param conn_graph_facts: Connection graph facts
    @param creds: Credentials for console connection
    @return: Console connection object or None
    """
    try:
        dut_console = create_duthost_console(duthost, localhost, conn_graph_facts, creds)
        logger.info("Successfully created DUT console connection")
        return dut_console
    except Exception as err:
        logger.warning("Failed to create DUT console: %s", err)
        return None


def collect_console_log(duthost, localhost):
    """
    Establish console connection and keep it active during reboot to collect logs.

    @param duthost: The AnsibleHost object of DUT
    @param localhost: The Localhost object
    @return: Console connection object or None
    """
    creds = creds_on_dut(duthost)
    conn_graph_facts = get_graph_facts(duthost, localhost, [duthost.hostname])     # noqa: F811
    dut_console = try_create_dut_console(duthost, localhost, conn_graph_facts, creds)

    if dut_console:
        logger.info("Console connection established for log collection")
        return dut_console
    else:
        logger.warning("Console connection not available, cannot collect logs")
        return None


def check_console_for_pcie_errors(console_output):
    """
    Check if PCIe Bus Error is present in console output.

    @param console_output: String containing console logs
    @return: List of lines containing PCIe Bus Error (empty list if none found)
    """
    if not console_output:
        logger.warning("No console output available to check")
        return []

    logger.info("Checking console output for PCIe Bus Errors")

    # Split console output and extract all lines with PCIe Bus Error
    lines = console_output.splitlines()
    error_lines = [line for line in lines if "PCIe Bus Error" in line]
    return error_lines


def check_syslog_for_pcie_errors(duthost, reboot_time):
    """
    Check syslog for PCIe Bus Errors since the reboot was initiated.
    Syslog persists across reboots, capturing kernel messages from the going-down phase.

    @param duthost: The AnsibleHost object of DUT
    @param reboot_time: time.struct_time captured from DUT before reboot
    @return: List of lines containing PCIe Bus Error (empty list if none found)
    """
    remote_syslog = "/var/log/syslog"
    local_syslog = "/tmp/syslog_%s" % duthost.hostname
    logger.info("Checking %s for PCIe Bus Errors", remote_syslog)
    try:
        duthost.fetch(src=remote_syslog, dest=local_syslog, flat=True)
    except Exception as err:
        pytest_assert(False, "Failed to fetch syslog from DUT: %s" % err)

    lines = []
    try:
        with open(local_syslog) as f:
            lines = f.readlines()
    except Exception as err:
        pytest_assert(False, "Failed to read local syslog: %s" % err)
    finally:
        try:
            os.remove(local_syslog)
        except OSError as err:
            logger.warning("Failed to clean up local syslog: %s", err)

    # Filter lines with PCIe Bus Error at or after reboot time
    # Syslog timestamp format: "2026 Apr  8 21:36:10.027574 sonic ..."
    error_lines = []
    for line in lines:
        if "PCIe Bus Error" not in line:
            continue
        try:
            timestamp_str = ' '.join(line.split()[:4])
            timestamp_str = timestamp_str.split('.')[0]
            line_dt = time.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
            if line_dt >= reboot_time:
                error_lines.append(line.strip())
        except ValueError:
            # If timestamp parsing fails, include the line to be safe
            error_lines.append(line.strip())

    return error_lines


def test_cold_reboot_pcie_check(duthosts, enum_rand_one_per_hwsku_hostname,
                                localhost, conn_graph_facts):      # noqa: F811
    """
    Test case to perform cold reboot and verify no PCIe Bus Errors occur.

    @param duthosts: Fixture for DUT hosts
    @param enum_rand_one_per_hwsku_hostname: Fixture to select one DUT
    @param localhost: The Localhost object
    @param conn_graph_facts: Connection graph facts fixture
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    hostname = duthost.hostname

    pool = ThreadPool()
    reboot_ctrl = reboot_ctrl_dict[REBOOT_TYPE_COLD]
    timeout = reboot_ctrl['timeout']
    if duthost.get_facts().get("modular_chassis"):
        timeout = max(timeout, 420)

    logger.info("Establishing console connection before reboot")
    console_wait_time = 5
    console_thread_res = pool.apply_async(collect_console_log, args=(duthost, localhost))
    time.sleep(console_wait_time)

    try:
        dut_console = console_thread_res.get()
    except Exception as console_err:
        logger.warning('Failed to get console thread result: %s', console_err)
        dut_console = None

    if not dut_console:
        pytest.skip("Skipping the test as console connection is not available")

    reboot_res = None
    try:
        dut_reboot_time = duthost.command("date +'%Y-%m-%d %H:%M:%S'")["stdout"].strip()
        logger.info("DUT time before reboot: %s", dut_reboot_time)
        dut_reboot_time = time.strptime(dut_reboot_time, "%Y-%m-%d %H:%M:%S")

        logger.info("Performing cold reboot on %s", hostname)
        reboot_res, dut_datetime = perform_reboot(duthost, pool, reboot_ctrl['command'], reboot_type=REBOOT_TYPE_COLD)

        logger.info("Waiting for %s to shutdown", hostname)
        wait_for_shutdown(duthost, localhost, delay=10, timeout=timeout, reboot_res=reboot_res)

        logger.info("Waiting for %s to startup", hostname)
        wait_for_startup(duthost, localhost, delay=10, timeout=timeout)

        wait_critical_processes(duthost)

        try:
            console_output = dut_console.read_channel()
            console_error_lines = check_console_for_pcie_errors(console_output)
            if console_error_lines:
                logger.error("PCIe Bus Error detected in console output!")
                pytest_assert(
                    False,
                    "PCIe Bus Error detected in console during cold reboot!\n"
                    "Error details:\n%s" % '\n'.join(console_error_lines))
            else:
                logger.info("No PCIe Bus Error found in console output")
        except Exception as console_err:
            pytest_assert(False, "Failed to read console log: %s" % console_err)

        syslog_error_lines = check_syslog_for_pcie_errors(duthost, dut_reboot_time)
        if syslog_error_lines:
            logger.error("PCIe Bus Error detected in syslog!")
            pytest_assert(
                False,
                "PCIe Bus Error detected in syslog during cold reboot!\n"
                "Error details:\n%s" % '\n'.join(syslog_error_lines))
        else:
            logger.info("No PCIe Bus Error found in syslog")
    finally:
        dut_console.disconnect()
        pool.terminate()
