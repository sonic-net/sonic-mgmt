"""
Check platform status after reboot. Three types of reboot are covered in this script:
* Cold reboot
* Fast reboot
* Warm reboot

This script is to cover the test case 'Reload configuration' in the SONiC platform test plan:
https://github.com/Azure/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import re
import time

from datetime import datetime

import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.utilities import wait_until
from tests.common.reboot import *
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.platform.interface_utils import check_all_interface_information, get_port_map
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

MAX_WAIT_TIME_FOR_INTERFACES = 300
MAX_WAIT_TIME_FOR_REBOOT_CAUSE = 120


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthosts, enum_rand_one_per_hwsku_hostname, conn_graph_facts, xcvr_skip_list):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    yield

    logging.info("Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    check_critical_processes(duthost, watch_secs=10)
    check_interfaces_and_services(duthost, interfaces, xcvr_skip_list)


def reboot_and_check(localhost, dut, interfaces, xcvr_skip_list, reboot_type=REBOOT_TYPE_COLD, reboot_helper=None, reboot_kwargs=None):
    """
    Perform the specified type of reboot and check platform status.
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    @param xcvr_skip_list: list of DUT's interfaces for which transeiver checks are skipped
    @param reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
    @param reboot_helper: The helper function used only by power off reboot
    @param reboot_kwargs: The argument used by reboot_helper
    """

    logging.info("Sync reboot cause history queue with DUT reboot cause history queue")
    sync_reboot_history_queue_with_dut(dut)

    logging.info("Run %s reboot on DUT" % reboot_type)
    reboot(dut, localhost, reboot_type=reboot_type, reboot_helper=reboot_helper, reboot_kwargs=reboot_kwargs)

    # Append the last reboot type to the queue
    logging.info("Append the latest reboot type to the queue")
    REBOOT_TYPE_HISTOYR_QUEUE.append(reboot_type)

    check_interfaces_and_services(dut, interfaces, xcvr_skip_list, reboot_type)


def check_interfaces_and_services(dut, interfaces, xcvr_skip_list, reboot_type = None):
    """
    Perform a further check after reboot-cause, including transceiver status, interface status
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    """
    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(dut)

    if reboot_type is not None:
        logging.info("Check reboot cause")
        assert wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, 30, check_reboot_cause, dut, reboot_type), \
            "got reboot-cause failed after rebooted by %s" % reboot_type

        if "201811" in dut.os_version or "201911" in dut.os_version:
            logging.info("Skip check reboot-cause history for version before 202012")
        else:
            logger.info("Check reboot-cause history")
            assert wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, 0, check_reboot_cause_history, dut,
                              REBOOT_TYPE_HISTOYR_QUEUE), "Check reboot-cause history failed after rebooted by %s" % reboot_type
        if reboot_ctrl_dict[reboot_type]["test_reboot_cause_only"]:
            logging.info("Further checking skipped for %s test which intends to verify reboot-cause only" % reboot_type)
            return

    if dut.is_supervisor_node():
        logging.info("skipping interfaces related check for supervisor")
    else:
        logging.info("Wait {} seconds for all the transceivers to be detected".format(MAX_WAIT_TIME_FOR_INTERFACES))
        result = wait_until(MAX_WAIT_TIME_FOR_INTERFACES, 20, 0, check_all_interface_information, dut, interfaces,
                            xcvr_skip_list)
        assert result, "Not all transceivers are detected or interfaces are up in {} seconds".format(
            MAX_WAIT_TIME_FOR_INTERFACES)

        logging.info("Check transceiver status")
        for asic_index in dut.get_frontend_asic_ids():
            # Get the interfaces pertaining to that asic
            interface_list = get_port_map(dut, asic_index)
            interfaces_per_asic = {k:v for k, v in interface_list.items() if k in interfaces}
            check_transceiver_basic(dut, asic_index, interfaces_per_asic, xcvr_skip_list)

        logging.info("Check pmon daemon status")
        assert check_pmon_daemon_status(dut), "Not all pmon daemons running."

    if dut.facts["asic_type"] in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)


def test_cold_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_COLD)


def test_soft_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to perform soft reboot and check platform status
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    soft_reboot_supported = duthost.command('which soft-reboot', module_ignore_errors=True)["stdout"]
    if "" == soft_reboot_supported:
        pytest.skip("Soft-reboot is not supported on this DUT, skip this test case")

    if duthost.is_multi_asic:
        pytest.skip("Multi-ASIC devices not supporting soft reboot")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_SOFT)


def test_fast_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to perform fast reboot and check platform status
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.is_multi_asic:
        pytest.skip("Multi-ASIC devices not supporting fast reboot")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_FAST)


def test_warm_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to perform warm reboot and check platform status
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if duthost.is_multi_asic:
        pytest.skip("Multi-ASIC devices not supporting warm reboot")

    asic_type = duthost.facts["asic_type"]

    if asic_type in ["mellanox"]:
        issu_capability = duthost.command("show platform mlnx issu")["stdout"]
        if "disabled" in issu_capability:
            pytest.skip("ISSU is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_WARM)


def _power_off_reboot_helper(kwargs):
    """
    @summary: used to parametrized test cases on power_off_delay
    @param kwargs: the delay time between turning off and on the PSU
    """
    pdu_ctrl = kwargs["pdu_ctrl"]
    all_outlets = kwargs["all_outlets"]
    power_on_seq = kwargs["power_on_seq"]
    delay_time = kwargs["delay_time"]

    for outlet in all_outlets:
        logging.debug("turning off {}".format(outlet))
        pdu_ctrl.turn_off_outlet(outlet)
    time.sleep(delay_time)
    logging.info("Power on {}".format(power_on_seq))
    for outlet in power_on_seq:
        logging.debug("turning on {}".format(outlet))
        pdu_ctrl.turn_on_outlet(outlet)


def test_power_off_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list, pdu_controller, power_off_delay):
    """
    @summary: This test case is to perform reboot via powercycle and check platform status
    @param duthost: Fixture for DUT AnsibleHost object
    @param localhost: Fixture for interacting with localhost through ansible
    @param conn_graph_facts: Fixture parse and return lab connection graph
    @param xcvr_skip_list: list of DUT's interfaces for which transeiver checks are skipped
    @param pdu_controller: The python object of psu controller
    @param power_off_delay: Pytest parameter. The delay between turning off and on the PSU
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    UNSUPPORTED_ASIC_TYPE = ["cisco-8000"]
    if duthost.facts["asic_type"] in UNSUPPORTED_ASIC_TYPE:
        pytest.skip("Skipping test_power_off_reboot. Test unsupported on {} platform".format(duthost.facts["asic_type"]))
    pdu_ctrl = pdu_controller
    if pdu_ctrl is None:
        pytest.skip("No PSU controller for %s, skip rest of the testing in this case" % duthost.hostname)

    all_outlets = pdu_ctrl.get_outlet_status()
    # If PDU supports returning output_watts, making sure that all outlets has power.
    no_power = [item for item in all_outlets if int(item.get('output_watts', '1')) == 0]
    pytest_assert(not no_power, "Not all outlets have power output: {}".format(no_power))

    # Purpose of this list is to control sequence of turning on PSUs in power off testing.
    # If there are 2 PSUs, then 3 scenarios would be covered:
    # 1. Turn off all PSUs, turn on PSU1, then check.
    # 2. Turn off all PSUs, turn on PSU2, then check.
    # 3. Turn off all PSUs, turn on one of the PSU, then turn on the other PSU, then check.
    power_on_seq_list = []
    if all_outlets:
        power_on_seq_list = [[item] for item in all_outlets]
        power_on_seq_list.append(all_outlets)

    logging.info("Got all power on sequences {}".format(power_on_seq_list))

    poweroff_reboot_kwargs = {"dut": duthost}

    try:
        for power_on_seq in power_on_seq_list:
            poweroff_reboot_kwargs["pdu_ctrl"] = pdu_ctrl
            poweroff_reboot_kwargs["all_outlets"] = all_outlets
            poweroff_reboot_kwargs["power_on_seq"] = power_on_seq
            poweroff_reboot_kwargs["delay_time"] = power_off_delay
            reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, REBOOT_TYPE_POWEROFF,
                             _power_off_reboot_helper, poweroff_reboot_kwargs)
    except Exception as e:
        logging.debug("Restore power after test failure")
        for outlet in all_outlets:
            logging.debug("turning on {}".format(outlet))
            pdu_ctrl.turn_on_outlet(outlet)
        # Sleep 120 for dut to boot up
        time.sleep(120)
        wait_critical_processes(duthost)
        raise e


def test_watchdog_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to perform reboot via watchdog and check platform status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    watchdogutil_status_result = duthost.command("watchdogutil status", module_ignore_errors=True)
    if "" != watchdogutil_status_result["stderr"] or "" == watchdogutil_status_result["stdout"]:
        pytest.skip("Watchdog is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, REBOOT_TYPE_WATCHDOG)


def test_continuous_reboot(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """
    @summary: This test case is to perform 3 cold reboot in a row
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ls_starting_out = set(duthost.shell("ls /dev/C0-*", module_ignore_errors=True)["stdout"].split())
    for i in range(3):
        reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_COLD)
    ls_ending_out = set(duthost.shell("ls /dev/C0-*", module_ignore_errors=True)["stdout"].split())
    pytest_assert(ls_ending_out == ls_starting_out,
            "Console devices have changed: expected console devices: {}, got: {}".format(", ".join(sorted(ls_starting_out)), ", ".join(sorted(ls_ending_out))))
