"""
Check platform status after reboot. Three types of reboot are covered in this script:
* Cold reboot
* Fast reboot
* Warm reboot

This script is to cover the test case 'Reload configuration' in the SONiC platform test plan:
https://github.com/sonic-net/SONiC/blob/master/doc/pmon/sonic_platform_test_plan.md
"""
import logging
import pytest

from tests.common.fixtures.conn_graph_facts import conn_graph_facts     # noqa F401
from tests.common.utilities import wait_until, get_plt_reboot_ctrl
from tests.common.reboot import sync_reboot_history_queue_with_dut, reboot, check_reboot_cause,\
    check_reboot_cause_history, reboot_ctrl_dict,\
    REBOOT_TYPE_HISTOYR_QUEUE, REBOOT_TYPE_COLD,\
    REBOOT_TYPE_SOFT, REBOOT_TYPE_FAST, REBOOT_TYPE_WARM, REBOOT_TYPE_WATCHDOG
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


@pytest.fixture
def set_max_time_for_interfaces(duthost):
    """
    For chassis testbeds, we need to specify plt_reboot_ctrl in inventory file,
    to let MAX_TIME_TO_REBOOT to be overwritten by specified timeout value
    """
    global MAX_WAIT_TIME_FOR_INTERFACES
    plt_reboot_ctrl = get_plt_reboot_ctrl(duthost, 'test_reboot.py', 'cold')
    if plt_reboot_ctrl:
        MAX_WAIT_TIME_FOR_INTERFACES = plt_reboot_ctrl.get('timeout', 300)


@pytest.fixture(scope="module", autouse=True)
def teardown_module(duthosts, enum_rand_one_per_hwsku_hostname, conn_graph_facts, xcvr_skip_list):      # noqa F811
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    yield

    logging.info(
        "Tearing down: to make sure all the critical services, interfaces and transceivers are good")
    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    check_critical_processes(duthost, watch_secs=10)
    check_interfaces_and_services(duthost, interfaces, xcvr_skip_list)


def reboot_and_check(localhost, dut, interfaces, xcvr_skip_list,
                     reboot_type=REBOOT_TYPE_COLD, reboot_helper=None, reboot_kwargs=None):
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

    logging.info(
        "Sync reboot cause history queue with DUT reboot cause history queue")
    sync_reboot_history_queue_with_dut(dut)

    logging.info("Run %s reboot on DUT" % reboot_type)
    reboot(dut, localhost, reboot_type=reboot_type,
           reboot_helper=reboot_helper, reboot_kwargs=reboot_kwargs)

    # Append the last reboot type to the queue
    logging.info("Append the latest reboot type to the queue")
    REBOOT_TYPE_HISTOYR_QUEUE.append(reboot_type)

    check_interfaces_and_services(dut, interfaces, xcvr_skip_list, reboot_type)


def check_interfaces_and_services(dut, interfaces, xcvr_skip_list,
                                  interfaces_wait_time=MAX_WAIT_TIME_FOR_INTERFACES, reboot_type=None):
    """
    Perform a further check after reboot-cause, including transceiver status, interface status
    @param localhost: The Localhost object.
    @param dut: The AnsibleHost object of DUT.
    @param interfaces: DUT's interfaces defined by minigraph
    """
    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(dut)

    if dut.is_supervisor_node():
        logging.info("skipping interfaces related check for supervisor")
    else:
        logging.info("Wait {} seconds for all the transceivers to be detected".format(
            interfaces_wait_time))
        result = wait_until(interfaces_wait_time, 20, 0, check_all_interface_information, dut, interfaces,
                            xcvr_skip_list)
        assert result, "Not all transceivers are detected or interfaces are up in {} seconds".format(
            interfaces_wait_time)

        logging.info("Check transceiver status")
        for asic_index in dut.get_frontend_asic_ids():
            # Get the interfaces pertaining to that asic
            interface_list = get_port_map(dut, asic_index)
            interfaces_per_asic = {k: v for k, v in list(
                interface_list.items()) if k in interfaces}
            check_transceiver_basic(
                dut, asic_index, interfaces_per_asic, xcvr_skip_list)

        logging.info("Check pmon daemon status")
        assert check_pmon_daemon_status(dut), "Not all pmon daemons running."

    if dut.facts["asic_type"] in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logging.info("Check the hw-management service")
        check_hw_management_service(dut)

        logging.info("Check sysfs")
        check_sysfs(dut)

    if reboot_type is not None:
        logging.info("Check reboot cause")
        assert wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, 30, check_reboot_cause, dut, reboot_type), \
            "got reboot-cause failed after rebooted by %s" % reboot_type

        if "201811" in dut.os_version or "201911" in dut.os_version:
            logging.info(
                "Skip check reboot-cause history for version before 202012")
        else:
            logging.info("Check reboot-cause history")
            assert wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, 0, check_reboot_cause_history, dut,
                              REBOOT_TYPE_HISTOYR_QUEUE), \
                "Check reboot-cause history failed after rebooted by %s" % reboot_type
        if reboot_ctrl_dict[reboot_type]["test_reboot_cause_only"]:
            logging.info(
                "Further checking skipped for %s test which intends to verify reboot-cause only" % reboot_type)
            return


def test_cold_reboot(duthosts, enum_rand_one_per_hwsku_hostname, set_max_time_for_interfaces,
                     localhost, conn_graph_facts, xcvr_skip_list):      # noqa F811
    """
    @summary: This test case is to perform cold reboot and check platform status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"]
                     [duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_COLD)


def test_soft_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
                     localhost, conn_graph_facts, xcvr_skip_list):      # noqa F811
    """
    @summary: This test case is to perform soft reboot and check platform status
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    soft_reboot_supported = duthost.command(
        'which soft-reboot', module_ignore_errors=True)["stdout"]
    if "" == soft_reboot_supported:
        pytest.skip(
            "Soft-reboot is not supported on this DUT, skip this test case")

    if duthost.is_multi_asic:
        pytest.skip("Multi-ASIC devices not supporting soft reboot")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"]
                     [duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_SOFT)


def test_fast_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
                     localhost, conn_graph_facts, xcvr_skip_list):      # noqa F811
    """
    @summary: This test case is to perform fast reboot and check platform status
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    sonic_hwsku = duthost.sonichost.facts["hwsku"]
    if "SN3800" in sonic_hwsku:
        pytest.skip("Not supported on Mellanox 3800")

    if duthost.is_multi_asic:
        pytest.skip("Multi-ASIC devices not supporting fast reboot")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"]
                     [duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_FAST)


def test_warm_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
                     localhost, conn_graph_facts, xcvr_skip_list):      # noqa F811
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
            pytest.skip(
                "ISSU is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"]
                     [duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_WARM)


def test_watchdog_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
                         localhost, conn_graph_facts, set_max_time_for_interfaces, xcvr_skip_list):      # noqa F811
    """
    @summary: This test case is to perform reboot via watchdog and check platform status
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    watchdogutil_status_result = duthost.command(
        "watchdogutil status", module_ignore_errors=True)
    if "" != watchdogutil_status_result["stderr"] or "" == watchdogutil_status_result["stdout"]:
        pytest.skip(
            "Watchdog is not supported on this DUT, skip this test case")

    reboot_and_check(localhost, duthost,
                     conn_graph_facts["device_conn"][duthost.hostname], xcvr_skip_list, REBOOT_TYPE_WATCHDOG)


def test_continuous_reboot(duthosts, enum_rand_one_per_hwsku_hostname,
                           localhost, conn_graph_facts, set_max_time_for_interfaces, xcvr_skip_list):        # noqa F811
    """
    @summary: This test case is to perform 3 cold reboot in a row
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    ls_starting_out = set(duthost.shell(
        "ls /dev/C0-*", module_ignore_errors=True)["stdout"].split())
    for i in range(3):
        reboot_and_check(localhost, duthost, conn_graph_facts["device_conn"]
                         [duthost.hostname], xcvr_skip_list, reboot_type=REBOOT_TYPE_COLD)
    ls_ending_out = set(duthost.shell(
        "ls /dev/C0-*", module_ignore_errors=True)["stdout"].split())
    pytest_assert(ls_ending_out == ls_starting_out,
                  "Console devices have changed: expected console devices: {}, got: {}"
                  .format(", ".join(sorted(ls_starting_out)), ", ".join(sorted(ls_ending_out))))
