"""
Test the Linux kernel dump mechanism.
"""
import logging
import time

import pytest

from pkg_resources import parse_version
from tests.common.fixtures.conn_graph_facts import conn_graph_facts
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.platform.transceiver_utils import check_transceiver_basic
from tests.common.platform.interface_utils import check_all_interface_information, get_port_map
from tests.common.platform.daemon_utils import check_pmon_daemon_status
from tests.common.platform.processes_utils import wait_critical_processes, check_critical_processes
from tests.common.reboot import *
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

MAX_WAIT_TIME_FOR_INTERFACES = 300
MAX_WAIT_TIME_FOR_REBOOT_CAUSE = 120

KDUMP_CORE_FILE_DIR = "/var/crash/"


@pytest.fixture(autouse=True, scope="module")
def check_image_version(duthost):
    """Skips this test if the SONiC image installed on DUT was 20191130 or older image version.

    Args:
        duthost: The AnsibleHost onject of DUT.

    Returns:
        None.
    """
    pytest_require(parse_version(duthost.kernel_version) > parse_version("4.9.0"),
                   "Test is not supported for 20191130 and older image versions!")


@pytest.fixture(scope="module", autouse=True)
def post_check(duthost, conn_graph_facts, xcvr_skip_list):
    """Post checks the BGP sessions and critical processes.

    Args:
        duthost: The fixture returns a list of duthost.
        conn_graph_facts: The fixture returns a dictionary which shows lab fanout switches
          physical and VLAN connections.
        xcvr_skip_list: The fixture returns list of DUT's interfaces for which
          transceiver checks are skipped.

    Returns:
        None.
    """
    duthost.shell("sudo chmod 666 /proc/sysrq-trigger")

    yield

    duthost.shell("sudo chmod 400 /proc/sysrq-trigger")

    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]
    duthost.check_bgp_session_state(up_bgp_neighbors, "established")

    logger.info("Post checking the critical processes, interfaces and transceivers ...")
    interfaces = conn_graph_facts["device_conn"][duthost.hostname]
    check_critical_processes_and_interfaces(duthost, interfaces, xcvr_skip_list)
    logger.info("Post checking the critical processes, interfaces and transceivers was done!")


def reboot_and_check_system_status(localhost, duthost, interfaces, xcvr_skip_list,
                                   reboot_type, reboot_helper=None, reboot_kwargs=None):
    """Performs the specified type of reboot and then checks platform status.

    Args:
        localhost: The Localhost object.
        duthost: The AnsibleHost object of DUT.
        interfaces: DUT's interfaces defined by minigraph.
        xcvr_skip_list: list of DUT's interfaces for which transceiver checks are skipped.
        reboot_type: The reboot type, pre-defined const that has name convention of REBOOT_TYPE_XXX.
        reboot_helper: The helper function used only by power off reboot.
        reboot_kwargs: The argument used by reboot_helper.

    Returns:
        None.
    """
    logger.info("Executing command '{}' on device '{}' ..."
                .format(reboot_ctrl_dict[reboot_type]["command"], duthost.hostname))
    reboot(duthost, localhost, reboot_type=reboot_type, reboot_helper=reboot_helper,
           reboot_kwargs=reboot_kwargs)
    logger.info("Command '{}' was executed on deivce '{}'."
                .format(reboot_ctrl_dict[reboot_type]["command"], duthost.hostname))

    check_critical_processes_and_interfaces(duthost, interfaces, xcvr_skip_list)


def check_critical_processes_and_interfaces(duthost, interfaces, xcvr_skip_list):
    """Checks the critical processes, transceiver and interface status after device was rebooted.

    Args:
        localhost: The Localhost object.
        duthost: The AnsibleHost object of DUT.
        interfaces: DUT's interfaces defined by minigraph.

    Returns:
        None.
    """
    logger.info("Waiting until all critical processes are started ...")
    wait_critical_processes(duthost)
    logger.info("All critical processes are started!")

    if not duthost.is_supervisor_node():
        logger.info("Checking the transceivers and interfaces status ...")
        pytest_assert(wait_until(MAX_WAIT_TIME_FOR_INTERFACES, 20, check_all_interface_information,
                      duthost, interfaces, xcvr_skip_list),
                      "some transceivers were not detected or some interfaces were not up")
        logger.info("Checking the transceivers and interfaces status was done!")

        logger.info("Checking transceiver information of all ports in CONFIG_DB ...")
        for asic_index in duthost.get_frontend_asic_ids():
            # Get the interfaces pertaining to that asic
            interface_list = get_port_map(duthost, asic_index)
            interfaces_per_asic = {k:v for k, v in interface_list.items() if k in interfaces}
            check_transceiver_basic(duthost, asic_index, interfaces_per_asic, xcvr_skip_list)
        logger.info("Checking transceiver information of all ports in CONFIG_DB was done!")

        logger.info("Checking daemon status in PMon ...")
        pytest_assert(check_pmon_daemon_status(duthost), "Not all pmon daemons running.")
        logger.info("Checking daemon status in PMon was done!")
    else:
        logger.info("Skip testing the supervisord node.")

    if duthost.facts["asic_type"] in ["mellanox"]:

        from .mellanox.check_hw_mgmt_service import check_hw_management_service
        from .mellanox.check_sysfs import check_sysfs

        logger.info("Checking the hw-management service ...")
        check_hw_management_service(duthost)
        logger.info("Checking the hw-management service was done!")

        logger.info("Checking sysfs ...")
        check_sysfs(duthost)
        logger.info("Checking sysfs was done!")


def is_kdump_enabled(duthost):
    """Checks whether the kdump mechanism was enabled or not on device.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        True if kdump was enabled, otherwise return False.
    """
    show_status = "sudo show kdump status"
    show_status_result = duthost.shell(show_status)
    exit_code = show_status_result["rc"]
    pytest_assert(exit_code == 0, "Failed to get status of kdump!")

    admin_mode_enabled = False
    oper_state_ready = False
    for line in show_status_result["stdout_lines"]:
        if "Administrative Mode" in line and "Enabled" in line:
            admin_mode_enabled = True
        if "Operational State" in line and "Ready" in line:
            oper_state_ready = True

    return admin_mode_enabled and oper_state_ready


def delete_stale_kdump_dirs(duthost):
    """Finds and deletes the stale kdump directories on the device.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """
    find_kdump_dir_cmd = "find {0} -type d -regextype grep -regex '{0}[[:digit:]]\+'" \
                         .format(KDUMP_CORE_FILE_DIR)
    find_kdump_dir_cmd_result = duthost.shell(find_kdump_dir_cmd)
    exit_code = find_kdump_dir_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to retrieve stale kdump directories!")

    if len(find_kdump_dir_cmd_result["stdout_lines"]) == 0:
        logger.info("None of stale kdump directories was found!")
    else:
        for line in find_kdump_dir_cmd_result["stdout_lines"]:
            logger.info("Found stale kdump directory: '{}'".format(line))
            delete_cmd_result = duthost.shell("sudo rm -rf {}".format(line.strip()))
            exit_code = delete_cmd_result["rc"]
            pytest_assert(exit_code == 0, "Failed to delete stale kdump directory '{}'!".format(line))
            logger.info("Stale kdump directory '{}' was being deleted ...".format(line))

        logger.info("Sleep 5 seconds such that the stale directories can be safely\
                    deleted from disk before kernel panic was triggered.")
        time.sleep(5)


def enable_kdump(duthost):
    """Enables the kdump mechanism on device.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        None.
    """

    logger.info("Enabling the kdump mechanism on device '{}' ...".format(duthost.hostname))

    enable_kdump_cmd = "sudo config kdump enable"
    enable_kdump_cmd_result = duthost.shell(enable_kdump_cmd)
    exit_code = enable_kdump_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to enable kdump mechanism on device '{}'!"
                  .format(duthost.hostname))

    logger.info("kdump mechanism was enabled on device '{}'.".format(duthost.hostname))


def check_generated_kdump_dir(duthost):
    """Checks whether the kdump directory was generated or not. This kdump directory was named
    by the timestamp and placed under the `/var/crash/`. Also checks whether kdump core
    file and demsg file were generated or not in this kdump directory.

    Args:
        duthost: The AnsibleHost object of DuT.

    Returns:
        The generated kdump directory path.
    """
    logger.info("Retrieving the generated kdump directory ...")
    find_kdump_dir_cmd = "find {0} -type d -regextype grep -regex '{0}[[:digit:]]\+'" \
                         .format(KDUMP_CORE_FILE_DIR)
    find_kdump_dir_cmd_result = duthost.shell(find_kdump_dir_cmd)
    exit_code = find_kdump_dir_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to retrieve generated kdump directories!")

    pytest_assert(len(find_kdump_dir_cmd_result["stdout_lines"]) == 1,
                  "Number of generated kdump directory should be one!")
    generated_kdump_dir_path = find_kdump_dir_cmd_result["stdout_lines"][0].strip()
    logger.info("Found the generated kdump directory '{}'.".format(generated_kdump_dir_path))

    logger.info("Retrieving the timestamp of kdump directory...")
    timestamp = generated_kdump_dir_path.split("/")[-1]
    logger.info("The timestamp is '{}'.".format(timestamp))

    kdump_core_file_path = generated_kdump_dir_path + "/kdump.{}".format(timestamp)
    logger.info("Checking whether kdump core file '{}' was generated or not ..."
                .format(kdump_core_file_path))
    check_file_existence_cmd = "sudo test -f {}".format(kdump_core_file_path)
    check_file_existence_cmd_result = duthost.shell(check_file_existence_cmd)
    exit_code = check_file_existence_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to find generated kdump core file!")
    logger.info("kdump core file '{}' was generated.".format(kdump_core_file_path))

    dmesg_file_path = generated_kdump_dir_path + "/dmesg.{}".format(timestamp)
    logger.info("Checking whether dmesg file '{}' was generated or not ..."
                .format(dmesg_file_path))
    check_file_existence_cmd = "sudo test -f {}".format(dmesg_file_path)
    check_file_existence_cmd_result = duthost.shell(check_file_existence_cmd)
    exit_code = check_file_existence_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to find generated dmesg file!")
    logger.info("dmesg file '{}' was generated.".format(dmesg_file_path))

    return generated_kdump_dir_path


def delete_generated_kdump_dir(duthost, generated_kdump_dir_path):
    """Deletes the newly generated kdump directory.

    Args:
        duthost: The AnsibleHost object of DuT.
        generated_kdump_dir_path: The absolute path shows the kdump directory.

    Returns:
        None.
    """

    logger.info("Deleting the generated kdump directory '{}' ..."
                .format(generated_kdump_dir_path))
    delete_dir_cmd_result = duthost.shell("sudo rm -rf {}".format(generated_kdump_dir_path))
    exit_code = delete_dir_cmd_result["rc"]
    if exit_code == 0:
        logger.info("The generated kdump directory '{}' was deleted."
                    .format(generated_kdump_dir_path))
    else:
        logger.info("Failed to delete the generated kdump directory '{}'!"
                    .format(generated_kdump_dir_path))


def test_kdump(duthosts, enum_rand_one_per_hwsku_hostname, localhost, conn_graph_facts, xcvr_skip_list):
    """Test the Linux kenrel dump mechanism.

    Args:
        duthost: The fixture returns a list of duthost.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
          a frontend DuT from testbed.
        localhost: The fixture returns localhost object.
        conn_graph_facts: The fixture returns a dictionary which shows lab fanout switches
          physical and VLAN connections.
        xcvr_skip_list: The fixture returns list of DUT's interfaces for which
          transceiver checks are skipped.

    Returns:
        None.
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    if is_kdump_enabled(duthost):
        logger.info("Kdump machanism on device was already enabled.")
        logger.info("Trying to delete stale kdump directories ...")
        delete_stale_kdump_dirs(duthost)
    else:
        enable_kdump(duthost)

        logger.info("Cold rebooting the device '{}' and loading the capture kernel ..."
                    .format(duthost.hostname))
        reboot_and_check_system_status(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname],
                                       xcvr_skip_list, REBOOT_TYPE_COLD)
        logger.info("Device '{}' was rebooted and capture kernel was loaded."
                    .format(duthost.hostname))

    reboot_and_check_system_status(localhost, duthost, conn_graph_facts["device_conn"][duthost.hostname],
                                   xcvr_skip_list, REBOOT_TYPE_KDUMP)

    logger.info("Checking the reboot cause ...")
    pytest_assert(wait_until(MAX_WAIT_TIME_FOR_REBOOT_CAUSE, 20, check_reboot_cause, duthost, REBOOT_TYPE_KDUMP),
                  "Failed to check reboot-cause after device was rebooted by command '{}'"
                  .format(reboot_ctrl_dict[REBOOT_TYPE_KDUMP]["command"]))
    logger.info("Checking the reboot cause was done!")

    generated_kdump_dir_path = check_generated_kdump_dir(duthost)
    delete_generated_kdump_dir(duthost, generated_kdump_dir_path)
