"""
Helper script for DPU  operations
"""
import logging
import pytest
import re
from tests.common.platform.device_utils import platform_api_conn  # noqa: F401,F403
from tests.common.helpers.platform_api import chassis, module
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.platform.interface_utils \
     import check_interface_status_of_up_ports
from tests.common.reboot import wait_for_startup
from tests.common.platform.processes_utils import wait_critical_processes

# Timeouts, Delays and Time Intervals in secs
DPU_TIMEOUT = 210
DPU_TIME_INT = 30
PING_MAX_TIMEOUT = 180
PING_MAX_TIME_INT = 60
SWITCH_MAX_DELAY = 100
SWITCH_MAX_TIMEOUT = 400
INTF_MAX_TIMEOUT = 300
INTF_TIME_INT = 5
DPU_MAX_TIMEOUT = 360
DPU_MAX_TIME_INT = 30
REBOOT_CAUSE_TIMEOUT = 30
REBOOT_CAUSE_INT = 10
PING_TIMEOUT = 30
PING_TIME_INT = 10


@pytest.fixture(scope='function')
def num_dpu_modules(platform_api_conn):   # noqa F811
    """
    Returns the number of DPU modules
    """

    num_modules = int(chassis.get_num_modules(platform_api_conn))
    logging.info("Num of modules: '{}'".format(num_modules))

    return num_modules


@pytest.fixture(scope='function', autouse=True)
def check_smartswitch_and_dark_mode(duthosts, enum_rand_one_per_hwsku_hostname,
                                    platform_api_conn, num_dpu_modules):  # noqa F811
    """
    Checks whether given testbed is running
    202405 image or below versions
    If True, then skip the script
    else checks if dpus are in darkmode
    If dpus are in dark mode, then power up the DPUs
    else, proceeds to run all test cases
    """

    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    if "DPUS" not in duthost.facts:
        pytest.skip("Test is not supported for this testbed")

    darkmode = is_dark_mode_enabled(duthost, platform_api_conn, num_dpu_modules) # noqa F811

    if darkmode:
        dpu_power_on(duthost, platform_api_conn, num_dpu_modules)


def is_dark_mode_enabled(duthost, platform_api_conn, num_dpu_modules):   # noqa F811
    """
    Checks the liveliness of DPU
    Returns:
        True if all DPUs admin status are down
        else False
    """

    count_admin_down = 0

    for index in range(num_dpu_modules):
        dpu = module.get_name(platform_api_conn, index)
        output_config_db = duthost.command(
                           'redis-cli -p 6379 -h 127.0.0.1 \
                            -n 4 hgetall "CHASSIS_MODULE|{}"'.format(dpu))
        if output_config_db['stdout'] is None:
            logging.warning("redis cli output for chassis module state is empty")
            break
        if 'down' in output_config_db['stdout']:
            count_admin_down += 1

    if count_admin_down == num_dpu_modules:
        logging.info("Smartswitch is in dark mode")
        return True

    logging.info("Smartswitch is in non-dark mode")
    return False


def dpu_power_on(duthost, platform_api_conn, num_dpu_modules):    # noqa F811
    """
    Executes power on all DPUs
    Returns:
        Returns True or False based on all DPUs powered on or not
    """

    ip_address_list = []

    for index in range(num_dpu_modules):
        dpu = module.get_name(platform_api_conn, index)
        ip_address_list.append(
                module.get_midplane_ip(platform_api_conn, index))
        duthost.shell("sudo config chassis modules startup %s" % (dpu))

    pytest_assert(wait_until(PING_MAX_TIMEOUT, PING_MAX_TIME_INT, 0,
                  check_dpu_ping_status,
                  duthost, ip_address_list),
                  "Not all DPUs are operationally up")


def check_dpu_ping_status(duthost, ip_address_list):
    """
    Executes ping to all DPUs
    Args:
        duthost : Host handle
        ip_address_list (list): List of all DPU ip addresses
    Returns:
        Returns True or False based on Ping is successfull or not to all DPUs
    """

    ping_count = 0
    for ip_address in ip_address_list:
        output_ping = duthost.command("ping -c 3 %s" % (ip_address))
        logging.info("Ping output: '{}'".format(output_ping))
        if "0% packet loss" in output_ping["stdout"]:
            ping_count += 1
        else:
            logging.error("Ping failed for '{}'".format(ip_address))

    return ping_count == len(ip_address_list)


def check_dpu_module_status(duthost, power_status, dpu_name):
    """
    Check status of given DPU module against given option on/off
    Args:
        duthost : Host handle
        power_status: on/off status of dpu
        dpu_name: name of the dpu module
    Returns:
        Returns True or False based on status of given DPU module
    """

    output_dpu_status = duthost.shell(
            'show chassis module status | grep %s' % (dpu_name))

    if "offline" in output_dpu_status["stdout"].lower():
        logging.info("'{}' is offline ...".format(dpu_name))
        if power_status == "off":
            return True
        else:
            return False
    else:
        logging.info("'{}' is online ...".format(dpu_name))
        if power_status == "on":
            return True
        else:
            return False


def check_dpu_reboot_cause(duthost, dpu_name, reason):
    """
    Check reboot cause of all DPU modules
    Args:
        duthost : Host handle
        dpu_name: name of the dpu module
        reason: check against the reason for reboot
    Returns:
        Returns True or False based on reboot cause of all DPU modules
    """

    output_reboot_cause = duthost.shell(
            'show reboot-cause all | grep %s' % (dpu_name))

    output_str = output_reboot_cause["stdout"]
    if reason in output_str.strip():
        logging.info("'{}' - reboot cause is {} as expected".format(dpu_name,
                                                                    reason))
        return True

    logging.error("'{}' - reboot cause is not {}".format(dpu_name,
                                                         reason))
    return False


def check_pmon_status(duthost):
    """
    Check the status of PMON Container
    Args:
        duthost : Host handle
    Returns:
        Returns True or False based on pmon status
    """
    output_pmon_status = duthost.shell('docker ps | grep pmon')
    if "up" in output_pmon_status['stdout'].lower():
        logging.info("pmon container is up")
        return True

    logging.error("pmon container is not up")
    return False


def parse_dpu_memory_usage(dpu_memory):
    """
    Parse the DPU memory output and returns memory usuage value
    Args:
        dpu_memory : output of show system-memory on DPU
    Returns:
        Returns the memory used as percentage value
    """

    # Regular expression pattern to extract the total and used values
    pattern = r"Mem:\s+(\d+)\s+(\d+)\s+"

    # Search for the pattern in the data
    match = re.search(pattern, dpu_memory)

    if match:
        total_mem = int(match.group(1))
        used_mem = int(match.group(2))
    else:
        print("Memory information not found.")
        return 0

    return int(used_mem/total_mem * 100)


def parse_system_health_summary(output_health_summary):
    """
    Parse the show system health summary cli output
    Checks for HW, Service and SW status are OK
    and returns True/False
    Args:
        output_health_summary : output of show system-health summary
                                on Switch and DPU
    Returns:
        Returns True or False
    """
    # Regex to find all status names and values
    status_data = re.findall(r"(\w+):\s+Status:\s+(\w+)",
                             output_health_summary)

    status_dict = {name: status for name, status in status_data}

    # Check if all statuses are "OK"
    result = all(status == "OK" for status in status_dict.values())

    return result


def check_dpu_link_and_status(duthost, dpu_on_list,
                              dpu_off_list, ip_address_list):
    """
    Checks whether the intended DPUs are ON/OFF
    and their connectivity
    Args:
        duthost: Host handle
        dpu_on_list: List of dpu names that are On
        dpu_off_list: List of dpu names that are Off
        ip_address_list: List of dpu ip address which
                         are on
    """

    for index in range(len(dpu_on_list)):
        pytest_assert(wait_until(DPU_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_on_list[index]),
                      "DPU is not operationally up")

    for index in range(len(dpu_off_list)):
        pytest_assert(wait_until(DPU_TIMEOUT, DPU_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "off", dpu_off_list[index]),
                      "DPU is not operationally down")

    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to DPU has failed")


def get_dpu_link_status(duthost, num_dpu_modules,
                        platform_api_conn):  # noqa F811
    """
    Checks whether DPU status is ON/OFF and store it.
    Args:
       duthost: Host handle
       num_dpu_modules: Gets number of DPU modules
    Returns:
       Returns ip_address_list, dpu_on_list and dpu_off_list
    """

    ip_address_list = []
    dpu_on_list = []
    dpu_off_list = []

    for index in range(num_dpu_modules):
        dpu_name = module.get_name(platform_api_conn, index)
        ip_address = module.get_midplane_ip(platform_api_conn, index)
        rc = check_dpu_module_status(duthost, "on", dpu_name)
        if rc:
            dpu_on_list.append(dpu_name)
            ip_address_list.append(ip_address)
        else:
            dpu_off_list.append(dpu_name)
            continue

    return ip_address_list, dpu_on_list, dpu_off_list


def check_dpu_health_status(duthost, dpu_name,
                            expected_oper_status,
                            expected_state_value):
    """
    Parse, checks and asserts expected system-health of DPU.
    Args:
       duthost: Host handle
       dpu_name: Name of the DPU
       expected_oper_status: (Online/Offline)
       expected_oper_value: (up/down)
    Returns:
       Returns Nothing
    """
    logging.info(f"Checking system-health status of {dpu_name}")
    output_dpu_health_status = duthost.show_and_parse(f"show system-health dpu {dpu_name}")
    for status in output_dpu_health_status:
        if status['name'] == dpu_name:
            pytest_assert(expected_oper_status.lower() in status['oper-status'].lower(),
                          f"DPU status is not {expected_oper_status}")
            if status['state-detail'] == "dpu_midplane_link_state":
                pytest_assert(status['state-value'].lower() == expected_state_value,
                              f"midplane link state is not {expected_state_value}")
            if 'online' in expected_oper_status.lower():
                if status['state-detail'] == "dpu_control_plane_state":
                    pytest_assert(status['state-value'].lower() == expected_state_value,
                                  f"control plane state is not {expected_state_value}")
                if status['state-detail'] == "dpu_data_plane_state":
                    pytest_assert(status['state-value'].lower() == expected_state_value,
                                  f"data plane state is not {expected_state_value}")
    return


def check_dpu_critical_processes(dpuhosts, dpu_number):

    """
    Checks all critical processes are up on DPU
    If not, fails the case
    Args:
       dpuhosts: DPU Host handle
       num_dpu_modules: Gets number of DPU modules
    Returns:
       Nothing
    """

    cmd = "sudo show system-health detail"
    output_dpu_process = dpuhosts[dpu_number].show_and_parse(cmd)

    for index in range(len(output_dpu_process)):
        parse_output = output_dpu_process[index]
        pytest_assert(parse_output['status'].lower() == 'ok',
                      f"{parse_output['name']} not Ok in DPU{dpu_number}")

    return


def pre_test_check(duthost,
                   platform_api_conn,  # noqa F811
                   num_dpu_modules):
    """
    Collects and checks DPU status on Pre Test
    Args:
       duthost: Host handle
       num_dpu_modules: Gets number of DPU modules
    Returns:
       dpu_on_list: List of DPUs that are ON
       dpu_off_list: List of DPUs that are OFF
       ip_address_list: List of DPU IP address that are ON
    """

    logging.info("Getting DPU On/Off list and IP address list")
    ip_address_list, dpu_on_list, dpu_off_list = get_dpu_link_status(
                                                 duthost, num_dpu_modules,
                                                 platform_api_conn)

    logging.info("Checking DPU connectivity before the operation")
    pytest_assert(wait_until(PING_TIMEOUT, PING_TIME_INT, 0,
                  check_dpu_ping_status, duthost, ip_address_list),
                  "Error: Not all DPUs are pingable on Pre Check")

    return ip_address_list, dpu_on_list, dpu_off_list


def post_test_switch_check(duthost, localhost,
                           dpu_on_list, dpu_off_list,
                           ip_address_list):
    """
    Checks Switch, Interface and DPU status Post Test
    Fails the test based if it is not same as Pre test
    Args:
       duthost: Host handle
       dpu_on_list: List of DPUs that are ON
       dpu_off_list: List of DPUs that are OFF
       ip_address_list: List of DPU IP address that are ON
    Returns:
       Returns Nothing
    """

    logging.info("Waiting for ssh connection to switch")
    wait_for_startup(duthost, localhost, SWITCH_MAX_DELAY, SWITCH_MAX_TIMEOUT)

    logging.info("Checking for Interface status")
    pytest_assert(wait_until(INTF_MAX_TIMEOUT, INTF_TIME_INT, 0,
                  check_interface_status_of_up_ports, duthost),
                  "Not all ports that are admin up, are operationally up")
    logging.info("Interfaces are up")

    logging.info("Wait until all critical services are fully started")
    wait_critical_processes(duthost)

    logging.info("Checking DPU link status and connectivity")
    check_dpu_link_and_status(duthost, dpu_on_list,
                              dpu_off_list, ip_address_list)

    return


def post_test_dpu_check(duthost, dpuhosts,
                        dpu_on_list, dpu_off_list,
                        ip_address_list):
    """
    Checks DPU off/on and reboot cause status Post Test
    Args:
       duthost: Host handle
       dpuhosts: DPU Host handle
       dpu_on_list: List of DPUs that are ON
       dpu_off_list: List of DPUs that are OFF
       ip_address_list: List of DPU IP address that are ON
    Returns:
       Returns Nothing
    """

    for index in range(len(dpu_on_list)):
        logging.info(
            "Checking %s is up post test" % (dpu_on_list[index])
            )

        pytest_assert(wait_until(DPU_MAX_TIMEOUT, DPU_MAX_TIME_INT, 0,
                      check_dpu_module_status,
                      duthost, "on", dpu_on_list[index]),
                      "DPU is not operationally up post the operation")

        dpu_number = int(re.search(r'\d+', dpu_on_list[index]).group())
        logging.info("Checking crictical processes \
                      on %s" % (dpu_on_list[index]))
        wait_until(DPU_MAX_TIMEOUT, DPU_MAX_TIME_INT, 0,
                   check_dpu_critical_processes,
                   dpuhosts, dpu_number)

        logging.info("Checking reboot cause of %s" % (dpu_on_list[index]))
        pytest_assert(wait_until(REBOOT_CAUSE_TIMEOUT, REBOOT_CAUSE_INT, 0,
                      check_dpu_reboot_cause,
                      duthost, dpu_on_list[index], "Non-Hardware"),
                      "Reboot cause is not correct")

    logging.info("Checking all powered on DPUs connectivity")
    ping_status = check_dpu_ping_status(duthost, ip_address_list)
    pytest_assert(ping_status == 1, "Ping to one or more DPUs has failed")

    return
