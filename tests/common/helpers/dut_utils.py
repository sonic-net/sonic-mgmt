import logging
import allure
import os
import jinja2
import glob
import re
import yaml
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_host_visible_vars
from tests.common.utilities import wait_until
from tests.common.errors import RunAnsibleModuleFail
from collections import defaultdict
from tests.common.connections.console_host import ConsoleHost
from tests.common.utilities import get_dut_current_passwd
from tests.common.connections.base_console_conn import (
    CONSOLE_SSH_CISCO_CONFIG,
    CONSOLE_SSH_DIGI_CONFIG,
    CONSOLE_SSH_SONIC_CONFIG
)
import time

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_RESTART_THRESHOLD_SECS = 180

# Ansible config files
LAB_CONNECTION_GRAPH_PATH = os.path.normpath((os.path.join(os.path.dirname(__file__), "../../../ansible/files")))

BASI_PATH = os.path.dirname(os.path.abspath(__file__))


logger = logging.getLogger(__name__)


def is_supervisor_node(inv_files, hostname):
    """Check if the current node is a supervisor node in case of multi-DUT.
     @param inv_files: List of inventory file paths, In tests,
            you can be get it from get_inventory_files in tests.common.utilities
     @param hostname: hostname as defined in the inventory
    Returns:
          Currently, we are using 'card_type' in the inventory to make the decision.
          If 'card_type' for the node is defined in the inventory, and it is 'supervisor',
          then return True, else return False. In future, we can change this
          logic if possible to derive it from the DUT.
    """
    dut_vars = get_host_visible_vars(inv_files, hostname)
    if dut_vars and 'card_type' in dut_vars and dut_vars['card_type'] == 'supervisor':
        return True
    return False


def is_frontend_node(inv_files, hostname):
    """Check if the current node is a frontend node in case of multi-DUT.
     @param inv_files: List of inventory file paths, In tests,
            you can be get it from get_inventory_files in tests.common.utilities
     @param hostname: hostname as defined in the inventory
     Returns:
          True if it is not any other type of node.
          Currently, the only other type of node supported is 'supervisor' node.
          If we add more types of nodes, then we need to exclude them from this method as well.
    """
    return not is_supervisor_node(inv_files, hostname)


def is_macsec_capable_node(inv_files, hostname):
    dut_vars = get_host_visible_vars(inv_files, hostname)
    if dut_vars and 'macsec_card' in dut_vars and dut_vars['macsec_card']:
        return True
    return False


def is_container_running(duthost, container_name):
    """Decides whether the container is running or not
    @param duthost: Host DUT.
    @param container_name: Name of a container.
    Returns:
        Boolean value. True represents the container is running
    """
    running_containers = duthost.shell(r"docker ps -f 'status=running' --format \{\{.Names\}\}")['stdout_lines']
    return container_name in running_containers


def check_container_state(duthost, container_name, should_be_running):
    """Determines whether a container is in the expected state (running/not running)
    @param duthost: Host DUT.
    @param container_name: Name of container.
    @param should_be_running: Boolean value.
    Returns:
        This function will return True if the container was in the expected state.
        Otherwise, it will return False.
    """
    is_running = is_container_running(duthost, container_name)
    return is_running == should_be_running


def is_hitting_start_limit(duthost, container_name):
    """Checks whether the container can not be restarted is due to start-limit-hit.
    @param duthost: Host DUT.
    @param ontainer_name: name of a container.
    Returns:
        If start limitation was hit, then this function will return True. Otherwise
        it returns False.
    """
    service_status = duthost.shell("sudo systemctl status {}.service | grep 'Active'".format(container_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False


def clear_failed_flag_and_restart(duthost, container_name):
    """Clears the failed flag of a container and restart it.
    @param duthost: Host DUT.
    @param container_name: name of a container.
    Returns:
        None
    """
    logger.info("{} hits start limit and clear reset-failed flag".format(container_name))
    duthost.shell("sudo systemctl reset-failed {}.service".format(container_name))
    duthost.shell("sudo systemctl start {}.service".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                           CONTAINER_CHECK_INTERVAL_SECS,
                           0,
                           check_container_state, duthost, container_name, True)
    pytest_assert(restarted, "Failed to restart container '{}' after reset-failed was cleared".format(container_name))


def get_group_program_info(duthost, container_name, group_name):
    """Gets program names, running status and their pids by analyzing the command
       output of "docker exec <container_name> supervisorctl status". Program name
       at here represents a program which is part of group <group_name>

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.

    Returns:
        A dictionary where keys are the program names and values are their running
        status and pids.
    """
    group_program_info = defaultdict(list)
    program_name = None
    program_status = None
    program_pid = None

    program_list = duthost.shell("docker exec {} supervisorctl status"
                                 .format(container_name), module_ignore_errors=True)
    for program_info in program_list["stdout_lines"]:
        if program_info.find(group_name) != -1:
            program_name = program_info.split()[0].split(':')[1].strip()
            program_status = program_info.split()[1].strip()
            if program_status in ["EXITED", "STOPPED", "STARTING"]:
                program_pid = -1
            else:
                program_pid = int(program_info.split()[3].strip(','))

            group_program_info[program_name].append(program_status)
            group_program_info[program_name].append(program_pid)

            if program_pid != -1:
                logger.info("Found program '{}' in the '{}' state with pid {}"
                            .format(program_name, program_status, program_pid))

    return group_program_info


def get_program_info(duthost, container_name, program_name):
    """Gets program running status and its pid by analyzing the command
       output of "docker exec <container_name> supervisorctl status"

    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.

    Return:
        Program running status and its pid.
    """
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl status"
                                 .format(container_name), module_ignore_errors=True)
    for program_info in program_list["stdout_lines"]:
        if program_info.find(program_name) != -1:
            program_status = program_info.split()[1].strip()
            if program_status == "RUNNING":
                program_pid = int(program_info.split()[3].strip(','))
            break

    if program_pid != -1:
        logger.info("Found program '{}' in the '{}' state with pid {}"
                    .format(program_name, program_status, program_pid))

    return program_status, program_pid


def kill_process_by_pid(duthost, container_name, program_name, program_pid):
    """
    @summary: Kill a process in the specified container by its pid
    """
    kill_cmd_result = duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid))

    # Get the exit code of 'kill' command
    exit_code = kill_cmd_result["rc"]
    pytest_assert(exit_code == 0, "Failed to stop program '{}' before test".format(program_name))

    logger.info("Program '{}' in container '{}' was stopped successfully"
                .format(program_name, container_name))


def get_disabled_container_list(duthost):
    """Gets the container/service names which are disabled.

    Args:
        duthost: Host DUT.

    Return:
        A list includes the names of disabled containers/services
    """
    disabled_containers = []

    container_status, succeeded = duthost.get_feature_status()
    pytest_assert(succeeded, "Failed to get status ('enabled'|'disabled') of containers. Exiting...")

    for container_name, status in list(container_status.items()):
        if "disabled" in status:
            disabled_containers.append(container_name)

    return disabled_containers


def check_link_status(duthost, iface_list, expect_status):
    """
    check if the link status specified in the iface_list equal to expect status
    :param duthost: dut host object
    :param iface_list: the interface list
    :param expect_status: expected status for the interface specified in the iface_list
    :return: True if the status of all the interfaces specified in the iface_list equal to expect status, else False
    """
    int_status = duthost.show_interface(command="status")['ansible_facts']['int_status']
    for intf in iface_list:
        if int_status[intf]['admin_state'] == 'up' and int_status[intf]['oper_state'] != expect_status:
            return False
    return True


def encode_dut_and_container_name(dut_name, container_name):
    """Gets a string by combining dut name and container name.

    Args:
      dut_name: A string represents name of DuT.
      container_name: A string represents name of container.

    Returns:
      A string includes the DuT and container names.
    """

    return dut_name + "|" + container_name


def decode_dut_and_container_name(name_str):
    """Gets DuT name and container name by parsing the string 'name_str'.

    Args:
      A string includes the DuT and container names.

    Returns:
      dut_name: A string represents name of DuT.
      container_name: A string represents name of container.
    """
    dut_name = ""
    container_name = ""

    name_list = name_str.strip().split("|")
    if len(name_list) >= 2:
        dut_name = name_list[0]
        container_name = name_list[1]
    elif len(name_list) == 1:
        container_name = name_list[0]

    return dut_name, container_name


def verify_features_state(duthost):
    """Checks whether the state of each feature is valid.

    Args:
      duthost: An Ansible object of DuT.

    Returns:
      If states of all features are valid, returns True; otherwise,
      returns False.
    """
    feature_status, succeeded = duthost.get_feature_status()
    if not succeeded:
        logger.info("Failed to get list of feature names.")
        return False

    for feature_name, status in list(feature_status.items()):
        logger.info("The state of '{}' is '{}'.".format(feature_name, status))

        if status not in ("enabled", "always_enabled", "disabled", "always_disabled"):
            logger.info("The state of '{}' is invalid!".format(feature_name))
            return False

        logger.info("The state of '{}' is valid.".format(feature_name))

    return True


def verify_orchagent_running_or_assert(duthost):
    """
    Verifies that orchagent is running, asserts otherwise

    Args:
        duthost: Device Under Test (DUT)
    """

    def _orchagent_running():
        cmds = 'docker exec swss supervisorctl status orchagent'
        output = duthost.shell(cmds, module_ignore_errors=True)
        pytest_assert(not output['rc'], "Unable to check orchagent status output")
        return 'RUNNING' in output['stdout']

    pytest_assert(
        wait_until(120, 10, 0, _orchagent_running),
        "Orchagent is not running"
    )


def ignore_t2_syslog_msgs(duthost):

    """
        When we reboot / config_reload on T2 chassis cards, we see 2 error messages in the linecards

        1) During config_reload/reboot of linecard, LAGS are deleted, but ports are up,
        and we get mac learning events from SAI to orchagent
        which is in middle of cleanup and doesn't have the right data.
        This causes error message like Failed to get port by bridge port ID

        2) reboot/config_reload on supoervisor  will cause all the fabric links in the linecard to
        bounce which results in SAI sending messages orchagent regarding the fabric port state change.
        However, in linecards in T2 chassis, there is modelling of fabric ports in orchagent. Thus, orchagent generates
        error message indication to port object found for the port.
        Please see https://github.com/sonic-net/sonic-buildimage/issues/9033 for details.
    """
    if duthost.topo_type == "t2" and duthost.facts.get('platform_asic') == "broadcom-dnx":
        ignoreRegex = [".*orchagent.*Failed to get port by bridge port ID.*"]
        if duthost.is_supervisor_node():
            ignoreRegex.extend([".*orchagent.*Failed to get port object for port id.*"])
        for a_dut in duthost.duthosts.frontend_nodes:
            # DUT's loganalyzer would be null if we have disable_loganalyzer specified
            if a_dut.loganalyzer:
                a_dut.loganalyzer.ignore_regex.extend(ignoreRegex)


def get_sai_sdk_dump_file(duthost, dump_file_name):
    full_path_dump_file = f"/tmp/{dump_file_name}"
    cmd_gen_sdk_dump = f"docker exec syncd bash -c 'saisdkdump -f {full_path_dump_file}' "
    duthost.shell(cmd_gen_sdk_dump)

    cmd_copy_dmp_from_syncd_to_host = f"docker cp syncd: {full_path_dump_file}  {full_path_dump_file}"
    duthost.shell(cmd_copy_dmp_from_syncd_to_host)

    compressed_dump_file = f"/tmp/{dump_file_name}.tar.gz"
    duthost.archive(path=full_path_dump_file, dest=compressed_dump_file, format='gz')

    duthost.fetch(src=compressed_dump_file, dest="/tmp/", flat=True)
    allure.attach.file(compressed_dump_file, dump_file_name, extension=".tar.gz")


def is_mellanox_devices(hwsku):
    """
    A helper function to check if a given sku is Mellanox device
    """
    hwsku = hwsku.lower()
    return 'mellanox' in hwsku \
        or 'msn' in hwsku \
        or 'mlnx' in hwsku


def is_mellanox_fanout(duthost, localhost):
    # Ansible localhost fixture which calls ansible playbook on the local host

    if duthost.facts.get("asic_type") == "vs":
        return False

    try:
        dut_facts = \
            localhost.conn_graph_facts(host=duthost.hostname, filepath=LAB_CONNECTION_GRAPH_PATH)["ansible_facts"]
    except RunAnsibleModuleFail as e:
        logger.info("Get dut_facts failed, reason:{}".format(e.results['msg']))
        return False

    intf = list(dut_facts["device_conn"][duthost.hostname].keys())[0]
    fanout_host = dut_facts["device_conn"][duthost.hostname][intf]["peerdevice"]

    try:
        fanout_facts = \
            localhost.conn_graph_facts(host=fanout_host, filepath=LAB_CONNECTION_GRAPH_PATH)["ansible_facts"]
    except RunAnsibleModuleFail:
        return False

    fanout_sku = fanout_facts['device_info'][fanout_host]['HwSku']
    if not is_mellanox_devices(fanout_sku):
        return False

    return True


def create_duthost_console(duthost,localhost, conn_graph_facts, creds):  # noqa F811
    dut_hostname = duthost.hostname
    console_host = conn_graph_facts['device_console_info'][dut_hostname]['ManagementIp']
    if "/" in console_host:
        console_host = console_host.split("/")[0]
    console_port = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['peerport']
    console_type = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['type']
    console_menu_type = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['menu_type']
    console_username = conn_graph_facts['device_console_link'][dut_hostname]['ConsolePort']['proxy']

    console_type = f"console_{console_type}"
    console_menu_type = f"{console_type}_{console_menu_type}"

    # console password and sonic_password are lists, which may contain more than one password
    sonicadmin_alt_password = localhost.host.options['variable_manager']._hostvars[dut_hostname].get(
        "ansible_altpassword")
    sonic_password = [creds['sonicadmin_password'], sonicadmin_alt_password]

    # Attempt to clear the console port
    try:
        duthost_clear_console_port(
            menu_type=console_menu_type,
            console_host=console_host,
            console_port=console_port,
            console_username=console_username,
            console_password=creds['console_password'][console_type]
        )
    except Exception as e:
        logger.warning(f"Issue trying to clear console port: {e}")

    # Set up console host
    host = None
    for attempt in range(1, 4):
        try:
            host = ConsoleHost(console_type=console_type,
                               console_host=console_host,
                               console_port=console_port,
                               sonic_username=creds['sonicadmin_user'],
                               sonic_password=sonic_password,
                               console_username=console_username,
                               console_password=creds['console_password'][console_type])
            break
        except Exception as e:
            logger.warning(f"Attempt {attempt}/3 failed: {e}")
            continue
    else:
        raise Exception("Failed to set up connection to console port. See warning logs for details.")

    return host


def creds_on_dut(duthost):
    """ read credential information according to the dut inventory """
    groups = duthost.host.options['inventory_manager'].get_host(duthost.hostname).get_vars()['group_names']
    groups.append("fanout")
    logger.info("dut {} belongs to groups {}".format(duthost.hostname, groups))
    exclude_regex_patterns = [
        r'topo_.*\.yml',
        r'breakout_speed\.yml',
        r'lag_fanout_ports_test_vars\.yml',
        r'qos\.yml',
        r'sku-sensors-data\.yml',
        r'mux_simulator_http_port_map\.yml'
        ]
    ansible_folder_path = os.path.join(BASI_PATH, "../../../ansible/")
    files = glob.glob(os.path.join(ansible_folder_path, "group_vars/all/*.yml"))
    files += glob.glob(os.path.join(ansible_folder_path, "vars/*.yml"))
    for group in groups:
        files += glob.glob(os.path.join(ansible_folder_path, f"group_vars/{group}/*.yml"))
    filtered_files = [
        f for f in files if not re.search('|'.join(exclude_regex_patterns), f)
    ]

    creds = {}
    for f in filtered_files:
        with open(f) as stream:
            v = yaml.safe_load(stream)
            if v is not None:
                creds.update(v)
            else:
                logging.info("skip empty var file {}".format(f))

    cred_vars = [
        "sonicadmin_user",
        "sonicadmin_password",
        "docker_registry_host",
        "docker_registry_username",
        "docker_registry_password",
        "public_docker_registry_host"
    ]
    hostvars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]
    for cred_var in cred_vars:
        if cred_var in creds:
            creds[cred_var] = jinja2.Template(creds[cred_var]).render(**hostvars)
    # load creds for console
    if "console_login" not in list(hostvars.keys()):
        console_login_creds = {}
    else:
        console_login_creds = hostvars["console_login"]
    creds["console_user"] = {}
    creds["console_password"] = {}

    creds["ansible_altpasswords"] = []

    # If ansible_altpasswords is empty, add ansible_altpassword to it
    if len(creds["ansible_altpasswords"]) == 0:
        creds["ansible_altpasswords"].append(hostvars["ansible_altpassword"])

    passwords = creds["ansible_altpasswords"] + [creds["sonicadmin_password"]]
    creds['sonicadmin_password'] = get_dut_current_passwd(
        duthost.mgmt_ip,
        duthost.mgmt_ipv6,
        creds['sonicadmin_user'],
        passwords
    )

    for k, v in list(console_login_creds.items()):
        creds["console_user"][k] = v["user"]
        creds["console_password"][k] = v["passwd"]

    return creds


def duthost_clear_console_port(
        menu_type: str,
        console_host: str,
        console_port: str,
        console_username: str,
        console_password: str
):
    """
    Helper function to clear the console port for a given DUT.
    Useful when a device has an occupied console port, preventing dut_console tests from running.

    Parameters:
        menu_type: Connection type for the console's config menu (as expected by the ConsoleTypeMapper)
        console_host: DUT host's console IP address
        console_port: DUT host's console port, to be cleared
        console_username: Username for the console account (overridden for Digi console)
        console_password: Password for the console account
    """
    if menu_type == "console_ssh_":
        raise Exception("Device does not have a defined Console_menu_type.")

    # Override console user if the configuration menu is Digi, as this requires admin login
    console_user = 'admin' if menu_type == CONSOLE_SSH_DIGI_CONFIG else console_username

    duthost_config_menu = ConsoleHost(
        console_type=menu_type,
        console_host=console_host,
        console_port=console_port,
        console_username=console_user,
        console_password=console_password,
        sonic_username=None,
        sonic_password=None
    )

    # Command lists for each config menu type
    # List of tuples, containing a command to execute, and an optional pattern to wait for
    command_list = {
        CONSOLE_SSH_DIGI_CONFIG: [
            ('2', None),                                                    # Enter serial port config
            (console_port, None),                                           # Choose DUT console port
            ('a', None),                                                    # Enter port management
            ('1', f'Port #{console_port} has been reset successfully.')     # Reset chosen port
        ],
        CONSOLE_SSH_SONIC_CONFIG: [
            (f'sudo sonic-clear line {console_port}', None)     # Clear DUT console port (requires sudo)
        ],
        CONSOLE_SSH_CISCO_CONFIG: [
            (f'clear line tty {console_port}', '[confirm]'),    # Clear DUT console port
            ('', '[OK]')                                        # Confirm selection
        ],
    }

    for command, wait_for_pattern in command_list[menu_type]:
        duthost_config_menu.write_channel(command + duthost_config_menu.RETURN)
        duthost_config_menu.read_until_prompt_or_pattern(wait_for_pattern)

    duthost_config_menu.disconnect()
    logger.info(f"Successfully cleared console port {console_port}, sleeping for 5 seconds")
    time.sleep(5)
