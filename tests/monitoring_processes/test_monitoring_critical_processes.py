"""
Test the feature of container_checker
"""
from collections import defaultdict
import logging

import pytest

from pkg_resources import parse_version
from tests.common import config_reload
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import check_container_state
from tests.common.helpers.dut_utils import clear_failed_flag_and_restart
from tests.common.helpers.dut_utils import is_hitting_start_limit
from tests.common.helpers.dut_utils import is_container_running
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_STOP_THRESHOLD_SECS = 30
CONTAINER_RESTART_THRESHOLD_SECS = 180


def check_all_critical_processes_status(duthost):
    """Post-checks the status of critical processes.

    Args:
        duthost: Host DUT.

    Return:
        This function will return True if all critical processes are running.
        Otherwise it will return False.
    """
    processes_status = duthost.all_critical_process_status()
    for container_name, processes in processes_status.items():
        if processes["status"] is False or len(processes["exited_critical_process"]) > 0:
            return False

    return True


def post_test_check(duthost, up_bgp_neighbors):
    """Post-checks the status of critical processes and state of BGP sessions.

    Args:
        duthost: Host DUT.
        skip_containers: A list contains the container names which should be skipped.

    Return:
        This function will return True if all critical processes are running and
        all BGP sessions are established. Otherwise it will return False.
    """
    return check_all_critical_processes_status(duthost) and duthost.check_bgp_session_state(up_bgp_neighbors, "established")


def postcheck_critical_processes_status(duthost, up_bgp_neighbors):
    """Calls the functions to post-check the status of critical processes and
       state of BGP sessions.

    Args:
        duthost: Host DUT.
        skip_containers: A list contains the container names which should be skipped.

    Return:
        If all critical processes are running and all BGP sessions are established, it
        returns True. Otherwise it will call the function to do post-check every 30 seconds
        for 3 minutes. It will return False after timeout
    """
    logger.info("Post-checking status of critical processes and BGP sessions...")
    return wait_until(CONTAINER_RESTART_THRESHOLD_SECS, CONTAINER_CHECK_INTERVAL_SECS,
                      post_test_check, duthost, up_bgp_neighbors)


def found_alerting_message(expected_alerting_message, alerting_messages):
    """Device whether the expected alerting message appeared in syslog.

    Args:
        expected_alerting_message: A string which contains the expected alerting message.
        alerting_messages: A list which contains all the alerting messages from syslog.

    Return:
        True if the expected alerting message was found in messages from syslgo,
        otherwise return False.
    """
    for message in alerting_messages:
        if expected_alerting_message in message:
            return True

    return False


def check_alerting_messages(duthost, containers_in_namespaces):
    """Checks whether the names of stopped critical processes and corresponding namespace
       appeared in syslog.

    Args:
        duthost: Host DUT.
        stopped_container_list: A dictionary. Key is container name and value is a list
        which contains ids of namespace.

    Return:
        None.
    """
    logger.info("Checking the alerting messages from syslog...")
    alerting_command_output = duthost.shell("sudo cat /var/log/syslog | grep '.*ERR.*supervisor-proc-exit-listener'",
                                      module_ignore_errors=True)

    pytest_assert(len(alerting_command_output["stdout_lines"]) > 0,
                  "Failed to get Monit alerting messages from container_checker!")

    alerting_messages = alerting_command_output["stdout_lines"]

    for container_name in containers_in_namespaces.keys():
        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'".format(container_name))

        namespaces = containers_in_namespaces[container_name]
        for namespace_id in namespaces:
            namespace_name = "host"
            if namespace_id != "host":
                namespace_name = "asic" + namesapce_id
        
            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if container_name == "syncd" and critical_process == "dsserve":
                    continue
                
                expected_alerting_message = "Process '{}' is not running in namespace '{}'".format(critical_process, namespace_name)
                if not found_alerting_message(expected_alerting_message, alerting_message):
                    pytest.fail("Failed to find the alerting message of process '{}' under namespace '{}'".format(critical_process, namespace_name))

    logger.info("Checking the alerting message was done!")


def check_containers_status(duthost, containers_in_namespaces):
    """Checks whether the containers were started after executing config_reload.

    This function will check whether the containers were actually
    restarted. If the container was not restarted by the command 'config reload', then we
    start it and check its status.

    Args:
        duthost: Hostname of DUT.
        containers_in_namespaces: A dictionary.

    Returns:
        None.
    """
    for container_name in containers_in_namespaces.keys():
        namespaces = containers_in_namespaces[container_name]
        container_name_in_namespace = container_name
        for namespace_id in namespaces:
            if namespace_id != "host":
                container_name_in_namespace += namesapce_id
     
        logger.info("Checking the running status of container '{}'".format(container_name_in_namespace))
        if is_container_running(duthost, container_name_in_namespace):
            logger.info("Container '{}' is running.".format(container_name_in_namespace))
        else:
            logger.info("Container '{}' is not running and restart it...".format(container_name_in_namespace))
            duthost.shell("sudo systemctl restart {}".format(container_name_in_namespace))
            logger.info("Waiting until container '{}' is restarted...".format(container_name_in_namespace))
            restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS,
                                   CONTAINER_CHECK_INTERVAL_SECS,
                                   check_container_state, duthost, container_name_in_namespace, True)
            if not restarted:
                if is_hiting_start_limit(duthost, container_name_in_namespace):
                    clear_failed_flag_and_restart(duthost, container_name_in_namespace)
                else:
                    pytest.fail("Failed to restart container '{}'".format(container_name_in_namespace))

            logger.info("Container '{}' was restarted".format(container_name_in_namespace))


def get_num_asics(duthost):
    """Get number of ASICs on a device.

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    command_num_asics = "python -c 'exec(\"from sonic_py_common import multi_asic\\nprint(multi_asic.get_num_asics())\")'"
    command_output = duthost.shell(command_num_asics)
    exit_code = command_output["rc"]
    pytest_assert(exit_code == 0, "Failed to get number of ASICs"))
 
    num_asics = command_output["stdout_lines"][0]

    return int(num_asics)

def parse_config_entry(config_info):
    """Parse a single entry of FEATURE table.
    
    Args:
        config_info: A list which contains the detailed configuration of a 
        container in FEATURE table.

    Returns:
        is_enabled: A string ("enabled|disabled") shows whether this container
        is enabled or not.
        has_global_scope: A string ("True|False") shows if a device has multi-ASIC,
        whether the container will run in the host.
        has_per_asic_scope: A string ("True|False") shows if a device has multi-ASIC,
        whether the container will run in each ASIC.
    """
    is_enabled = ""
    has_global_scope = ""
    has_per_asic_scope = ""

    for index, item in enumerate(config_info):
        if item == "state":
            is_enabled = config_info[index + 1]
        elif item == "has_global_scope":
            has_global_scope = config_info[index + 1]
        elif item == "has_per_asic_scope":
            has_per_asic_scope = config_info[index + 1]
           
    return is_enabled, has_global_scope, has_per_asic_scope 


def parse_feature_table(duthost, num_asics, skip_containers):
    """Parse the FEATURE table in Config_DB.

    This function will parse the FEATURE table in Config_DB to get which containers
    were enabled and which namespaces these enabled containers reside in.

    Args:
        duthost: Hostname of DUT.
        num_asics: Number of ASICs on a device.
        skip_containers: A list shows which containers will be skipped.

    Returns:
        A dictionary where key is container name and value is a list which contains
        ids of namespaces this container resides in.
    """
    container_list = []
    containers_in_namespaces = defaultdict(list)

    container_list_command = "redis-cli -n 4 keys \"FEATURE|*\""
    command_output = duthost.shell(container_list_command)
    for line in command_output["stdout_lines"]:
        container_list.append(line.split("|")[1].strip())

    for container_name in container_list:
        if container_name in skip_containers:
            continue

        logger.info("Parsing the configuration of container '{}' in Config_DB.".format(container_name))
        config_entry_command = "redis-cli -n 4 hgetall \"FEATURE|{}\"".format(container_name)
        command_output = duthost.shell(config_entry_command)
        is_enabled, has_global_scope, has_per_asic_scope = parse_config_entry(command_output["stdout_lines"])
        if is_enabled != "disabled":
            if num_asics > 1:
	        if has_global_scope == "True":
		    containers_in_namespaces[container_name].append("host")
	        if has_per_asic_scope == "True":
	            for asic_id in range(num_asics):
	                containers_in_namespaces[container_name].append(str(asic_id))
	    else:
	        containers_in_namespaces[container_name].append("host")
        logger.info("The configuration of container '{}' in Config_DB was retrieved.".format(container_name))

    return containers_in_namespaces


def disable_container_autorestart(duthost, containers_in_namespaces):
    """
    """
    for container_name in containers_in_namespaces.keys():
        logger.info("Disabling the autorestart of container '{}'.".format(container_name))
        disable_autorestart_command = "sudo config feature autorestart {} disabled".format(container_name)
        command_output = duthost.shell(disable_autorestart_command) 
        exit_code = command_output["rc"]
        pytest_assert(exit_code == 0, "Failed to disable the autorestart of container '{}'".format(container_name))
        logger.info("The autorestart of container '{}' was disabled.".format(container_name))


def get_group_program_info(duthost, container_name, group_name):
    """Get program names, running status and their pids by analyzing the command
       output of "docker exec <container_name> supervisorctl status". Program name
       at here represents a program which is part of group <group_name>
    
    Args:
        duthost: Hostname of DUT.
        container_name: A string shows container name.
        program_name: A string shows process name.

    Return:
        A dictionary where keys are the program names and values are their running
        status and pids.

    """
    group_program_info = defaultdict(list)
    program_name = None
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl status".format(container_name), module_ignore_errors=True)
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
    """Get program running status and its pid by analyzing the command
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

    program_list = duthost.shell("docker exec {} supervisorctl status".format(container_name), module_ignore_errors=True)
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


def check_and_kill_process(duthost, container_name, program_name, program_status, program_pid):
    """
    """
    if program_status == "RUNNING":
        kill_process_by_pid(duthost, container_name, program_name, program_pid)
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        pytest.fail("Program '{}' in container '{}' is in the '{}' state, expected 'RUNNING'"
                    .format(program_name, container_name, program_status))
    else:
        pytest.fail("Failed to find program '{}' in container '{}'"
                    .format(program_name, container_name))


def stop_critical_processes(duthost, containers_in_namespaces):
    """
    """
    for container_name in containers_in_namespaces.keys():
        critical_group_list, critical_process_list, succeeded = duthost.get_critical_group_and_process_lists(container_name)
        pytest_assert(succeeded, "Failed to get critical group and process lists of container '{}'".format(container_name))

        namespaces = containers_in_namespaces[container_name]
        container_name_in_namespace = container_name
        for namespace_id in namespaces:
            if namespace_id != "host":
                container_name_in_namespace += namesapce_id
        
            for critical_process in critical_process_list:
                # Skip 'dsserve' process since it was not managed by supervisord
                # TODO: Should remove the following two lines once the issue was solved in the image.
                if container_name_in_namespace == "syncd" and critical_process == "dsserve":
                    continue

                program_status, program_pid = get_program_info(duthost, container_name_in_namespace, critical_process)
                check_and_kill_process(duthost, container_name, critical_process, program_status, program_pid)

            for critical_group in critical_group_list:
                group_program_info = get_group_program_info(duthost, container_name, critical_group)
                for program_name in group_program_info:
                    check_and_kill_critical_process(duthost, container_name_in_namespace, program_name,
                                                    group_program_info[program_name][0],
                                                    group_program_info[program_name][1])
 
 
def test_monitoring_critical_processes(duthosts, rand_one_dut_hostname, tbinfo):
    """Tests the feature of monitoring critical processes with Supervisord.

    This function will check whether names of critical processes will appear
    in the syslog if the autorestart were disabled and these critical processes were
    mnually stopped.

    Args:
        duthosts: list of DUTs.
        rand_one_dut_hostname: hostname of DUT.
        tbinfo: Testbed information.

    Returns:
        None.
    """
    duthost = duthosts[rand_one_dut_hostname]

    bgp_neighbors = duthost.get_bgp_neighbors()
    up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]
 
    skip_containers = []
    skip_containers.append("database")
    # Skip 'radv' container on devices whose role is not T0.
    if tbinfo["topo"]["type"] != "t0":
        skip_containers.append("radv")


    num_asics = get_num_asics(duthost)
    containers_in_namespaces = parse_feature_table(duthost, num_asics, skip_containers)

    container_autorestart_states = duthost.get_container_autorestart_states()
    disable_container_autorestart(duthost, containers_in_namespaces)
    stop_critical_processes(duthost, containers_in_namespaces)

    # Wait for 70 seconds such that Monit has a chance to write alerting message into syslog.
    logger.info("Sleep 70 seconds to wait for the alerting message...")
    time.sleep(70)

    check_alerting_messages(duthost, containers_in_namespaces)

    logger.info("Executing the config reload...")
    config_reload(duthost)
    logger.info("Executing the config reload was done!")

    check_containers_status(duthost, containers_in_namespaces)

    if not postcheck_critical_processes_status(duthost, up_bgp_neighbors):
        pytest.fail("Post-check failed after testing the container checker!")
    logger.info("Post-checking status of critical processes and BGP sessions was done!")
