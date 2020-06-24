"""
Test the auto-restart feature of containers 
"""
import time
import pytest
import logging

from common.utilities import wait_until
from common.helpers.assertions import pytest_assert

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_STOP_THRESHOLD_SECS = 30
CONTAINER_RESTART_THRESHOLD_SECS = 180

CMD_CONTAINER_FEATURE_AUTORESTART = "show container feature autorestart"

def get_critical_group_and_process_list(duthost, container_name):
    """
    @summary: Get critical group and process lists by parsing the 
              critical_processes file in the specified container
    @return: Two lists which include the critical process and critical groups respectively
    """
    critical_group_list = []
    critical_process_list = []

    file_content = duthost.shell("docker exec {} bash -c '[ -f /etc/supervisor/critical_processes ] \
        && cat /etc/supervisor/critical_processes'".format(container_name), module_ignore_errors=True)
    for line in file_content["stdout_lines"]:
        line_info = line.strip(' \n').split(':')
        if len(line_info) != 2:
            pytest_assert(False, "Syntax of the line {} in critical_processes \
                file is incorrect.".format(line))
        
        identifier_key = line_info[0].strip()
        identifier_value = line_info[1].strip()
        if identifier_key == "group" and identifier_value:
            critical_group_list.append(identifier_value)
        elif identifier_key == "program" and identifier_value:
            critical_process_list.append(identifier_value)
        else:
            pytest_assert(False, "Syntax of the line {} in critical_processes \
                file is incorrect.".format(line))
 
    return critical_group_list, critical_process_list

def get_group_program_info(duthost, container_name, critical_group):
    """
    @summary: Get critical program names and their pids by analyzing the command
              output of "docker exec <container_name> supervisorctl"
    @return: Critical program names and their pids
    """
    group_program_info = {}
    program_list = duthost.shell("docker exec {} supervisorctl".format(container_name))
    for program_info in program_list["stdout_lines"]:
        if program_info.find(critical_group) != -1 and program_info.split()[1].strip() == "RUNNING":
            program_name = program_info.split()[0].split(':')[1].strip(' \n')
            program_pid = program_info.split()[3].strip(' ,')
            group_program_info[program_name] = program_pid
            
    return group_program_info

def get_autorestart_container_and_state(duthost):
    """
    @summary: Get container names and its autorestart states by analyzing 
              the command output of "show container feature autorestart"
    @return:  container names and their states which have the autorestart feature implemented
    """
    container_autorestart_info = {}
    show_cmd_output = duthost.shell(CMD_CONTAINER_FEATURE_AUTORESTART)
    for line in show_cmd_output["stdout_lines"]:
        container_name = line.split()[0].strip()
        container_state = line.split()[1].strip(' \n')
        if container_state in ["enabled", "disabled"]:
            container_autorestart_info[container_name] = container_state

    return container_autorestart_info

def is_container_running(duthost, container_name):
    """
    @summary: Decide whether the container is running or not
    @return:  Boolean value. True represents the container is running

    """
    is_running = duthost.shell("docker inspect -f \{{\{{.State.Running\}}\}} {}".format(container_name))
    return is_running['stdout'].strip()

def get_program_state(duthost, container_name, program_name):
    """
    @summary: Return the running status of a program 
    @return:  "RUNNING" and "EXITED" represents the program is in running or exited state

    """
    process_list = duthost.shell("docker exec {} supervisorctl".format(container_name))
    for process_info in process_list["stdout_lines"]:
        if process_info.find(program_name) != -1:
            return process_info.split()[1].strip()

def get_process_info(duthost, container_name, process_name):
    """
    @summary: Get the pid of process in the specified container by analyzing
              the command output of "ps -ax"
    @return: first value is a boolean. True indicates the processs is running
             second value is the process id. Returning -1 if the process is not found
    """
    running_status = False
    process_id = -1
 
    ps_cmd_out = duthost.shell("docker exec {} ps -ax".format(container_name))
    for line in ps_cmd_out["stdout_lines"]:
        if "/usr/bin/supervisor-proc-exit-listener" not in line \
            and line.find(process_name) != -1:
            running_status = True
            process_id = int(line.split()[0].strip())
            break 

    return running_status, process_id
 
def kill_process_by_name(duthost, container_name, process_name):
    """
    @summary: Kill a process in the specified container by its name

    """
    running_status, process_id = get_process_info(duthost, container_name, process_name)
    if running_status:
        duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, process_id)) 
    else:
        pytest_assert(False, "Failed to find {} process in {}".format(process_name, container_name))

    time.sleep(7)

    is_running = is_container_running(duthost, container_name)
    if is_running == "true":
        running_status, process_id = get_process_info(duthost, container_name, process_name)
        if running_status:
            pytest_assert(False, "Failed to stop {} process before test".format(process_name))

    logging.info("{} process in {} is stopped successfully".format(process_name, container_name)) 

def kill_process_by_pid(duthost, container_name, program_name, program_pid):
    """
    @summary: Kill a process in the specified container by its pid

    """
    duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid)) 

    time.sleep(7)

    is_running = is_container_running(duthost, container_name)
    if is_running == "true":
        running_status = get_program_state(duthost, container_name, program_name)
        if running_status == "RUNNING":
            pytest_assert(False, "Failed to stop {} before test".format(program_name))

    logging.info("{} in {} is stopped successfully".format(program_name, container_name)) 


def check_container_status(duthost, container_name, should_be_stopped):
    """
    @summary: Determine whether a container should be in running state or not
    """
    is_running = is_container_running(duthost, container_name)
    if is_running == "false" and should_be_stopped:
        return True
    if is_running == "true" and not should_be_stopped:
        return True
    return False
 
def verify_autorestart_with_critical_process(duthost, container_name, process_name, 
                                             program_name, program_pid, is_process_name):
    """
    @summary: Killing a critical process in a container to verify whether the container 
              can be stopped and then restarted correctly 
    """
    is_running = is_container_running(duthost, container_name)
    if is_running == "false":
        pytest_assert(False, "{} is not running".format(container_name))

    if is_process_name:
        kill_process_by_name(duthost, container_name, process_name)
    else:
        kill_process_by_pid(duthost, container_name, program_name, program_pid)

    logging.info("Waiting until {} is stopped...".format(container_name))
    pytest_assert(wait_until(CONTAINER_STOP_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, True), 
                  "Failed to stop {}".format(container_name))
    logging.info("{} is stopped".format(container_name))

    logging.info("Waiting until {} is restarted...".format(container_name))
    pytest_assert(wait_until(CONTAINER_RESTART_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, False),
                  "Failed to restart {}".format(container_name))
    logging.info("{} is restarted".format(container_name))

def verify_no_autorestart_with_non_critical_process(duthost, container_name, process_name):
    """
    @summary: Killing a non-critical process in a container to verify whether the container 
              is still in the running state 
    """
    is_running = is_container_running(duthost, container_name)
    if is_running == "false":
        pytest_assert(False, "{} is not running".format(container_name))

    kill_process_by_name(duthost, container_name, process_name)

    logging.info("Checking whether the {} is still running...".format(container_name))
    pytest_assert(wait_until(CONTAINER_STOP_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, False),
                  "{} is stopped unexpectedly".format(container_name))
    logging.info("{} is running".format(container_name))

def test_containers_autorestart(duthost):
    container_autorestart_info = get_autorestart_container_and_state(duthost)
    for container_name in container_autorestart_info:
        logging.info("Change {} auto-restart state to 'enabled'".format(container_name))
        duthost.shell("config container feature autorestart {} enabled".format(container_name))
 
        if container_name in ["restapi"]:
            continue
        
        verify_no_autorestart_with_non_critical_process(duthost, container_name, "rsyslogd")

        if container_name in ["pmon", "radv"]:
            logging.info("Restore {} auto-restart state to {}".format(container_name, container_autorestart_info[container_name]))
            duthost.shell("config container feature autorestart {} {}".format(container_name, container_autorestart_info[container_name]))
            continue
        
        critical_group_list, critical_process_list = get_critical_group_and_process_list(duthost, container_name)
        for critical_process in critical_process_list:
            verify_autorestart_with_critical_process(duthost, container_name, critical_process, "", "", True)
            break
        for critical_group in critical_group_list:
            group_program_info = get_group_program_info(duthost, container_name, critical_group) 
            for program_name in group_program_info:
                verify_autorestart_with_critical_process(duthost, container_name, "", program_name, 
                                                         group_program_info[program_name], False)
            break

        if container_name in ["swss", "database"]:
            logging.info("Sleep 10 seconds after testing the {}...".format(container_name))
            time.sleep(10)

        logging.info("Restore {} auto-restart state to {}".format(container_name, container_autorestart_info[container_name]))
        duthost.shell("config container feature autorestart {} {}".format(container_name, container_autorestart_info[container_name]))
