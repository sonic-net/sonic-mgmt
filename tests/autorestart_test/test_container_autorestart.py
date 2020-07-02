"""
Test the auto-restart feature of containers 
"""
import time
import pytest
import logging

from collections import defaultdict

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
    @summary: Get critical program names, running status and their pids by analyzing the command
              output of "docker exec <container_name> supervisorctl"
    @return: Critical program names and their pids
    """
    group_program_info = defaultdict(list)
    program_name = None
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl".format(container_name))
    for program_info in program_list["stdout_lines"]:
        if program_info.find(critical_group) != -1:
            program_name = program_info.split()[0].split(':')[1].strip(' \n')
            program_status = program_info.split()[1].strip()
            if program_status in ["EXITED", "STOPPED", "STARTING"]:
                program_pid = -1
            else:
                program_pid = program_info.split()[3].strip(' ,')

            group_program_info[program_name].append(program_status)
            group_program_info[program_name].append(program_pid)
            
    return group_program_info

def get_program_info(duthost, container_name, program_name):
    """
    @summary: Get program running status and pid by analyzing the command
              output of "docker exec <container_name> supervisorctl"
    @return:  Program running status and its pid
    """
    program_status = None
    program_pid = -1

    program_list = duthost.shell("docker exec {} supervisorctl".format(container_name))
    for program_info in program_list["stdout_lines"]:
        if program_info.find(program_name) != -1:
            program_status = program_info.split()[1].strip()
            if program_status == "RUNNING":
                program_pid = int(program_info.split()[3].strip(' ,'))
            break

    logging.info("Found program {} in the {} state with pid {}".format(program_name, program_status, program_pid))
            
    return program_status, program_pid

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
    return is_running["stdout_lines"][0].strip(' \n')

def get_program_status(duthost, container_name, program_name):
    """
    @summary: Return the running status of a program 
    @return:  "RUNNING" or "EXITED" represents the program is in running or exited state

    """
    program_status = None

    process_list = duthost.shell("docker exec {} supervisorctl".format(container_name))
    for process_info in process_list["stdout_lines"]:
        if process_info.find(program_name) != -1:
            program_status = process_info.split()[1].strip()
            break
 
    return program_status

def kill_process_by_pid(duthost, container_name, program_name, program_status, program_pid):
    """
    @summary: Kill a process in the specified container by its pid

    """
    if program_status == "RUNNING":
        duthost.shell("docker exec {} kill -SIGKILL {}".format(container_name, program_pid)) 
    elif program_status in ["EXITED", "STOPPED", "STARTING"]:
        pytest_assert(False, "{} in {} is in the {} state not running".format(program_name, container_name, program_status))
    else:
        pytest_assert(False, "Failed to find {} in {}".format(program_name, container_name))
    # Sleep 10 seconds to wait container is stopped
    time.sleep(10)

    is_running = is_container_running(duthost, container_name)
    if is_running == "true":
        program_status = get_program_status(duthost, container_name, program_name)
        if program_status == "RUNNING":
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
 
def is_hiting_start_limit(duthost, container_name):
    """
    @summary: Determine whether the container can not be restarted is due to 
              start-limit-hit or not
    """
    service_status = duthost.shell("systemctl status {}.service | grep 'Active'".format(container_name))
    for line in service_status["stdout_lines"]:
        if "start-limit-hit" in line:
            return True

    return False
 
def verify_autorestart_with_critical_process(duthost, container_name, program_name, 
                                             program_status, program_pid):
    """
    @summary: Killing a critical process in a container to verify whether the container 
              can be stopped and then restarted correctly 
    """
    kill_process_by_pid(duthost, container_name, program_name, program_status, program_pid)

    logging.info("Waiting until {} is stopped...".format(container_name))
    pytest_assert(wait_until(CONTAINER_STOP_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, True), 
                  "Failed to stop {}".format(container_name))
    logging.info("{} is stopped".format(container_name))

    logging.info("Waiting until {} is restarted...".format(container_name))
    restarted = wait_until(CONTAINER_RESTART_THRESHOLD_SECS, 
                  CONTAINER_CHECK_INTERVAL_SECS,
                  check_container_status, duthost, container_name, False)
    if not restarted:
        if is_hiting_start_limit(duthost, container_name):
            logging.info("{} hits start limit and clear reset-failed...".format(container_name))
            duthost.shell("sudo systemctl reset-failed {}.service".format(container_name))
            duthost.shell("sudo systemctl start {}.service".format(container_name))
            pytest_assert(wait_until(CONTAINER_RESTART_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, False), 
                  "Failed to restart {} after reset-failed is cleared".format(container_name))
        else:
            pytest_assert(False, "Failed to restart {}".format(container_name)) 
    logging.info("{} is restarted".format(container_name))

def verify_no_autorestart_with_non_critical_process(duthost, container_name, program_name,
                                                    program_status, program_pid):
    """
    @summary: Killing a non-critical process in a container to verify whether the container 
              is still in the running state 
    """
    kill_process_by_pid(duthost, container_name, program_name, program_status, program_pid)

    logging.info("Checking whether the {} is still running...".format(container_name))
    pytest_assert(wait_until(CONTAINER_STOP_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, False),
                  "{} is stopped unexpectedly".format(container_name))
    logging.info("{} is running".format(container_name))

def test_containers_autorestart(duthost):
    """
    @summary: Test the auto-restart feature of each contianer against two scenarios: killing
              a non-critical process to verity the container is still running; killing each
              critical process to verify the container will be stopped and restarted
    """ 
    container_autorestart_info = get_autorestart_container_and_state(duthost)
    for container_name in container_autorestart_info:
        is_running = is_container_running(duthost, container_name)
        if is_running == "false":
            pytest_assert(False, "{} is not running".format(container_name))

        logging.info("Start testing the container {}...".format(container_name))

        if container_name == "sflow":
            logging.info("Unmask sflow service and start it")
            duthost.shell("sudo systemctl unmask {}".format(container_name))
            duthost.shell("sudo systemctl start {}".format(container_name))
            # Sleep 10 seconds such that processes in sflow can come into live
            time.sleep(10)

        need_restore_state = False
        if container_autorestart_info[container_name] == "disabled":
            logging.info("Change {} auto-restart state to 'enabled'".format(container_name))
            duthost.shell("config container feature autorestart {} enabled".format(container_name))
            need_restore_state = True
 
        # Currently we select 'rsyslogd' as non-critical processes for testing based on 
        # the assumption that every container has an 'rsyslogd' process running and it is not
        # consider a critical process
        program_status, program_pid = get_program_info(duthost, container_name, "rsyslogd")
        verify_no_autorestart_with_non_critical_process(duthost, container_name, "rsyslogd", 
                                                        program_status, program_pid)

        critical_group_list, critical_process_list = get_critical_group_and_process_list(duthost, container_name)
        for critical_process in critical_process_list:
            program_status, program_pid = get_program_info(duthost, container_name, critical_process)
            verify_autorestart_with_critical_process(duthost, container_name, critical_process, 
                                                     program_status, program_pid)
            # Sleep 20 seconds in order to let the processes come into live after container is restarted
            time.sleep(20)
            # We are currently only testing one critical process, that is why we use 'break'. Once
            # we add the "extended" mode, we will remove this statement
            #break
        for critical_group in critical_group_list:
            group_program_info = get_group_program_info(duthost, container_name, critical_group) 
            for program_name in group_program_info:
                verify_autorestart_with_critical_process(duthost, container_name, program_name, 
                                                         group_program_info[program_name][0],
                                                         group_program_info[program_name][1])
            # We are currently only testing one critical program for each critical group, which is
            # why we use 'break' statement. Once we add the "extended" mode, we will remove this
            # statement
                break

        # After these two containers are restarted, we need wait to give their dependent containers
        # a chance to restart
        if container_name in ["syncd", "swss", "database"]:
            logging.info("Sleep 20 seconds after testing the {}...".format(container_name))
            time.sleep(20)
        
        if need_restore_state:
            logging.info("Restore {} auto-restart state to {}".format(container_name, container_autorestart_info[container_name]))
            duthost.shell("config container feature autorestart {} {}".format(container_name, container_autorestart_info[container_name]))

        logging.info("End of testing for {}".format(container_name))
