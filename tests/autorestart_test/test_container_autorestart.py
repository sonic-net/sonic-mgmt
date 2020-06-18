"""
Check the auto-restart feature of containers 
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

def get_autorestart_container_list(duthost):
    """
    @summary: Get container list by analyzing the command output of 
              "show container feature autorestart"
    @return: The list includes containers which was implemented with the autorestart feature
    """
    container_list = []
    show_cmd_output = duthost.shell(CMD_CONTAINER_FEATURE_AUTORESTART)
    for line in show_cmd_output["stdout_lines"]:
        if line.split()[1] in ["enabled", "disabled"]:
            container_list.append(line.split()[0])

    return container_list


def get_process_id(duthost, container_name, process):
    """
    @summary: Get the pid of process in the specified container by analyzing
              the command output of "ps -ax"
    @return: first value is a boolean. True indicates the processs is running
             second value is the process id. Returning -1 if the process is not found
    """
    running_status = False
    process_id = -1
    is_running = duthost.shell("docker inspect -f \{\{.State.Running\}\} %s" % container_name)
    if is_running['stdout'].strip() == "false":
        return running_status, process_id
 
    ps_cmd_out = duthost.shell("docker exec {} ps -ax".format(container_name))
    for line in ps_cmd_out["stdout_lines"]:
        if "/usr/bin/supervisor-proc-exit-listener" not in line \
            and line.find(process) != -1:
            running_status = True
            process_id = int(line.split()[0])
            break 

    return running_status, process_id
 
def kill_process(duthost, container_name, process):
    """
    @summary: Kill a process in the specified container

    """
    running_status, process_id = get_process_id(duthost, container_name, process)
    if running_status:
        duthost.shell("docker exec {} kill -9 {}".format(container_name, process_id)) 
    else:
        pytest_assert(False, "Failed to find {} process in {}".format(process, container_name))

    time.sleep(7)

    running_status, process_id = get_process_id(duthost, container_name, process)
    if running_status:
        pytest_assert(False, "Failed to stop {} process before test".format(process))
    else:
        logging.info("{} process in {} is stopped successfully".format(process, container_name)) 

def check_container_status(duthost, container_name, should_be_stopped):
    """
    @summary: Determine whether a container should be in running state or not
    """
    is_running = duthost.shell("docker inspect -f \{\{.State.Running\}\} %s" % container_name)
    if is_running['stdout'].strip() == "false" and should_be_stopped:
        return True
    if is_running['stdout'].strip() == "true" and not should_be_stopped:
        return True
    return False
 
def verify_autorestart_with_critical_process(duthost, container_name, process):
    """
    @summary: Killing a critical process in a container to verify whether the container 
              can be stopped and then restarted correctly 
    """
    kill_process(duthost, container_name, process)

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

def verify_no_autorestart_with_non_critical_process(duthost, container_name, process):
    """
    @summary: Killing a non-critical process in a container to verify whether the container 
              is still in the running state 
    """
    kill_process(duthost, container_name, process)

    logging.info("Checking whether the {} is still running...".format(container_name))
    pytest_assert(wait_until(CONTAINER_STOP_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, False),
                  "{} is stopped unexpectedly".format(container_name))
    logging.info("{} is running".format(container_name))

@pytest.fixture(scope="module", autouse=True)
def change_autorestart_state(duthost):
    container_list = get_autorestart_container_list(duthost)
    for container_name in container_list:
        logging.info("Change {} auto-restart state to 'enabled'".format(container_name))
        duthost.shell("config container feature autorestart %s enabled" % container_name)

def test_containers_autorestart(duthost):
    container_list = get_autorestart_container_list(duthost)
    for container_name in container_list:
        logging.info(container_name)
        if container_name != "restapi":
            verify_no_autorestart_with_non_critical_process(duthost, container_name, "rsyslogd")

        if container_name == "swss" :
            verify_autorestart_with_critical_process(duthost, container_name, "portsyncd")
            time.sleep(7)
        elif container_name == "lldp":
            verify_autorestart_with_critical_process(duthost, container_name, "lldpmgrd")
        elif container_name == "sflow":
            verify_autorestart_with_critical_process(duthost, container_name, "sflowmgrd")
        elif container_name == "database":
            verify_autorestart_with_critical_process(duthost, container_name, "redis")
        elif container_name == "telemetry":
            verify_autorestart_with_critical_process(duthost, container_name, "telemetry")
        elif container_name == "snmp":
            verify_autorestart_with_critical_process(duthost, container_name, "snmpd")
        elif container_name == "bgp":
            verify_autorestart_with_critical_process(duthost, container_name, "zebra")
        elif container_name == "radv":
            pass
            #verify_autorestart_with_critical_process(duthost, container_name, "radvd")
        elif container_name == "dhcp_relay":
            verify_autorestart_with_critical_process(duthost, container_name, "dhcrelay")
        elif container_name == "nat":
            verify_autorestart_with_critical_process(duthost, container_name, "natmgrd")
        elif container_name == "teamd":
            verify_autorestart_with_critical_process(duthost, container_name, "teammgrd")
        elif container_name == "syncd":
            verify_autorestart_with_critical_process(duthost, container_name, "syncd")
        elif container_name == "pmon":
            pass
            #verify_autorestart_with_critical_process(duthost, container_name, "ledd")
