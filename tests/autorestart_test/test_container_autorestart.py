"""
Check the auto-restart feature of syncd, swss, teamd, bgp and dhcp_relay
"""
import time
import logging

from common.utilities import wait_until

CONTAINER_STOP_TEST_WAITING_TIME = 30
CONTAINER_STOP_TEST_CHECK_INTERVAL = 1
CONTAINER_RESTART_TEST_WAITING_TIME = 180
CONTAINER_RESTART_TEST_CHECK_INTERVAL = 1
CONTAINER_RUNNING_TEST_WAITING_TIME = 30
CONTAINER_RUNNING_TEST_CHECK_INTERVAL = 1

def get_process_id(duthost, container_name, process):
    """
    @summary: Get the pid of process in the specified container by analyzing
              the command output of "ps -ax"
    @return: first value is a boolean. True indicates the processs is running
             second value is the process id. Returning -1 if the process is not found
    """
    running_status = False
    process_id = -1
    ps_out = duthost.shell("docker exec {} ps -ax".format(container_name))
    for line in ps_out["stdout_lines"]:
        process_info = line.split()
        if "/usr/bin/supervisor-proc-exit-listener" not in process_info \
            and str(process_info).find(process) != -1:
            running_status = True
            process_id = int(process_info[0])
            break 

    return running_status, process_id
 
def kill_process(duthost, container_name, process):
    """
    @summary: Kill a process in the specified container

    """
    running_status, process_id = get_process_id(duthost, container_name, process)
    if running_status:
        duthost.shell("docker exec {} kill -SIGTERM {}".format(container_name, process_id)) 

    running_status, process_id = get_process_id(duthost, container_name, process)
    if running_status:
        assert False, "Failed to stop %s process" % process
    else:
        logging.info("{} process is stopped successfully".format(process)) 

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
    
    #for process in critical_process_list:
    kill_process(duthost, container_name, process)

    logging.info("Waiting until {} is stopped...".format(container_name))
    assert wait_until(CONTAINER_STOP_TEST_WAITING_TIME, 
                      CONTAINER_STOP_TEST_CHECK_INTERVAL,
                      check_container_status, duthost, 
                      container_name, True), "Failed to stop %s" % container_name
    logging.info("{} is stopped".format(container_name))

    logging.info("Waiting until {} is restarted...".format(container_name))
    assert wait_until(CONTAINER_RESTART_TEST_WAITING_TIME, 
                      CONTAINER_RESTART_TEST_CHECK_INTERVAL,
                      check_container_status, duthost, 
                      container_name, False), "Failed to restart %s" % container_name
    logging.info("{} is restarted".format(container_name))

def verify_autorestart_with_non_critical_process(duthost, container_name, process):
    """
    @summary: Killing a non-critical process in a container to verify whether the container 
              is still in the running state 
    """
    
    #for process in critical_process_list:
    kill_process(duthost, container_name, process)

    logging.info("Checking whether the {} is still running...".format(container_name))
    assert wait_until(CONTAINER_RUNNING_TEST_WAITING_TIME, 
                      CONTAINER_RUNNING_TEST_CHECK_INTERVAL,
                      check_container_status, duthost, 
                      container_name, False), "%s is stopped unexpectedly" % container_name
    logging.info("{} is running".format(container_name))

def test_swss_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "swss", "portsyncd")
    verify_autorestart_with_non_critical_process(duthost, "swss", "rsyslogd")
