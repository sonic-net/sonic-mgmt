"""
Check the auto-restart feature of different containers 
"""
import time
import pytest
import logging

from common.utilities import wait_until

CONTAINER_CHECK_INTERVAL_SECS = 1
CONTAINER_STOP_THRESHOLD_SECS = 30
CONTAINER_RESTART_THRESHOLD_SECS = 180

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
        assert False, "Failed to stop {} process before test.".format(process)
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
    kill_process(duthost, container_name, process)

    logging.info("Waiting until {} is stopped...".format(container_name))
    assert wait_until(CONTAINER_STOP_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, True)
    logging.info("{} is stopped".format(container_name))

    logging.info("Waiting until {} is restarted...".format(container_name))
    assert wait_until(CONTAINER_RESTART_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, False)
    logging.info("{} is restarted".format(container_name))

def verify_autorestart_with_non_critical_process(duthost, container_name, process):
    """
    @summary: Killing a non-critical process in a container to verify whether the container 
              is still in the running state 
    """
    kill_process(duthost, container_name, process)

    logging.info("Checking whether the {} is still running...".format(container_name))
    assert wait_until(CONTAINER_STOP_THRESHOLD_SECS, 
                      CONTAINER_CHECK_INTERVAL_SECS,
                      check_container_status, duthost, container_name, False)
    logging.info("{} is running".format(container_name))

@pytest.fixture(scope="module", autouse=True)
def change_autorestart_status(duthost):
    container_list = ["lldp", "radv", "pmon", "sflow", "database", "telemetry", "snmp",
                      "bgp", "dhcp_relay", "nat", "teamd", "syncd", "swss"]
    for container_name in container_list:
        logging.info("Change {} auto-restart status to enabled".format(container_name))
        duthost.shell("config container feature autorestart %s enabled" % container_name)

def test_swss_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "swss", "portsyncd")
    verify_autorestart_with_non_critical_process(duthost, "swss", "rsyslogd")

def test_lldp_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "lldp", "lldpmgrd")
    verify_autorestart_with_non_critical_process(duthost, "lldp", "rsyslogd")

def test_sflow_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "sflow", "sflowmgrd")
    verify_autorestart_with_non_critical_process(duthost, "sflow", "rsyslogd")

def test_database_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "database", "redis")
    verify_autorestart_with_non_critical_process(duthost, "database", "rsyslogd")

def test_telemetry_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "telemetry", "telemetry")
    verify_autorestart_with_non_critical_process(duthost, "telemetry", "rsyslogd")

def test_snmp_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "snmp", "snmpd")
    verify_autorestart_with_non_critical_process(duthost, "snmp", "rsyslogd")

def test_bgp_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "bgp", "zebra")
    verify_autorestart_with_non_critical_process(duthost, "bgp", "rsyslogd")

def test_radv_autorestart(duthost):
    verify_autorestart_with_non_critical_process(duthost, "radv", "rsyslogd")

def test_dhcp_relay_autorestart(duthost):
    #verify_autorestart_with_critical_process(duthost, "dhcp_relay", "")
    verify_autorestart_with_non_critical_process(duthost, "dhcp_relay", "rsyslogd")

def test_nat_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "nat", "natmgrd")
    verify_autorestart_with_non_critical_process(duthost, "nat", "rsyslogd")

def test_teamd_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "teamd", "teammgrd")
    verify_autorestart_with_non_critical_process(duthost, "teamd", "rsyslogd")

def test_syncd_autorestart(duthost):
    verify_autorestart_with_critical_process(duthost, "syncd", "syncd")
    verify_autorestart_with_non_critical_process(duthost, "syncd", "rsyslogd")

def test_pmon_autorestart(duthost):
    #verify_autorestart_with_critical_process(duthost, "pmon", "")
    verify_autorestart_with_non_critical_process(duthost, "pmon", "rsyslogd")
