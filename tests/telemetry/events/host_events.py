#! /usr/bin/env python3

import logging
import time
from run_events_test import run_test
from event_utils import backup_monit_config, customize_monit_config, restore_monit_config
from event_utils import add_test_watchdog_timeout_service, delete_test_watchdog_timeout_service
from telemetry_utils import trigger_logger
from tests.common.helpers.dut_utils import is_container_running
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)
tag = "sonic-events-host"


def test_event(duthost, gnxi_path, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test host events")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_kernel_event,
             "event_kernel.json", "sonic-events-host:event-kernel", tag, False)
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, kill_critical_process,
             "process_exited_unexpectedly.json", "sonic-events-host:process-exited-unexpectedly",
             tag, False)
    backup_monit_config(duthost)
    customize_monit_config(
        duthost,
        [
            "> 90% for 10 times within 20 cycles then alert repeat every 1 cycles",
            "> 2% for 1 times within 5 cycles then alert repeat every 1 cycles"
        ]
    )
    try:
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, None,
                 "memory_usage.json", "sonic-events-host:memory-usage", tag, False)
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, None,
                 "disk_usage.json", "sonic-events-host:disk-usage", tag, False)
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, None,
                 "cpu_usage.json", "sonic-events-host:cpu-usage", tag, False)
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_mem_threshold_exceeded_alert,
                 "mem_threshold_exceeded.json", "sonic-events-host:mem-threshold-exceeded", tag)
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, restart_container,
                 "event_stopped_ctr.json", "sonic-events-host:event-stopped-ctr", tag, False)
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, mask_container,
                 "event_down_ctr.json", "sonic-events-host:event-down-ctr", tag, False)
    finally:
        restore_monit_config(duthost)
    add_test_watchdog_timeout_service(duthost)
    try:
        # We need to alot flat 60 seconds for watchdog timeout to fire since the timer is set to 60\
        # With a base limit of 30 seconds, we will use 90 seconds
        run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, None,
                 "watchdog_timeout.json", "sonic-events-host:watchdog-timeout", tag, False, 90)
    finally:
        delete_test_watchdog_timeout_service(duthost)


def trigger_mem_threshold_exceeded_alert(duthost):
    logger.info("Invoking memory checker with low threshold")
    cmd = "docker images | grep -w sonic-gnmi"
    if duthost.shell(cmd, module_ignore_errors=True)['rc'] == 0:
        duthost.shell("/usr/bin/memory_checker gnmi 100", module_ignore_errors=True)
    else:
        duthost.shell("/usr/bin/memory_checker telemetry 100", module_ignore_errors=True)


def trigger_kernel_event(duthost):
    logger.info("Invoking logger for kernel events")
    # syslog at github.com/torvalds/linux/blob/master/fs/squashfs/decompressor_multi.c#L193
    trigger_logger(duthost, "zlib decompression failed, data probably corrupt", "kernel")


def is_container_down(duthost, container):
    return not is_container_running(duthost, container)


def get_running_container(duthost):
    logger.info("Check if acms or snmp container is running")
    if is_container_running(duthost, "acms"):
        return "acms"
    elif is_container_running(duthost, "snmp"):
        return "snmp"
    else:
        return ""


def get_critical_process(duthost):
    logger.info("Check if snmpd/bgpd process is running")
    if is_container_running(duthost, "snmp"):
        pid = duthost.shell("docker exec snmp pgrep -f sonic_ax_impl")["stdout"]
        if pid != "":
            return pid, "snmp"
    if is_container_running(duthost, "bpg"):
        pid = duthost.shell("docker exec bgp pgrep -f bpgd")["stdout"]
        if pid != "":
            return pid, "bgpd"
    return "", ""


def restart_container(duthost):
    logger.info("Stopping container for event stopped event")
    container = get_running_container(duthost)
    assert container != "", "No available container for testing"
    duthost.shell("systemctl reset-failed {}".format(container))
    duthost.shell("systemctl restart {}".format(container))
    is_container_running = wait_until(100, 10, 0, duthost.is_service_fully_started, container)
    assert is_container_running, "{} not running after restart".format(container)


def mask_container(duthost):
    logger.info("Masking container for event down event")
    container = get_running_container(duthost)
    assert container != "", "No available container for testing"

    duthost.shell("systemctl mask {}".format(container))
    duthost.shell("docker stop {}".format(container))

    time.sleep(30)  # Wait 30 seconds for container_checker to fire event

    duthost.shell("systemctl unmask {}".format(container))
    duthost.shell("systemctl restart {}".format(container))


def kill_critical_process(duthost):
    logger.info("Killing critical process for exited unexpectedly event")
    pid, container = get_critical_process(duthost)
    assert pid != "", "No available process for testing"

    change_autorestart = False
    autorestart = duthost.shell("show feature autorestart {}".format(container))['stdout_lines']
    if "disabled" in str(autorestart):
        change_autorestart = True
        duthost.shell("config feature autorestart {} enabled".format(container))

    duthost.shell("docker exec {} kill -9 {}".format(container, pid), module_ignore_errors=True)

    # Wait until specified container is not running because of critical process exit
    wait_until(30, 5, 0, is_container_down, duthost, container)

    if change_autorestart:
        duthost.shell("config feature autorestart {} disabled".format(container))

    duthost.shell("systemctl reset-failed {}".format(container), module_ignore_errors=True)
    wait_until(100, 10, 0, duthost.is_service_fully_started, container)
