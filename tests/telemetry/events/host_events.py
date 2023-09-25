#! /usr/bin/env python3

import logging
import time
from run_events_test import run_test
from event_utils import backup_monit_config, customize_monit_config, restore_monit_config
from telemetry_utils import trigger_logger
from tests.common.helpers.dut_utils import is_container_running

logger = logging.getLogger(__name__)
tag = "sonic-events-host"


def test_event(duthost, gnxi_path, ptfhost, data_dir, validate_yang):
    logger.info("Beginning to test host events")
    run_test(duthost, gnxi_path, ptfhost, data_dir, validate_yang, trigger_kernel_event,
             "event_kernel.json", "sonic-events-host:event-kernel", tag, False)
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


def trigger_mem_threshold_exceeded_alert(duthost):
    logger.info("Invoking memory checker with low threshold")
    duthost.shell("/usr/bin/memory_checker telemetry 100", module_ignore_errors=True)


def trigger_kernel_event(duthost):
    logger.info("Invoking logger for kernel events")
    # syslog at github.com/torvalds/linux/blob/master/fs/squashfs/decompressor_multi.c#L193
    trigger_logger(duthost, "zlib decompression failed, data probably corrupt", "kernel")


def get_running_container(duthost):
    logger.info("Check if acms or snmp container is running")
    container = "acms"
    container_running = is_container_running(duthost, container)
    if not container_running:
        container = "snmp"
    else:
        return container
    container_running = is_container_running(duthost, container)
    if not container_running:
        return ""
    return container


def restart_container(duthost):
    logger.info("Stopping container for event stopped event")
    container = get_running_container(duthost)
    assert container != "", "No available container for testing"

    duthost.shell("systemctl restart {}".format(container))


def mask_container(duthost):
    logger.info("Masking container for event down event")
    container = get_running_container(duthost)
    assert container != "", "No available container for testing"

    duthost.shell("systemctl mask {}".format(container))
    duthost.shell("docker stop {}".format(container))

    time.sleep(30)  # Wait 30 seconds for container_checker to fire event

    duthost.shell("systemctl unmask {}".format(container))
    duthost.shell("systemctl restart {}".format(container))
