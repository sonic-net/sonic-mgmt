#! /usr/bin/env python3

import logging

from run_events_test import run_test
from event_utils import backup_monit_config, customize_monit_config, restore_monit_config
from telemetry_utils import trigger_logger

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
    finally:
        restore_monit_config(duthost)


def trigger_mem_threshold_exceeded_alert(duthost):
    logger.info("Invoking memory checker with low threshold")
    duthost.shell("/usr/bin/memory_checker telemetry 100", module_ignore_errors=True)


def trigger_kernel_event(duthost):
    logger.info("Invoking logger for kernel events")
    # syslog at github.com/torvalds/linux/blob/master/fs/squashfs/decompressor_multi.c#L193
    trigger_logger(duthost, "zlib decompression failed, data probably corrupt", "kernel")
