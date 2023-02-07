#! /usr/bin/env/python3

import json
import logging
import os
import time

from run_events_test import run_test

logger = logging.getLogger(__name__)
tag = "sonic-events-host"

def test_event(duthost, localhost, run_cmd, data_dir, validate_yang):
    test_mem_threshold_exceeded(duthost, localhost, run_cmd, data_dir, validate_yang)
    test_process_exited_unexpectedly(duthost, localhost, run_cmd, data_dir, validate_yang)
    test_event_down_ctr(duthost, localhost, run_cmd, data_dir, validate_yang)
    test_event_stopped_ctr(duthost, localhost, run_cmd, data_dir, validate_yang)


def test_mem_threshold_exceeded(duthost, localhost, run_cmd, data_dir, validate_yang):
    run_test(duthost, localhost, run_cmd, data_dir, validate_yang, invoke_memory_checker, "mem_threshold_exceeded.json", tag. "mem-threshold-exceeded")


def test_process_exited_unexpectedly(duthost, localhost, run_cmd, data_dir, validate_yang):
    run_test(duthost, localhost run_cmd, data_dir, validate_yang, stop_bgpd_process, "process_exited_unexpectedly.json", tag, "process-exited-unexpectedly")


def test_process_not_running(duthost, localhost, run_cmd, data_dir, validate_yang):
    run_test(duthost, localhost, run_cmd, data_dir, validate_yang, stop_bgpd_process, "process_not_running", tag, "process-not-running", 80)


def test_event_stopped_ctr(duthost, localhost, run_cmd, data_dir, validate_yang):
    run_test(duthost, localhost, run_cmd, data_dir, validate_yang, stop_bgp_container, "event_stopped_ctr.json", tag, "event-stopped-ctr")


def test_event_down_ctr(duthost, localhost, run_cmd, data_dir, validate_yang):
    run_test(duthost, localhost, run_cmd, data_dir, validate_yang, stop_bgp_container, "event_down_ctr.json", tag, "event-down-ctr", 80)


def stop_bgp_container(duthost):
    logger.info("Stopping bgp container")
    duthost.shell("docker stop bgp")
    time.sleep(30) # wait 30 seconds for bgp to stay down until container_checker script fires_event
    duthost.shell("docker start bgp")


def stop_bgpd_process(duthost):
    logger.info("Stopping critical process bgpd in bgp container")
    duthost.shell("docker exec -i bgp kill -9 bgpd")
    duthost.shell("docker restart bgp")


def invoke_memory_checker(duthost):
    logger.info("Invoke memory_checker script with low threshold")
    duthost.shell("python3 /usr/bin/memory_checker telemetry 100", module_ignore_errors=True)
