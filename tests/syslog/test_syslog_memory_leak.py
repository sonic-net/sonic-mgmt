import logging
import os
import pytest
import random
import time

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_LOG_GENERATOR_FILE = os.path.join(BASE_DIR, 'bulk_log_generator.py')
REMOTE_LOG_GENERATOR_FILE = os.path.join('/tmp', 'bulk_log_generator.py')
DOCKER_LOG_GENERATOR_FILE = '/bulk_log_generator.py'

pytestmark = [
    pytest.mark.topology("any")
]


def get_rsyslogd_pid(duthost, service_name):
    """Get the rsyslogd pid running in a container

    Args:
        duthost (object): DUT host object
        service_name (str): Service name
    """
    cmd = "docker exec -i {} bash -c 'pidof rsyslogd'".format(service_name)
    return duthost.command(cmd, module_ignore_errors=True)['stdout'].strip()


def get_memory_usage(rand_selected_dut, service_name):
    """Get the memory used by rsyslogs for a container

    Args:
        duthost (object): DUT host object
        service_name (str): Service name
    """
    cmd = "docker exec -i {} bash -c 'ps -o rss -C rsyslogd'".format(service_name)
    cmd_output = rand_selected_dut.command(cmd, module_ignore_errors=True)['stdout'].strip()
    mem_usage = int(cmd_output.split("\n")[1].strip())
    return mem_usage


def generate_syslog(duthost, service_name):
    """Generate syslog with a script

    Args:
        duthost (object): DUT host object
        service_name (str): Service name
    """
    run_generator_cmd = "docker exec -i {} bash -c 'python3 {}'".format(service_name, DOCKER_LOG_GENERATOR_FILE)
    return duthost.command(run_generator_cmd)


def test_container_syslog_memory_leak(rand_selected_dut, ignore_containers=[]):
    """Test syslog memory leak for each container and verify memory does not leak. Basic flow:
        1. For each container
        2. Filter disabled container
        3. Filter un-supported container
        4. Generate syslog via a script and get the memory usage by rsyslogd
        5. Wait for 60 secs and re-check the memory usage
        6. Fail the test if the memory usage increases.

    Args:
        rand_selected_dut (object): DUT host object
        ignore_containers (list): container list that will be ignored for this test
    """
    feature_data = rand_selected_dut.show_and_parse('show feature status')
    random.shuffle(feature_data)

    # Copy tests/syslog/bulk_log_generator.py to DUT
    rand_selected_dut.copy(src=LOCAL_LOG_GENERATOR_FILE, dest=REMOTE_LOG_GENERATOR_FILE)

    for item in feature_data:
        service_name = item['feature']
        if service_name in ignore_containers:
            continue

        logger.info('Start syslog memory leak test for container {}'.format(service_name))
        if item['state'] in ['disabled', 'always_disabled']:
            logger.info('Container {} is {}'.format(service_name, item['state']))
            continue

        rsyslog_pid = get_rsyslogd_pid(rand_selected_dut, service_name)
        if not rsyslog_pid:
            continue

        memory_bef_log_generation = get_memory_usage(rand_selected_dut, service_name)
        logger.info('Memory used by rsyslogd for {} is {}'.format(service_name, memory_bef_log_generation))
        rand_selected_dut.command(
            'docker cp {} {}:{}'.format(REMOTE_LOG_GENERATOR_FILE, service_name, DOCKER_LOG_GENERATOR_FILE))
        logger.info('Generate bulk syslog for container {}'.format(service_name))
        generate_syslog(rand_selected_dut, service_name)

        time.sleep(60)

        memory_after_log_generation = get_memory_usage(rand_selected_dut, service_name)
        logger.info('Memory used by rsyslogd after generating syslog for {} is {}'
                    .format(service_name, memory_after_log_generation))

        pytest_assert(memory_after_log_generation <= memory_bef_log_generation,
                      'Memory leak detected in {} container. Before: {}, After: {}'
                      .format(service_name, memory_bef_log_generation, memory_after_log_generation))
