import logging
import os
import pytest
import json
import re

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

EVENT_COUNTER_KEYS = ["missed_to_cache", "published"]
PUBLISHED = 1


def add_test_watchdog_timeout_service(duthost):
    logger.info("Adding mock watchdog.service to systemd")
    duthost.copy(src="telemetry/events/events_data/test-watchdog-timeout.service", dest="/etc/systemd/system/")
    duthost.shell("systemctl daemon-reload")
    duthost.shell("systemctl start test-watchdog-timeout.service")


def delete_test_watchdog_timeout_service(duthost):
    logger.info("Deleting mock test-watchdog-timeout.service")
    duthost.shell("systemctl stop test-watchdog-timeout.service", module_ignore_errors=True)
    duthost.shell("rm /etc/systemd/system/test-watchdog-timeout.service", module_ignore_errors=True)
    duthost.shell("systemctl daemon-reload")
    duthost.shell("systemctl reset-failed")


def backup_monit_config(duthost):
    logger.info("Backing up monit config files")
    duthost.shell("cp -f /etc/monit/monitrc ~/")
    duthost.shell("cp -f /etc/monit/conf.d/sonic-host ~/")


def restore_monit_config(duthost):
    logger.info("Restoring monit config files")
    duthost.shell("mv -f ~/monitrc /etc/monit/monitrc")
    duthost.shell("mv -f ~/sonic-host /etc/monit/conf.d/sonic-host")
    duthost.shell("systemctl restart monit")


def customize_monit_config(duthost, regex_pair):
    logger.info("Customizing monit files")
    # Modifying monitrc to reduce monit start delay time
    logger.info("Modifying monit config to eliminate start delay")
    duthost.replace(path="/etc/monit/monitrc", regexp='set daemon 60', replace='set daemon 10')
    duthost.replace(path="/etc/monit/monitrc", regexp='with start delay 300')
    original_line = regex_pair[0]
    new_line = regex_pair[1]
    if original_line != "":
        duthost.replace(path="/etc/monit/conf.d/sonic-host", regexp=original_line, replace=new_line)
    restart_monit(duthost)


def restart_monit(duthost):
    duthost.shell("systemctl restart monit")
    is_monit_running = wait_until(320,
                                  5,
                                  0,
                                  check_monit_running,
                                  duthost)
    pytest_assert(is_monit_running, "Monit is not running after restarted!")


def check_monit_running(duthost):
    monit_services_status = duthost.get_monit_services_status()
    return monit_services_status


def create_ip_file(duthost, data_dir, json_file, start_idx, end_idx):
    ip_file = os.path.join(data_dir, json_file)
    with open(ip_file, "w") as f:
        for i in range(start_idx, end_idx + 1):
            json_string = f'{{"test-event-source:test": {{"test_key": "test_val_{i}"}}}}'
            f.write(json_string + '\n')
    dest = "~/" + json_file
    duthost.copy(src=ip_file, dest=dest)
    duthost.shell("docker cp {} eventd:/".format(dest))


def event_publish_tool(duthost, json_file='', count=1):
    cmd = "docker exec eventd python /usr/bin/events_publish_tool.py"
    if json_file == '':
        cmd += " -c {}".format(count)
    else:
        cmd += " -f /{}".format(json_file)
    ret = duthost.shell(cmd)
    assert ret["rc"] == 0, "Unable to publish events via events_publish_tool.py"


def verify_received_output(received_file, N):
    key = "test_key"
    with open(received_file, 'r') as file:
        json_array = json.load(file)
        pytest_assert(len(json_array) == N, "Expected {} events, but found {}".format(N, len(json_array)))
        for i in range(0, len(json_array)):
            block = json_array[i]["test-event-source:test"]
            pytest_assert(key in block and len(re.findall('test_val_{}'.format(i + 1), block[key])) > 0,
                          "Missing key or incorrect value")


def restart_eventd(duthost):
    features_dict, succeeded = duthost.get_feature_status()
    if succeeded and ('eventd' not in features_dict or features_dict['eventd'] == 'disabled'):
        pytest.skip("eventd is disabled on the system")

    duthost.shell("systemctl reset-failed eventd")
    duthost.service(name="eventd", state="restarted")
    pytest_assert(wait_until(100, 10, 0, duthost.is_service_fully_started, "eventd"), "eventd not started")
    pytest_assert(wait_until(300, 10, 0, verify_counter_increase, duthost, 0, 2, PUBLISHED),
                  "events_monit_test has not published")


def reset_event_counters(duthost):
    for key in EVENT_COUNTER_KEYS:
        cmd = "sonic-db-cli COUNTERS_DB HSET COUNTERS_EVENTS:{} value 0".format(key)
        duthost.shell(cmd, module_ignore_errors=True)


def read_event_counters(duthost):
    stats = []
    for key in EVENT_COUNTER_KEYS:
        cmd = "sonic-db-cli COUNTERS_DB HGET COUNTERS_EVENTS:{} value".format(key)
        output = duthost.shell(cmd)['stdout']
        stats.append(int(output))
    return stats


def verify_counter_increase(duthost, current_value, increase, stat):
    current_counters = read_event_counters(duthost)
    current_stat_counter = current_counters[stat]
    return current_stat_counter >= current_value + increase
