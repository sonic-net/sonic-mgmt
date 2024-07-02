import contextlib
import logging
import os
import pytest
import random
import time

from tests.common.config_reload import config_reload
from tests.common.utilities import skip_release
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer
from tests.common.helpers.sonic_db import SonicDbCli

logger = logging.getLogger(__name__)

RATE_LIMIT_BURST = 100
RATE_LIMIT_INTERVAL = 10
# Generate 101 packets in tests/syslog/log_generator.py, so that 1 log message will be dropped by rsyslogd
LOG_MESSAGE_GENERATE_COUNT = 101
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_LOG_GENERATOR_FILE = os.path.join(BASE_DIR, 'log_generator.py')
REMOTE_LOG_GENERATOR_FILE = os.path.join('/tmp', 'log_generator.py')
DOCKER_LOG_GENERATOR_FILE = '/log_generator.py'
# rsyslogd prints this log when rate-limiting reached
LOG_EXPECT_SYSLOG_RATE_LIMIT_REACHED = '.*begin to drop messages due to rate-limiting.*'
# Log pattern for tests/syslog/log_generator.py
LOG_EXPECT_LAST_MESSAGE = '.*{}rate-limit-test: This is a test log:.*'

pytestmark = [
    pytest.mark.topology("any")
]


@pytest.fixture(autouse=True, scope="module")
def check_image_version(rand_selected_dut):
    """Skips this test if the SONiC image installed on DUT is older than 202205

    Args:
        duthost: Hostname of DUT.

    Returns:
        None.
    """
    skip_release(rand_selected_dut, ["201811", "201911", "202012", "202106", "202205"])


@pytest.fixture(autouse=True, scope="module")
def restore_rate_limit(rand_selected_dut):
    """Fixture to automatically restore syslog rate limit configuration

    Args:
        rand_selected_dut (object): DUT host object
    """
    output = rand_selected_dut.command('config syslog --help')['stdout']
    manually_enable_feature = False
    if 'rate-limit-feature' in output:
        # in 202305, the feature is disabled by default for warmboot/fastboot
        # performance, need manually enable it via command
        rand_selected_dut.command('config syslog rate-limit-feature enable')
        manually_enable_feature = True
    container_data = rand_selected_dut.show_and_parse('show syslog rate-limit-container')
    host_data = rand_selected_dut.show_and_parse('show syslog rate-limit-host')

    yield

    for item in container_data:
        rand_selected_dut.command('config syslog rate-limit-container {} -b {} -i {}'.format(
            item['service'], item['burst'], item['interval']))

    rand_selected_dut.command('config syslog rate-limit-host -b {} -i {}'.format(
        host_data[0]['burst'], host_data[0]['interval']))
    rand_selected_dut.command('config save -y')
    if manually_enable_feature:
        rand_selected_dut.command('config syslog rate-limit-feature disable')


@pytest.mark.disable_loganalyzer
def test_syslog_rate_limit(rand_selected_dut):
    """Test case for syslog rate limit

    Args:
        rand_selected_dut (object): DUT host object
    """
    # Copy tests/syslog/log_generator.py to DUT
    rand_selected_dut.copy(src=LOCAL_LOG_GENERATOR_FILE, dest=REMOTE_LOG_GENERATOR_FILE)

    verify_container_rate_limit(rand_selected_dut)
    verify_host_rate_limit(rand_selected_dut)

    # Save configuration and reload, verify the configuration can be loaded
    logger.info('Persist syslog rate limit configuration to DB and do config reload')
    rand_selected_dut.command('config save -y')
    config_reload(rand_selected_dut)

    # database does not support syslog rate limit configuration persist
    verify_container_rate_limit(rand_selected_dut, ignore_containers=['database'])
    verify_host_rate_limit(rand_selected_dut)


def verify_container_rate_limit(rand_selected_dut, ignore_containers=[]):
    """Config syslog rate limit for each container and verify it works. Basic flow:
        1. For each container
        2. Filter disabled container
        3. Filter un-supported container
        4. Config syslog rate limit
        5. Verify syslog rate limit with "show syslog rate-limit-container" command
        6. Generate syslog via a script and verify the rate limit configuration works
        7. Disable syslog rate limit by setting interval and burst to 0
        8. Verify syslog rate limit with "show syslog rate-limit-container" command
        9. Generate syslog via a script and verify there is no rate limit anymore

    Args:
        rand_selected_dut (object): DUT host object
        ignore_containers (list): container list that will be ignored for this test
    """
    config_db = SonicDbCli(rand_selected_dut, 'CONFIG_DB')
    feature_data = rand_selected_dut.show_and_parse('show feature status')
    random.shuffle(feature_data)
    for item in feature_data:
        service_name = item['feature']
        if service_name in ignore_containers:
            continue
        container_name = service_name
        if rand_selected_dut.is_multi_asic:
            config_facts = rand_selected_dut.get_running_config_facts()
            if config_facts['FEATURE'][service_name]['has_per_asic_scope'] == "True":
                asic_ids = rand_selected_dut.get_asic_ids()
                asic_id = random.choice(asic_ids)
                container_name = service_name + str(asic_id)

        logger.info('Start syslog rate limit test for container {}'.format(container_name))
        if item['state'] in ['disabled', 'always_disabled']:
            logger.info('Container {} is {}'.format(service_name, item['state']))
            continue

        support_syslog_rate_limit = config_db.hget_key_value('FEATURE|{}'.format(service_name),
                                                             'support_syslog_rate_limit')
        if support_syslog_rate_limit.lower() != 'true':
            logger.info('Container {} does not support syslog rate limit configuration'.format(container_name))
            verify_config_rate_limit_fail(rand_selected_dut, container_name)
            continue

        rsyslog_pid = get_rsyslogd_pid(rand_selected_dut, container_name)
        rand_selected_dut.command('config syslog rate-limit-container {} -b {} -i {}'.format(
            service_name, RATE_LIMIT_BURST, RATE_LIMIT_INTERVAL))
        assert wait_rsyslogd_restart(rand_selected_dut, container_name, rsyslog_pid)
        rate_limit_data = rand_selected_dut.show_and_parse('show syslog rate-limit-container {}'.format(service_name))
        pytest_assert(rate_limit_data[0]['interval'] == str(RATE_LIMIT_INTERVAL),
                      'Expect rate limit interval {}, actual {}'.format(RATE_LIMIT_INTERVAL,
                                                                        rate_limit_data[0]['interval']))
        pytest_assert(rate_limit_data[0]['burst'] == str(RATE_LIMIT_BURST),
                      'Expect rate limit burst {}, actual {}'.format(RATE_LIMIT_BURST, rate_limit_data[0]['burst']))

        rand_selected_dut.command(
            'docker cp {} {}:{}'.format(REMOTE_LOG_GENERATOR_FILE, container_name, DOCKER_LOG_GENERATOR_FILE))
        verify_rate_limit_with_log_generator(rand_selected_dut,
                                             container_name,
                                             'syslog_rate_limit_{}-interval_{}_burst_{}'.format(service_name,
                                                                                                RATE_LIMIT_INTERVAL,
                                                                                                RATE_LIMIT_BURST),
                                             [LOG_EXPECT_SYSLOG_RATE_LIMIT_REACHED,
                                              LOG_EXPECT_LAST_MESSAGE.format(container_name + '#')],
                                             RATE_LIMIT_BURST + 1)

        rsyslog_pid = get_rsyslogd_pid(rand_selected_dut, container_name)
        rand_selected_dut.command('config syslog rate-limit-container {} -b {} -i {}'.format(service_name, 0, 0))
        assert wait_rsyslogd_restart(rand_selected_dut, container_name, rsyslog_pid)
        rate_limit_data = rand_selected_dut.show_and_parse('show syslog rate-limit-container {}'.format(service_name))
        pytest_assert(rate_limit_data[0]['interval'] == '0',
                      'Expect rate limit interval {}, actual {}'.format(0, rate_limit_data[0]['interval']))
        pytest_assert(rate_limit_data[0]['burst'] == '0',
                      'Expect rate limit burst {}, actual {}'.format(0, rate_limit_data[0]['burst']))

        verify_rate_limit_with_log_generator(rand_selected_dut,
                                             container_name,
                                             'syslog_rate_limit_{}-interval_{}_burst_{}'.format(service_name, 0, 0),
                                             [LOG_EXPECT_LAST_MESSAGE.format(container_name + '#')],
                                             LOG_MESSAGE_GENERATE_COUNT)
        break  # we only randomly test 1 container to reduce test time


def verify_host_rate_limit(rand_selected_dut):
    """Config syslog rate limit for host and verify it works. Basic flow:
        1. Config syslog rate limit
        2. Verify syslog rate limit with "show syslog rate-limit-host" command
        3. Generate syslog via a script and verify the rate limit configuration works
        4. Disable syslog rate limit by setting interval and burst to 0
        5. Verify syslog rate limit with "show syslog rate-limit-host" command
        6. Generate syslog via a script and verify there is no rate limit anymore

    Args:
        rand_selected_dut (object): DUT host object
    """
    logger.info('Start syslog rate limit test for host')
    with expect_host_rsyslog_restart(rand_selected_dut):
        cmd = 'config syslog rate-limit-host -b {} -i {}'.format(RATE_LIMIT_BURST, RATE_LIMIT_INTERVAL)
        rand_selected_dut.command(cmd)
    rate_limit_data = rand_selected_dut.show_and_parse('show syslog rate-limit-host')
    pytest_assert(rate_limit_data[0]['interval'] == str(RATE_LIMIT_INTERVAL),
                  'Expect rate limit interval {}, actual {}'.format(RATE_LIMIT_INTERVAL,
                                                                    rate_limit_data[0]['interval']))
    pytest_assert(rate_limit_data[0]['burst'] == str(RATE_LIMIT_BURST),
                  'Expect rate limit burst {}, actual {}'.format(RATE_LIMIT_BURST, rate_limit_data[0]['burst']))

    verify_rate_limit_with_log_generator(rand_selected_dut,
                                         'host',
                                         'syslog_rate_limit_host_interval_{}_burst_{}'.format(RATE_LIMIT_INTERVAL,
                                                                                              RATE_LIMIT_BURST),
                                         [LOG_EXPECT_SYSLOG_RATE_LIMIT_REACHED, LOG_EXPECT_LAST_MESSAGE.format('')],
                                         RATE_LIMIT_BURST + 1,
                                         is_host=True)

    with expect_host_rsyslog_restart(rand_selected_dut):
        rand_selected_dut.command('config syslog rate-limit-host -b {} -i {}'.format(0, 0))
    rate_limit_data = rand_selected_dut.show_and_parse('show syslog rate-limit-host')
    pytest_assert(rate_limit_data[0]['interval'] == '0',
                  'Expect rate limit interval {}, actual {}'.format(0, rate_limit_data[0]['interval']))
    pytest_assert(rate_limit_data[0]['burst'] == '0',
                  'Expect rate limit burst {}, actual {}'.format(0, rate_limit_data[0]['burst']))

    verify_rate_limit_with_log_generator(rand_selected_dut,
                                         'host',
                                         'syslog_rate_limit_host_interval_{}_burst_{}'.format(0, 0),
                                         [LOG_EXPECT_LAST_MESSAGE.format('')],
                                         LOG_MESSAGE_GENERATE_COUNT,
                                         is_host=True)


def verify_config_rate_limit_fail(duthost, service_name):
    """For service that does not support rate limit configuration, verify that config rate limit fails

    Args:
        duthost (object): DUT object
        service_name (str): Service name
    """
    cmd = 'config syslog rate-limit-container {} -b {} -i {}'.format(
        service_name, RATE_LIMIT_BURST, RATE_LIMIT_INTERVAL)
    output = duthost.command(cmd, module_ignore_errors=True)['stderr']
    pytest_assert('Error' in output, 'Error: config syslog rate limit for {}: {}'.format(service_name, output))


def verify_rate_limit_with_log_generator(duthost, service_name, log_marker, expect_log_regex, expect_log_matches,
                                         is_host=False):
    """Generator syslog with a script and verify that syslog rate limit reached

    Args:
        duthost (object): DUT host object
        service_name (str): Service name
        log_marker (str): Log start marker
        expect_log_regex (list): A list of expected log message regular expression
        expect_log_matches (int): Number of log lines matches the expect_log_regex
        is_host (bool, optional): Verify on host side or container side. Defaults to False.
    """
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=log_marker)
    loganalyzer.expect_regex = expect_log_regex
    loganalyzer.expected_matches_target = expect_log_matches

    if is_host:
        run_generator_cmd = "python3 {}".format(REMOTE_LOG_GENERATOR_FILE)
    else:
        run_generator_cmd = "docker exec -i {} bash -c 'python3 {}'".format(service_name, DOCKER_LOG_GENERATOR_FILE)

    with loganalyzer:
        duthost.command(run_generator_cmd)


def get_host_rsyslogd_pid(duthost):
    cmd = 'systemctl show --property MainPID --value rsyslog'
    return int(duthost.command(cmd)['stdout'].strip())


@contextlib.contextmanager
def expect_host_rsyslog_restart(duthost, timeout=30):
    current_pid = get_host_rsyslogd_pid(duthost)

    yield

    logger.info('Waiting for host rsyslogd to restart')
    begin = time.time()
    cmd = 'systemctl is-active rsyslog'
    while time.time() < begin + timeout:
        if get_host_rsyslogd_pid(duthost) != current_pid:
            output = duthost.command(cmd, module_ignore_errors=True)['stdout'].strip()
            if output == 'active':
                logger.info('Host rsyslogd restarted')
                return

        time.sleep(1)

    raise TimeoutError('Timeout waiting for host rsyslogd to restart')


def wait_rsyslogd_restart(duthost, service_name, old_pid):
    logger.info('Waiting rsyslogd restart')
    cmd = "docker exec -i {} bash -c 'supervisorctl status rsyslogd'".format(service_name)
    wait_time = 30
    while wait_time > 0:
        wait_time -= 1
        if get_rsyslogd_pid(duthost, service_name) == old_pid:
            time.sleep(1)
            continue

        output = duthost.command(cmd, module_ignore_errors=True)['stdout'].strip()
        if 'RUNNING' in output:
            logger.info('Rsyslogd restarted')
            return True

        time.sleep(1)

    logger.error('Rsyslogd failed to restart')
    return False


def get_rsyslogd_pid(duthost, service_name):
    cmd = "docker exec -i {} bash -c 'pidof rsyslogd'".format(service_name)
    return duthost.command(cmd, module_ignore_errors=True)['stdout'].strip()
