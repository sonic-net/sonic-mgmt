import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_assert
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any')
]

logger = logging.getLogger(__name__)

SLEEP_TIME = 10


@pytest.fixture
def pause_orchagent(duthost):
    # find orchagent pid
    pid = duthost.shell(
                    r"pgrep orchagent",
                    module_ignore_errors=True)['stdout']
    logger.info('Get orchagent pid: {}'.format(pid))

    # pause orchagent and clear syslog
    duthost.shell(r"sudo kill -STOP {}".format(pid), module_ignore_errors=True)
    duthost.shell(r"sudo truncate -s 0 /var/log/syslog", module_ignore_errors=True)

    yield

    # resume orchagent and clear syslog
    duthost.shell(r"sudo kill -CONT {}".format(pid), module_ignore_errors=True)
    duthost.shell(r"sudo truncate -s 0 /var/log/syslog", module_ignore_errors=True)


def check_process_status(duthost, process):
    result = duthost.shell(
                        r"docker exec -i swss sh -c 'ps -au | grep {}".format(process),
                        module_ignore_errors=True)['stdout']
    logger.info('Check supervisor-proc-exit-listener running: {}'.format(result))
    return result


def make_ut_fail_if_process_not_running(duthost):
    result = check_process_status(duthost, "/usr/bin/supervisor-proc-exit-listener'")
    if not result:
        pytest.fail("Watchfog process does not running.")

    # if orchagent not running, alert will never been triggered
    result = check_process_status(duthost, "/usr/bin/orchagent'")
    if not result:
        pytest.fail("Orchagent does not running.")


def create_log_analyzer(duthost):
    marker_prefix = "test_orchagent_heartbeat_checker_{}".format(time.time())
    loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix=marker_prefix)
    loganalyzer.expect_regex = ["Process \'orchagent\' is stuck in namespace"]
    marker = loganalyzer.init()
    return loganalyzer, marker


def test_orchagent_watchdog(duthosts, enum_rand_one_per_hwsku_hostname, pause_orchagent):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # if watchdog_processes does not exits, watchdog been disabled
    result = duthost.shell(
                        r"docker exec -i swss sh -c 'test -f /etc/supervisor/watchdog_processes && echo exist'",
                        module_ignore_errors=True)['stdout']
    logger.info('Check watchdog exist: {}'.format(result))
    if result != 'exist':
        pytest.skip("Skip orchagent watchdog test.")

    make_ut_fail_if_process_not_running(duthost)

    # initialize LogAnalyzer for check stuck warning message
    last_loganalyzer, last_marker = create_log_analyzer(duthost)

    # wait watchdog emit alert, orchagent watchdog timeout is 60 seconds
    WATCHDOG_TIMEOUT = 120
    current_attempt = 0
    while (True):
        time.sleep(SLEEP_TIME)

        # LogAnalyzer can only analyze once, so create new analyzer for next iteration
        new_loganalyzer, new_marker = create_log_analyzer(duthost)
        analysis = last_loganalyzer.analyze(last_marker, fail=False)

        last_loganalyzer = new_loganalyzer
        last_marker = new_marker

        logger.info('Get alert from host: {}'.format(analysis['total']['expected_match']))
        if analysis['total']['expected_match']:
            # found orchagent stuck alert
            return
        else:
            # orchagent watchdog timeout is 60 seconds
            if current_attempt >= WATCHDOG_TIMEOUT/SLEEP_TIME:
                pytest_assert(
                            False,
                            "orchagent watchdog did not been trigger after {} seconds".format(WATCHDOG_TIMEOUT))
            else:
                make_ut_fail_if_process_not_running(duthost)
                current_attempt += 1
