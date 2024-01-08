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
    pid = None
    retry = 3
    while True:
        retry -= 1
        # find orchagent pid: https://www.man7.org/linux/man-pages/man1/pidof.1.html
        pid_result = duthost.shell(
                        r"pidof orchagent",
                        module_ignore_errors=True)

        rc = pid_result['rc']
        if rc == 1:
            logger.info('Get orchagent pid failed: {}'.format(pid_result))

            if retry <= 0:
                # break UT because orchagent pause failed
                pytest.fail("Can't pause Orchagent by pid.")
            else:
                continue

        pid = pid_result['stdout']
        logger.info('Get orchagent pid: {}'.format(pid))

        # pause orchagent
        duthost.shell(r"sudo kill -STOP {}".format(pid), module_ignore_errors=True)

        # validate orchagent paused, the stat colum should be Tl:
        # root         124  0.3  1.6 596616 63600 pts/0    Tl   02:33   0:06 /usr/bin/orchagent
        result = check_process_status(duthost, "'Tl.*/usr/bin/orchagent''")
        if result:
            # continue UT when Orchagent paused
            break
        else:
            # collect log for investigation not paused reason
            duthost.shell(r"sudo ps -auxww", module_ignore_errors=True)
            duthost.shell(r"sudo cat /var/log/syslog | grep orchagent", module_ignore_errors=True)

            if retry <= 0:
                # break UT because orchagent pause failed
                pytest.fail("Can't pause Orchagent by pid.")

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
