import logging
import pytest
import time
from tests.common.helpers.assertions import pytest_assert

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
                    r"ps -ef | grep orchagent | grep -v grep | awk '{print $2}'",
                    module_ignore_errors=True)['stdout']
    logger.info('Get orchagent pid: {}'.format(pid))

    # pause orchagent and clear syslog
    duthost.shell(r"sudo kill -STOP {}".format(pid), module_ignore_errors=True)
    duthost.shell(r"sudo truncate -s 0 /var/log/syslog", module_ignore_errors=True)

    yield

    # resume orchagent and clear syslog
    duthost.shell(r"sudo kill -CONT {}".format(pid), module_ignore_errors=True)
    duthost.shell(r"sudo truncate -s 0 /var/log/syslog", module_ignore_errors=True)


def test_orchagent_watchdog(duthosts, enum_rand_one_per_hwsku_hostname, pause_orchagent):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    result = duthost.shell(
                        r"docker exec -i swss sh -c 'test -f /usr/bin/supervisor-proc-watchdog-listener && echo exist'",
                        module_ignore_errors=True)['stdout']
    logger.info('Check watchdog exist: {}'.format(result))
    if result != 'exist':
        pytest.skip("Skip orchagent watchdog test.")

    # wait watchdog emit alert
    WATCHDOG_TIMEOUT = 120
    current_attempt = 0
    while (True):
        time.sleep(SLEEP_TIME)
        alert = duthost.shell(
                            r"sudo cat /var/log/syslog | grep 'is stuck in namespace'",
                            module_ignore_errors=True)['stdout']
        logger.info('Get alert from host: {}'.format(alert))
        if "orchagent" in str(alert):
            return
        else:
            # orchagent watchdog timeout is 60 seconds
            if current_attempt >= WATCHDOG_TIMEOUT/SLEEP_TIME:
                pytest_assert(
                            False,
                            "orchagent watchdog did not been trigger after {} seconds".format(WATCHDOG_TIMEOUT))
            else:
                current_attempt += 1