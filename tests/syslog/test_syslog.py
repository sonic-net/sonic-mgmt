import logging
import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology("any")
]

SYSLOG_STARTUP_TIMEOUT = 30
SYSLOG_STARTUP_POLLING_INTERVAL = 3

SYSLOG_MESSAGE_TEST_TIMEOUT = 10


def config_syslog_srv(ptfhost):
    logger.info("Configuring the syslog server")

    # Add the imudp configuration if not present
    ptfhost.shell("sed -i -e '/^input(type/d' -e '/^module/d' /etc/rsyslog.conf; sed -i -e '$amodule(load=\"imudp\")' -e '$ainput(type=\"imudp\" port=\"514\")' /etc/rsyslog.conf")

    # Restart Syslog Daemon
    logger.info("Restarting rsyslog service")
    ptfhost.shell("service rsyslog stop && rm -rf /var/log/syslog && touch /var/log/syslog && service rsyslog restart")

    # Wait a little bit for service to start
    rsyslog_running_msg="rsyslogd is running"
    def _is_syslog_running():
        result = ptfhost.shell("service rsyslog status | grep \"{}\"".format(rsyslog_running_msg))["stdout"]
        return rsyslog_running_msg in result

    logger.debug("Waiting for rsyslog server to restart")
    wait_until(SYSLOG_STARTUP_TIMEOUT, SYSLOG_STARTUP_POLLING_INTERVAL, _is_syslog_running)
    logger.debug("rsyslog server restarted")


@pytest.fixture(scope="module")
def config_dut(tbinfo, duthost):
    logger.info("Configuring the DUT")
    local_syslog_srv_ip = tbinfo["ptf_ip"]
    logger.info("test_syslog_srv_ip %s", local_syslog_srv_ip)

    # Add Rsyslog destination for testing
    duthost.shell("sudo config syslog add {}".format(local_syslog_srv_ip))
    logger.debug("Added new rsyslog server IP {}".format(local_syslog_srv_ip))

    yield

    # Remove the syslog configuration
    duthost.shell("sudo config syslog del {}".format(local_syslog_srv_ip))


def test_syslog(duthost, ptfhost, config_dut):
    logger.info("Starting syslog tests")
    test_message = "Basic Test Message"

    logger.debug("Configuring rsyslog server")
    config_syslog_srv(ptfhost)

    logger.debug("Generating log message from DUT")
    # Generate a syslog from the DUT
    duthost.shell("logger --priority INFO {}".format(test_message))

    # Check syslog messages for the test message
    def _check_syslog():
        result = ptfhost.shell("grep {} /var/log/syslog | grep -v ansible | grep -c \"{}\""
                               .format(duthost.hostname, test_message))["stdout"]
        return result != "0"

    pytest_assert(wait_until(SYSLOG_MESSAGE_TEST_TIMEOUT, 1, _check_syslog),
                  "Test syslog message not seen on the server after {}s".format(SYSLOG_MESSAGE_TEST_TIMEOUT))
