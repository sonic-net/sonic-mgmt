import binascii
import logging
import pytest
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.tacacs.tacacs_helper import start_tacacs_server


logger = logging.getLogger(__name__)


@pytest.fixture
def ensure_tacacs_server_running_after_ut(duthosts, enum_rand_one_per_hwsku_hostname):
    """make sure tacacs server running after UT finish"""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    yield

    start_tacacs_server(duthost)


def check_server_received(ptfhost, data, timeout=30):
    """
        Check if tacacs server received the data.
    """
    hex = binascii.hexlify(data.encode('ascii'))
    hex_string = hex.decode()

    """
      Extract received data from tac_plus.log, then use grep to check if the received data contains hex_string:
            1. tac_plus server start with '-d 2058' parameter to log received data in following format in tac_plus.log:
                    Thu Mar  9 06:26:16 2023 [75483]: data[140] = 0xf8, xor'ed with hash[12] = 0xab -> 0x53
                    Thu Mar  9 06:26:16 2023 [75483]: data[141] = 0x8d, xor'ed with hash[13] = 0xc2 -> 0x4f
                In above log, the 'data[140] = 0xf8' is received data.

            2. Following sed command will extract the received data from tac_plus.log:
                    sed -n 's/.*-> 0x\(..\).*/\\1/p'  /var/log/tac_plus.log     # noqa W605

            3. Following set command will join all received data to hex string:
                    sed ':a; N; $!ba; s/\\n//g'

            4. Then the grep command will check if the received hex data containes expected hex string.
                    grep '{0}'".format(hex_string)

      Also suppress following Flake8 error/warning:
            W605 : Invalid escape sequence. Flake8 can't handle sed command escape sequence, so will report false alert.
            E501 : Line too long. Following sed command difficult to split to multiple line.
    """
    sed_command = "sed -n 's/.*-> 0x\(..\).*/\\1/p'  /var/log/tac_plus.log | sed ':a; N; $!ba; s/\\n//g' | grep '{0}'".format(hex_string)   # noqa W605 E501

    # After tacplus service receive data, it need take some time to update to log file.
    def log_exist(ptfhost, sed_command):
        res = ptfhost.shell(sed_command)
        logger.info(sed_command)
        logger.info(res["stdout_lines"])
        return len(res["stdout_lines"]) > 0

    exist = wait_until(timeout, 1, 0, log_exist, ptfhost, sed_command)
    pytest_assert(exist, "Not found data: {} in tacplus server log".format(data))


def get_auditd_config_reload_timestamp(duthost):
    res = duthost.shell("sudo journalctl -u auditd --boot | grep 'audisp-tacplus re-initializing configuration'")
    logger.info("aaa config file timestamp {}".format(res["stdout_lines"]))

    if len(res["stdout_lines"]) == 0:
        return ""

    return res["stdout_lines"][-1]


def change_and_wait_aaa_config_update(duthost, command, last_timestamp=None, timeout=10):
    if not last_timestamp:
        last_timestamp = get_auditd_config_reload_timestamp(duthost)

    duthost.shell(command)

    # After AAA config update, hostcfgd will modify config file and notify auditd reload config
    # Wait auditd reload config finish
    def log_exist(duthost):
        latest_timestamp = get_auditd_config_reload_timestamp(duthost)
        return latest_timestamp != last_timestamp

    exist = wait_until(timeout, 1, 0, log_exist, duthost)
    pytest_assert(exist, "Not found aaa config update log: {}".format(command))
