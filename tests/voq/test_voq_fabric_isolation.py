from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
import logging
import pytest
import random

logger = logging.getLogger(__name__)

# This test only runs on t2 systems.
pytestmark = [
    pytest.mark.topology('t2')
]

# This test checks if fabric link monitoring algorithm works as expected.
# To do this, the test updates fake errors ( crc errors ) on a
# fabric link first, then check if the auto_isolated state get updated in
# state_db for this link. Then it clears the fake errors on that link and
# check if the auto_siolated state get cleared as well.


def test_voq_fabric_isolation_status(duthosts, enum_frontend_dut_hostname):
    """Check if the fabric link isolation status updated correctly by
    the link monitoring algorithm"""

    logger.info("Checking fabric serdes link status")

    # Get a link
    duthost = duthosts[enum_frontend_dut_hostname]
    logger.info("Testing on duthost: {}".format(duthost.hostname))
    num_asics = duthost.num_asics()
    if num_asics > 1:
        asic = random.randrange(num_asics)
        asicName = "-n asic{}".format(asic)
        logger.info("Testing on asic: {}".format(asicName))
    else:
        asicName = ""
        logger.info("Testing on a single asic card")

    port = random.randint(0, 111)

    # sanity check if the link is up or not
    cmd = "sonic-db-cli {} STATE_DB hget 'FABRIC_PORT_TABLE|PORT{}' STATUS".format(asicName, port)
    cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
    logger.info(cmd_output)
    lnkStatus = cmd_output[0]
    if lnkStatus != "up":
        return

    pytest_assert(wait_until(1200, 60, 0, check_skip_poll, duthost, asicName, port, '20'),
                  "skip the first 20 polls for link monitoring")

    try:
        # Now prepare for the test:
        # set TEST_CRC_ERRORS to 0
        # set TEST_CODE_ERRORS to 0
        # set TEST to "TEST"
        # Check auto_isolation status

        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST_CRC_ERRORS 0".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST_CODE_ERRORS 0".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST 'TEST'".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")

        pytest_assert(wait_until(600, 60, 0, check_fabric_link_status, duthost, asicName, port, '0'),
                      "auto_isolated state for port {} should be 0".format(port))

        # Update fake crc errors by setting TEST_CRC_ERRORS to <num>
        # Check auto_isolation status
        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST_CRC_ERRORS 2".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")

        pytest_assert(wait_until(360, 60, 0, check_fabric_link_status, duthost, asicName, port, '1'),
                      "auto_isolated state for port {} should be 1".format(port))

        # Clear fake crc errors by setting TEST_CRC_ERRORS to 0
        # Check auto_isolation status
        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST_CRC_ERRORS 0".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")

        pytest_assert(wait_until(600, 60, 0, check_fabric_link_status, duthost, asicName, port, '0'),
                      "auto_isolated state for port {} should be 0".format(port))
    finally:
        # Clean up the test
        # set TEST to "product"

        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST_CRC_ERRORS 0".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST_CODE_ERRORS 0".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
        cmd = "sonic-db-cli {} STATE_DB hset 'FABRIC_PORT_TABLE|PORT{}' TEST 'product'".format(asicName, port)
        cmd_output = duthost.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")


def check_skip_poll(host, asicName, port, skip_poll):
    cmd = "sonic-db-cli {} STATE_DB hget 'FABRIC_PORT_TABLE|PORT{}' 'SKIP_CRC_ERR_ON_LNKUP_CNT'".format(asicName, port)
    cmd_output = host.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
    num_poll = cmd_output[0]
    if num_poll == skip_poll:
        return True
    else:
        return False


def check_fabric_link_status(host, asicName, port, state):
    cmd = "sonic-db-cli {} STATE_DB hget 'FABRIC_PORT_TABLE|PORT{}' AUTO_ISOLATED".format(asicName, port)
    cmd_output = host.shell(cmd, module_ignore_errors=True)["stdout"].split("\n")
    auto_isolated = cmd_output[0]
    if auto_isolated == state:
        return True
    else:
        return False
