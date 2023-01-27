import pytest
import pexpect
import logging
import time

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

DEFAULT_TMOUT = "900"
SET_TMOUT = "10"

def test_timeout(duthost_console, duthost):
    logger.info("Get default session idle timeout")
    default_tmout = duthost_console.send_command('echo $TMOUT')
    pytest_assert(default_tmout == DEFAULT_TMOUT, "default timeout on dut is not {} seconds".format(DEFAULT_TMOUT))

    logger.info("Set session idle timeout")
    duthost_console.send_command('export TMOUT={}'.format(SET_TMOUT))
    set_tmout = duthost_console.send_command('echo $TMOUT')
    pytest_assert(set_tmout == SET_TMOUT, "set timeout fail")

    time.sleep(15)
    duthost_console.send_command("\n", expect_string=r"{} login:".format(duthost.hostname))
