import pytest
import pexpect
import logging
import time
import re

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.device_type("physical")

]

TOTAL_PACKETS = 100
logger = logging.getLogger(__name__)

def test_console_escape(duthost_console):
    """
    Test reverse SSH are working as expect.
    Verify serial session is available after connect DUT via reverse SSH
    """
    try:
        child = pexpect.spawn("ping 127.0.0.1 -c {} -i 1".format(TOTAL_PACKETS))
        time.sleep(5)
        child.sendcontrol('C')
        child.expect("\^C")
        match = re.search(r'(\d) packets transmitted', child.read())
        pytest_assert(int(match.group(1)) < TOTAL_PACKETS, "Escape Character does not work.")
    except Exception as e:
        pytest.fail("Not able to login DUT via console")

