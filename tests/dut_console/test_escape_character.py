import pexpect
import logging
import time
import re
import pytest

from tests.common.helpers.assertions import pytest_assert

TOTAL_PACKETS = 100
logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_console_escape(duthost_console, duthost):
    child = pexpect.spawn("ping 127.0.0.1 -c {} -i 1".format(TOTAL_PACKETS))
    time.sleep(5)
    child.sendcontrol('C')
    child.expect(r"\^C")
    match = re.search(r'(\d) packets transmitted', child.read())
    pytest_assert(int(match.group(1)) < TOTAL_PACKETS, "Escape Character does not work.")
