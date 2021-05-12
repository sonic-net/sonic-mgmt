import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

def test_console_driver(duthost):
    """
    Test console driver are well installed.
    Verify ttyUSB(0-47) are presented in DUT
    """
    out = duthost.shell('ls /dev/ttyUSB*')['stdout']
    pytest_assert(
        "No such file or directory" not in out,
        "No virtual tty devices been created by console driver")

    ttys = set(out.split())
    for i in range(48):
        expected_virtual_tty = "/dev/ttyUSB{}".format(i)
        pytest_assert(
            expected_virtual_tty in ttys,
            "Expected virtual tty device [{}] not found.".format(expected_virtual_tty))
