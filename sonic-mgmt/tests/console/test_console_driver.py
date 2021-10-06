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
    out = duthost.shell('ls /dev/ttyUSB*', module_ignore_errors=True)['stdout']
    ttys = set(out.split())
    pytest_assert(len(ttys) > 0, "No virtual tty devices been created by console driver")

    out = duthost.console_facts()["ansible_facts"]["console_facts"]["lines"].keys()
    for i in range(0, len(out)):
        expected_virtual_tty = "/dev/ttyUSB{}".format(i)
        pytest_assert(
            expected_virtual_tty in ttys,
            "Expected virtual tty device [{}] not found.".format(expected_virtual_tty))
