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

    out = duthost.shell('redis-cli -n 4 keys CONSOLE_PORT* | grep -oP \'(?<=CONSOLE_PORT\|)[0-9]+\'', module_ignore_errors=True)['stdout']
    for i in out.split():
        expected_virtual_tty = "/dev/ttyUSB{}".format(int(i)-1)
        pytest_assert(
            expected_virtual_tty in ttys,
            "Expected virtual tty device [{}] not found.".format(expected_virtual_tty))
