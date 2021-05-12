import pytest

from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any')
]

def test_console_port_mapping(duthost):
    """
    Test udev rule are working as expect.
    Verify C0-(1-48) are presented in DUT
    """
    out = duthost.shell('ls /dev/C0-*')['stdout']
    pytest_assert(
        "No such file or directory" not in out,
        "No console tty devices been created by udev rule")

    ttys = set(out.split())
    for i in range(1, 49):
        expected_virtual_tty = "/dev/C0-{}".format(i)
        pytest_assert(
            expected_virtual_tty in ttys,
            "Expected console device [{}] not found.".format(expected_virtual_tty))
