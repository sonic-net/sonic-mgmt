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
    out = duthost.shell('ls /dev/C0-*', module_ignore_errors=True)['stdout']
    ttys = set(out.split())
    pytest_assert(len(ttys) > 0, "No console tty devices been created by udev rule")

    out = duthost.console_facts()["ansible_facts"]["console_facts"]["lines"].keys()
    for i in out:
        expected_console_tty = "/dev/C0-{}".format(i)
        pytest_assert(
            expected_console_tty in ttys,
            "Expected console device [{}] not found.".format(expected_console_tty))
