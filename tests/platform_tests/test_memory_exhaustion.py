import pytest

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any')
]


def test_memory_exhaustion(duthosts, enum_frontend_dut_hostname):
    """validate kernel will panic and reboot the DUT when runs out of memory and hits oom event"""

    duthost = duthosts[enum_frontend_dut_hostname]
    duthost.shell('tail /dev/zero')
    pytest_assert(wait_until(300, 5, 60, check_uptime_less_than, duthost, 10),
                  "kernel didn't reboot or no response")


def check_uptime_less_than(dut, target):
    return dut.get_uptime().total_seconds() < target
