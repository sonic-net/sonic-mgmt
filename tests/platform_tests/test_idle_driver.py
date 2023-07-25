"""
Some devices have potential problems entering idle state. So
on m0 devices, we expect to disable both intel idle driver
and acpi idle driver, and no available idle state for all cpu.
"""
import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('m0', 'mx'),
]

def test_idle_driver(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    is_intel = 'Intel' in duthost.shell('lscpu | grep Vendor')['stdout']
    if not is_intel:
        pytest.skip('CPU vendor is not Intel')
    idle_driver = duthost.shell('cat /sys/devices/system/cpu/cpuidle/current_driver')['stdout']
    pytest_assert(idle_driver == 'none', 'Idle driver {} is active on this m0 device'.format(idle_driver))
    cpuidle = duthost.command('ls /sys/devices/system/cpu/cpu0/cpuidle/', module_ignore_errors=True)['rc']
    pytest_assert(cpuidle == 2, "cpuidle directory should not exist: rc {}".format(cpuidle))
