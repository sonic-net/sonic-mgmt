"""
Some devices have potential problems entering idle state. We
expect to disable both intel idle driver and acpi idle driver,
or have no available idle state higher than 1 for all cpu.
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
    idle_driver = duthost.shell('cat /sys/devices/system/cpu/cpuidle/current_driver')['stdout']
    if idle_driver != "none":
        cstates = duthost.shell('sed -n "s/.*C\([0-9]*\).*/\\1/p" /sys/devices/system/cpu/cpu*/cpuidle/state*/name')['stdout'].split()
        max_cstate = max([int(cstate) for cstate in cstates])
        pytest_assert(max_cstate <= 1,
                "When idle driver is present, cstate higher than 1 is not allowed: max_cstate {}".format(max_cstate))
