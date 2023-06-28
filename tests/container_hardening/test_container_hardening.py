import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


def test_bgp_dev(duthost):
    """
    Test bgp container has no access to /dev/vda* or /dev/sda*
    """
    cmd = duthost.shell("docker exec bgp bash -c 'df -h | grep /etc/hosts' | awk '{print $1}'")
    rc, device = cmd['rc'], cmd['stdout']
    if rc != 0:
        pytest_assert(False, 'Failed to get the device name.')
    if not device.startswith('/dev/'):
        pytest_assert(False, 'Invalid device {}.'.format(device))
    output = duthost.shell("docker exec bgp bash -c 'ls {}'".format(device), module_ignore_errors=True)['stdout']
    pytest_assert(not output, 'The partition {} exists.'.format(device))
