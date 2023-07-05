import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


def test_container_privileged(duthost):
    """
    Test container without --privileged flag has no access to /dev/vda* or /dev/sda*
    """
    container_names = duthost.shell(r'docker ps -a --format \{\{.Names\}\}')['stdout_lines']
    for container_name in container_names:
        if container_name == 'bgp':
            docker_exec_cmd = 'docker exec {} bash -c '.format(container_name)
            cmd = duthost.shell(docker_exec_cmd + "'df -h | grep /etc/hosts' | awk '{print $1}'")
            rc, device = cmd['rc'], cmd['stdout']
            pytest_assert(rc == 0, 'Failed to get the device name.')
            pytest_assert(device.startswith('/dev/'), 'Invalid device {}.'.format(device))
            output = duthost.shell(docker_exec_cmd + "'ls {}'".format(device), module_ignore_errors=True)['stdout']
            pytest_assert(not output, 'The partition {} exists.'.format(device))
