import re
import pytest
import logging
from tests.common.helpers.assertions import pytest_assert, pytest_require
from tests.common.helpers.dut_utils import is_container_running, get_disabled_container_list

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)

CONTAINER_NAME_REGEX = r"([a-zA-Z_-]+)(\d*)([a-zA-Z_-]+)(\d*)$"
# Skip testing on following containers
# db and pmon will be privileged hardening
# syncd, gbsyncd, and swss cannot be privileged hardening
PRIVILEGED_CONTAINERS = [
    "database",
    "pmon",
    "syncd",
    "gbsyncd",
    "swss",
]


def test_container_privileged(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index, enum_dut_feature):
    """
    Test container without --privileged flag has no access to /dev/vda* or /dev/sda*
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asic = duthost.asic_instance(enum_rand_one_asic_index)
    container_name = asic.get_docker_name(enum_dut_feature)
    disabled_containers = get_disabled_container_list(duthost)

    skip_condition = disabled_containers[:]
    skip_condition.extend(PRIVILEGED_CONTAINERS)
    # bgp0 -> bgp, bgp -> bgp, p4rt -> p4rt
    feature_name = ''.join(re.match(CONTAINER_NAME_REGEX, container_name).groups()[:-1])
    pytest_require(feature_name not in skip_condition, "Skipping test for container {}".format(feature_name))

    is_running = is_container_running(duthost, container_name)
    pytest_assert(is_running, "Container '{}' is not running. Exiting...".format(container_name))

    docker_exec_cmd = 'docker exec {} bash -c '.format(container_name)
    cmd = duthost.shell(docker_exec_cmd + "'mount | grep /etc/hosts' | awk '{print $1}'")
    rc, device = cmd['rc'], cmd['stdout']
    output = duthost.shell(docker_exec_cmd + "'ls {}'".format(device), module_ignore_errors=True)['stdout']

    pytest_assert(rc == 0, 'Failed to get the device name.')
    pytest_assert(device.startswith('/dev/'), 'Invalid device {}.'.format(device))
    pytest_assert(not output, 'The partition {} exists.'.format(device))
