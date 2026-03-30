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
# The following containers are allowed to run in privileged mode
PRIVILEGED_CONTAINERS = [
    "syncd",
    "gbsyncd",
    # gnmi is temporarily in privileged mode, remove when
    # https://github.com/sonic-net/sonic-buildimage/issues/24542 is closed
    "gnmi",
]

# The following containers are allowed to have block devices mounted.
# This will be a superset of privileged containers
CONTAINERS_WITH_BLOCKDEVICE_MOUNT = PRIVILEGED_CONTAINERS + [
    "pmon",
]


def get_base_container_name(container_name):
    """
    Extract the base feature name from a container name.
    e.g., bgp0 -> bgp, syncd1 -> syncd, p4rt -> p4rt
    """
    match = re.match(CONTAINER_NAME_REGEX, container_name)
    if match:
        return ''.join(match.groups()[:-1])
    return container_name


def test_container_block_device_mounted(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index,
                                        enum_dut_feature):
    """
    Test only containers allowed have access to block devices such as /dev/vda*, /dev/sda*, /dev/nvme0n1*
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asic = duthost.asic_instance(enum_rand_one_asic_index)
    container_name = asic.get_docker_name(enum_dut_feature)
    disabled_containers = get_disabled_container_list(duthost)

    skip_condition = disabled_containers[:]
    skip_condition.extend(CONTAINERS_WITH_BLOCKDEVICE_MOUNT)
    # bgp0 -> bgp, bgp -> bgp, p4rt -> p4rt
    feature_name = get_base_container_name(container_name)
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

    # Not only the partition needs to be checked but also the base block device.
    # If the base block device is there you can access all the partitions.
    base_device = re.sub(r'p\d+$', '', device)  # e.g., /dev/nvme0n1p3 -> /dev/nvme0n1
    if base_device == device:
        base_device = re.sub(r'\d+$', '', device)  # e.g., /dev/sda3 -> /dev/sda
    base_output = duthost.shell(docker_exec_cmd + "'ls {}'".format(base_device), module_ignore_errors=True)['stdout']
    pytest_assert(not base_output, 'The base block device {} exists.'.format(base_device))


def test_container_privileged(duthosts, enum_rand_one_per_hwsku_hostname):
    """
    Test that no containers are running in privileged mode except those explicitly allowed.

    Uses 'docker inspect' to check the privileged status of all running containers
    and fails if any container not in PRIVILEGED_CONTAINERS is running with --privileged.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Get all running containers
    running_containers = duthost.shell(
        r"docker ps -f 'status=running' --format \{\{.Names\}\}"
    )['stdout_lines']
    pytest_assert(running_containers, "No running containers found on DUT")

    # Check privileged status for each container using docker inspect
    unauthorized_privileged = []
    for container_name in running_containers:
        result = duthost.shell(
            r"docker inspect --format \{\{.HostConfig.Privileged\}\} " + container_name
        )
        is_privileged = result['stdout'].strip().lower() == 'true'

        if is_privileged:
            base_name = get_base_container_name(container_name)
            if base_name not in PRIVILEGED_CONTAINERS:
                logger.error("Container '{}' is running in privileged mode but is not allowed".format(container_name))
                unauthorized_privileged.append(container_name)
            else:
                logger.info("Container '{}' is privileged (as expected)".format(container_name))

    pytest_assert(
        not unauthorized_privileged,
        "The following containers are running in privileged mode but are not allowed: {}".format(
            unauthorized_privileged
        )
    )
