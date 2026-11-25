import re
import shlex
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


def _log_hosts_mount_diagnostics(duthost, container_name):
    container = shlex.quote(container_name)
    probes = (
        ("hosts mountinfo",
         "timeout -k 1 5 docker exec {} awk '$5 == \"/etc/hosts\"' /proc/self/mountinfo".format(container)),
        ("container ID", r"timeout -k 1 5 docker inspect --format \{\{.Id\}\} " + container),
    )
    for label, command in probes:
        result = duthost.shell(command, module_ignore_errors=True)
        logger.error("Container %s %s: rc=%s stdout=%r stderr=%r",
                     container_name, label, result.get('rc'),
                     (result.get('stdout') or '')[:2048], (result.get('stderr') or '')[:2048])


@pytest.fixture
def block_device_test_container(duthosts, enum_rand_one_per_hwsku_hostname, enum_rand_one_asic_index,
                                enum_dut_feature, vendor_specific_privileged_containers):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    asic = duthost.asic_instance(enum_rand_one_asic_index)
    container_name = asic.get_docker_name(enum_dut_feature)
    disabled_containers = get_disabled_container_list(duthost)

    skip_condition = disabled_containers[:]
    skip_condition.extend(CONTAINERS_WITH_BLOCKDEVICE_MOUNT + vendor_specific_privileged_containers)
    # bgp0 -> bgp, bgp -> bgp, p4rt -> p4rt
    feature_name = get_base_container_name(container_name)
    pytest_require(feature_name not in skip_condition, "Skipping test for container {}".format(feature_name))

    is_running = is_container_running(duthost, container_name)
    pytest_assert(is_running, "Prerequisite failed: container '{}' is not running. "
                  "Check DUT feature configuration and preceding test cleanup.".format(container_name))
    return duthost, container_name


def test_container_block_device_mounted(block_device_test_container):
    """
    Test only containers allowed have access to block devices such as /dev/vda*, /dev/sda*, /dev/nvme0n1*
    """
    duthost, container_name = block_device_test_container

    docker_exec_cmd = 'docker exec {} '.format(shlex.quote(container_name))
    mount_result = duthost.shell(docker_exec_cmd + 'mount', module_ignore_errors=True)
    mount_ok = not mount_result.get('failed') and mount_result.get('rc') == 0
    devices = re.findall(r'^(\S+) on /etc/hosts type ', mount_result.get('stdout') or '', re.MULTILINE)
    device_ok = len(devices) == 1 and devices[0].startswith('/dev/')
    if not mount_ok or not device_ok:
        _log_hosts_mount_diagnostics(duthost, container_name)

    pytest_assert(mount_ok,
                  "Failed to read mounts in container '{}': rc={}, stderr={!r}".format(
                      container_name, mount_result.get('rc'), mount_result.get('stderr')))
    pytest_assert(device_ok,
                  "Expected one /dev/ mount source for /etc/hosts in container '{}', got {!r}".format(
                      container_name, devices))

    device = devices[0]
    output = duthost.shell(docker_exec_cmd + 'ls ' + shlex.quote(device), module_ignore_errors=True)['stdout']
    pytest_assert(not output, 'The partition {} exists.'.format(device))

    # Not only the partition needs to be checked but also the base block device.
    # If the base block device is there you can access all the partitions.
    base_device = re.sub(r'p\d+$', '', device)  # e.g., /dev/nvme0n1p3 -> /dev/nvme0n1
    if base_device == device:
        base_device = re.sub(r'\d+$', '', device)  # e.g., /dev/sda3 -> /dev/sda
    base_output = duthost.shell(
        docker_exec_cmd + 'ls ' + shlex.quote(base_device), module_ignore_errors=True)['stdout']
    pytest_assert(not base_output, 'The base block device {} exists.'.format(base_device))


def test_container_privileged(duthosts, enum_rand_one_per_hwsku_hostname,
                              vendor_specific_privileged_containers):
    """
    Test that no containers are running in privileged mode except those explicitly allowed.

    Uses 'docker inspect' to check the privileged status of all running containers
    and fails if any container not in PRIVILEGED_CONTAINERS is running with --privileged.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    allowed_privileged = PRIVILEGED_CONTAINERS + vendor_specific_privileged_containers

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
            if base_name not in allowed_privileged:
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
