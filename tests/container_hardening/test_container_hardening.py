import re
import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

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


def get_base_container_name(container_name):
    """
    Extract the base feature name from a container name.
    e.g., bgp0 -> bgp, syncd1 -> syncd, p4rt -> p4rt
    """
    match = re.match(CONTAINER_NAME_REGEX, container_name)
    if match:
        return ''.join(match.groups()[:-1])
    return container_name


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
