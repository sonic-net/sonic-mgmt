import pytest
import logging
from tests.common.constants import RESOLV_CONF_NAMESERVERS
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_image_type

pytestmark = [
    pytest.mark.topology("any")
]

logger = logging.getLogger(__name__)


def test_dns_resolv_conf(duthost):
    """verify that /etc/resolv.conf contains the expected nameservers

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Check SONiC image type and get expected nameservers in /etc/resolv.conf
    expected_nameservers = set(RESOLV_CONF_NAMESERVERS[get_image_type(duthost=duthost)])

    logger.info("expected nameservers: [{}]".format(" ".join(expected_nameservers)))

    resolv_conf = duthost.shell("cat /etc/resolv.conf", module_ignore_errors=True)
    pytest_assert(resolv_conf["rc"] == 0, "Failed to read /etc/resolf.conf!")
    current_nameservers = []
    for resolver_line in resolv_conf["stdout_lines"]:
        if not resolver_line.startswith("nameserver"):
            continue
        current_nameservers.append(resolver_line.split()[1])

    current_nameservers = set(current_nameservers)

    logger.info("current nameservers: [{}]".format(" ".join(current_nameservers)))

    pytest_assert(not (current_nameservers ^ expected_nameservers),
                  "Mismatch between expected and current nameservers! Expected: [{}]. Current: [{}].".format(
                  " ".join(expected_nameservers), " ".join(current_nameservers)))


def test_dns_resolv_conf_container(duthost):
    """verify that /etc/resolv.conf in container contains the expected nameservers

    Args:
        duthost: AnsibleHost instance for DUT
    """

    # If running a public image with sonic-mgmt-int, we can't say for sure whether we should expect there to not be any
    # DNS servers configured in /etc/resolv.conf, or whether the internal DNS should be configured. This is becuase
    # pretest configures the internal DNS server, but if there's some system reload/reboot, then this may go away/be
    # overwritten.
    #
    # There are some changes that might improve the state of things (resolvconf, config_db support), but for now, just
    # skip this combination.
    if get_image_type(duthost) == "public":
        pytest.skip("Inconsistent expectations for DNS server when running a public image with sonic-mgmt-int")

    # Check SONiC image type and get expected nameservers in /etc/resolv.conf
    expected_nameservers = set(RESOLV_CONF_NAMESERVERS[get_image_type(duthost=duthost)])

    logger.info("expected nameservers: [{}]".format(" ".join(expected_nameservers)))

    containers = duthost.get_running_containers()
    for container in containers:
        resolv_conf = duthost.shell("docker exec %s cat /etc/resolv.conf" % container, module_ignore_errors=True)
        pytest_assert(resolv_conf["rc"] == 0, "Failed to read /etc/resolf.conf!")
        current_nameservers = []
        for resolver_line in resolv_conf["stdout_lines"]:
            if not resolver_line.startswith("nameserver"):
                continue
            current_nameservers.append(resolver_line.split()[1])

        current_nameservers = set(current_nameservers)

        logger.info("{} container, current nameservers: [{}]".format(container, " ".join(current_nameservers)))

        pytest_assert(not (current_nameservers ^ expected_nameservers),
                    "Mismatch between expected and current nameservers for {}! Expected: [{}]. Current: [{}].".format(
                    container, " ".join(expected_nameservers), " ".join(current_nameservers)))
