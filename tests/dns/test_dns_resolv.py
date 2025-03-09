import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_image_type

pytestmark = [
    pytest.mark.topology("t0", "t1", "m0", "mx")
]

logger = logging.getLogger(__name__)

GITHUB_URL = "www.github.com"


def test_dns_resolv(duthost):
    """verify that dns nameservers are working as expected

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

    # Configured DNS servers do not work on KVM platform
    if 'kvm' in duthost.facts['platform']:
        pytest.skip("Skip test on KVM platform")

    resolv_conf = duthost.shell("cat /etc/resolv.conf", module_ignore_errors=True)
    pytest_assert(resolv_conf["rc"] == 0, "Failed to read /etc/resolv.conf!")
    nameservers = set()
    for resolver_line in resolv_conf["stdout_lines"]:
        # Check if the line starts with "nameserver" to identify DNS server entries
        if not resolver_line.startswith("nameserver"):
            continue
        nameservers.add(resolver_line.split()[1])
    logger.info(f"current nameservers: [{' '.join(nameservers)}]")
    result = duthost.shell(f"getent hosts {GITHUB_URL}", module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, f"Failed to resolve {GITHUB_URL}!")
    logger.info(f"Resolve result: [{' '.join(result['stdout_lines'])}]")
