import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.dut_utils import is_container_running

pytestmark = [
    pytest.mark.topology('any'),
]

logger = logging.getLogger(__name__)


def test_container_privileged(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    is_running = is_container_running(duthost, "auditd")
    pytest_assert(is_running, "Container '{}' is not running. Exiting...".format(container_name))
