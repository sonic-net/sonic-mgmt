import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]

logger = logging.getLogger(__name__)


def test_bgp_dev(duthost):
    """
    Test bgp container has no access to /dev/vda*
    """
    output = duthost.shell("docker exec bgp bash -c 'ls /dev | grep vda'", module_ignore_errors=True)['stdout']
    pytest_assert(not output, 'vda is not removed from /dev')

