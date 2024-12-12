import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.helper.bmp_utils import BMPEnvironment

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.bmp_required,
    pytest.mark.topology('t2')
]


def test_restart_bmp_docker(duthosts,
                               enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    logger.info(duthost.shell(cmd="docker ps", module_ignore_errors=True)['stdout'])
    duthost.restart_service("bmp")
    logger.info(duthost.shell(cmd="docker ps", module_ignore_errors=True)['stdout'])
