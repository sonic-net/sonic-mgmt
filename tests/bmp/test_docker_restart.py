import pytest
import logging

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_restart_bmp_docker(duthosts,
                            enum_rand_one_per_hwsku_frontend_hostname,
                            enum_rand_one_frontend_asic_index):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asichost = duthost.asic_instance(enum_rand_one_frontend_asic_index)

    logger.info(duthost.shell(cmd="docker ps", module_ignore_errors=True)['stdout'])
    asichost.restart_service("bmp")
    logger.info(duthost.shell(cmd="docker ps", module_ignore_errors=True)['stdout'])

    logger.info("Wait until the system is stable")
    pytest_assert(wait_until(300, 20, 0, duthost.critical_services_fully_started),
                  "Not all critical services are fully started")
