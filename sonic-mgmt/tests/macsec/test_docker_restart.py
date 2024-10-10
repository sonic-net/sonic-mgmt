import pytest
import logging

from tests.common.utilities import wait_until
from .macsec_helper import check_appl_db

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology('t2')
]


def test_restart_macsec_docker(duthosts, ctrl_links, policy, cipher_suite, send_sci,
                               enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    logger.info(duthost.shell(cmd="docker ps", module_ignore_errors=True)['stdout'])
    duthost.restart_service("macsec")
    logger.info(duthost.shell(cmd="docker ps", module_ignore_errors=True)['stdout'])
    assert wait_until(300, 6, 12, check_appl_db, duthost, ctrl_links, policy, cipher_suite, send_sci)
