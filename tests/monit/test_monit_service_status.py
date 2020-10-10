"""
Test the running status of Monit service
"""
import logging

import pytest

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_monit_service_status(duthost):
    """
    @summary: Test the running status of Monit service by analyzing the command
              output of "sudo systemctl status monit.service | grep Active".
    """
    monit_service_status_info = duthost.shell("sudo monit status", module_ignore_erros=True)

    exit_code = monit_service_status_info["rc"]
    if exit_code == 0:
        logger.info("Monit service is running.")
    else:
        pytest.fail("Monit service is not running.")
