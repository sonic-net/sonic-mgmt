"""
Test the running status of Monit service
"""
import logging

import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any')
]


def test_monit_status(duthost):
    monit_status_result = duthost.shell("sudo monit status", module_ignore_errors=True)

    exit_code = monit_status_result["rc"]
    pytest_assert(exit_code == 0, "Monit is either not running or not configured correctly")
