import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def check_auditd(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command("sudo systemctl is-active auditd")["stdout"]
    if output != "active":
        logger.info("auditd is not active. Restarting...")
        duthost.command("sudo systemctl restart auditd")
        output = duthost.command("sudo systemctl is-active auditd")["stdout"]
        pytest_assert(output == "active", "auditd service failed to start")

    yield

    output = duthost.command("sudo systemctl is-active auditd")["stdout"]
    if output != "active":
        logger.warning("auditd became inactive during the test. Restarting...")
        duthost.command("sudo systemctl restart auditd")
    pytest_assert(output == "active", "auditd service is not running after test")


@pytest.fixture(scope="module")
def check_auditd_failure(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    duthost.command("sudo systemctl stop auditd")
    output = duthost.command("sudo systemctl is-active auditd")["stdout"]
    pytest_assert(output != "active", "auditd service is still running when it should be inactive")

    yield

    duthost.command("sudo systemctl restart auditd")
    output = duthost.command("sudo systemctl is-active auditd")["stdout"]
    pytest_assert(output == "active", "auditd service did not restart after test")
