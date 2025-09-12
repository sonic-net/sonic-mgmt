import os
import pytest
import logging
from tests.common.helpers.dut_utils import is_container_running
from tests.common.helpers.assertions import pytest_assert as py_assert

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module")
def check_auditd(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.command("sudo systemctl is-active auditd", module_ignore_errors=True)["stdout"]
    if output != "active":
        logger.info("auditd is not active. Restarting...")
        duthost.command("sudo systemctl restart auditd")
        output = duthost.command("sudo systemctl is-active auditd")["stdout"]
        py_assert(output == "active", "auditd service failed to start")

    yield

    output = duthost.command("sudo systemctl is-active auditd", module_ignore_errors=True)["stdout"]
    if output != "active":
        logger.warning("auditd became inactive during the test. Restarting...")
        duthost.command("sudo systemctl restart auditd")
        output = duthost.command("sudo systemctl is-active auditd")["stdout"]
        py_assert(output == "active", "auditd service is not running after test")


@pytest.fixture(scope="function")
def check_auditd_failure(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    duthost.command("sudo systemctl stop auditd")
    output = duthost.command("sudo systemctl is-active auditd", module_ignore_errors=True)["stdout"]
    py_assert(output != "active", "auditd service is still running when it should be inactive")

    yield

    duthost.command("sudo systemctl restart auditd")
    output = duthost.command("sudo systemctl is-active auditd", module_ignore_errors=True)["stdout"]
    py_assert(output == "active", "auditd service did not restart after test")


@pytest.fixture(scope="function")
def check_auditd_failure_32bit(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    test_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "32-test.rules")
    duthost.copy(src=test_path, dest="/etc/audit/rules.d/32-test.rules")
    duthost.shell("sudo systemctl restart auditd")

    yield

    duthost.command("sudo rm -f /etc/audit/rules.d/32-test.rules")
    duthost.command("sudo systemctl restart auditd")


@pytest.fixture(scope="module")
def reset_auditd_rate_limit(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    # Backup the rules file
    duthost.command("sudo cp /etc/audit/rules.d/audit.rules /tmp/audit.rules_backup")
    logger.info("Backed up audit.rules")

    # Set runtime rate limit to 0 so auditd logs will not be dropped
    duthost.command("sudo auditctl -r 0")
    logger.info("Set auditctl runtime rate limit to 0")

    yield

    # Restore rules file and restart auditd
    duthost.command("sudo cp /tmp/audit.rules_backup /etc/audit/rules.d/audit.rules")
    duthost.command("sudo service auditd restart")
    logger.info("Restored audit.rules from backup and restarted auditd")


@pytest.fixture(scope="module")
def verify_auditd_containers_running(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    for container in ["auditd", "auditd_watchdog"]:
        if not is_container_running(duthost, container):
            pytest.skip(f"Container {container} is not running")
