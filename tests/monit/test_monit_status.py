"""
Test the running status and format of alerting message of Monit service.
"""
import logging

import pytest
import random

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.assertions import pytest_require
from tests.common.helpers.monit import check_monit_expected_container_logging

logger = logging.getLogger(__name__)

MONIT_HOST_CONFIG = "/etc/monit/conf.d/sonic-host"
INODE_USAGE_ALERT = "if inode usage > 85% for 10 times within 20 cycles then alert repeat every 1 cycles"
MONIT_INODE_TEST_DIR = "/tmp/monit-inode-usage-test"
MONIT_INODE_TEST_MOUNT = "{}/filesystem".format(MONIT_INODE_TEST_DIR)
MONIT_INODE_TEST_CONFIG = "{}/monitrc".format(MONIT_INODE_TEST_DIR)
MONIT_INODE_TEST_SERVICE = "inode-usage-test"
MONIT_FILESYSTEM_HEALTHY_STATES = ("Accessible", "OK")

pytestmark = [
    pytest.mark.topology('any', 't1-multi-asic'),
    pytest.mark.disable_loganalyzer
]


@pytest.fixture
def stop_and_start_lldpmgrd(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Stops `lldpmgrd` process at setup stage and restarts it at teardwon.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
        a frontend DuT from testbed.

    Returns:
        None.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    if duthost.is_multi_asic:
        process = random.choice(["lldp0", "lldp1"])
    else:
        process = "lldp"

    logger.info("Stopping 'lldpmgrd' process in {} container ...".format(process))
    stop_command_result = duthost.command("docker exec {} supervisorctl stop lldpmgrd".format(process))
    exit_code = stop_command_result["rc"]
    pytest_assert(exit_code == 0, "Failed to stop 'lldpmgrd' process in {} container!".format(process))
    logger.info("'lldpmgrd' process in {} container is stopped.".format(process))

    yield

    logger.info("Starting 'lldpmgrd' process in {} container ...".format(process))
    start_command_result = duthost.command("docker exec {} supervisorctl start lldpmgrd".format(process))
    exit_code = start_command_result["rc"]
    pytest_assert(exit_code == 0, "Failed to start 'lldpmgrd' process in {} container!".format(process))
    logger.info("'lldpmgrd' process in {} container is started.".format(process))


def check_monit_last_output(duthost):
    """Checks whether alerting message appears as output of command 'monit status' if
    process `lldpmgrd` was stopped.

    Args:
        duthost: An AnsibleHost object of DuT.

    Returns:
        None.
    """
    monit_status_result = duthost.shell("sudo monit status 'lldp|lldpmgrd'", module_ignore_errors=True)
    exit_code = monit_status_result["rc"]
    pytest_assert(exit_code == 0, "Failed to get Monit status of process 'lldpmgrd'!")

    indices = [i for i, s in enumerate(monit_status_result["stdout_lines"]) if 'last output' in s]
    if len(indices) > 0:
        monit_last_output = monit_status_result["stdout_lines"][indices[0]]
        if duthost.is_multi_asic:
            return "/usr/bin/lldpmgrd' is not running in host and in namespace asic0" in monit_last_output
        else:
            return "/usr/bin/lldpmgrd' is not running in host" in monit_last_output
    else:
        return False


def get_inode_usage(duthost, filesystem_path):
    """Return used inodes, total inodes, and usage percentage for a filesystem."""
    inode_result = duthost.command("stat -f -c '%c %d' {}".format(filesystem_path))
    total_inodes, free_inodes = [int(value) for value in inode_result["stdout"].split()]
    used_inodes = total_inodes - free_inodes
    return used_inodes, total_inodes, used_inodes * 100.0 / total_inodes


def get_monit_filesystem_status(duthost):
    """Return the status of the isolated inode test filesystem."""
    status_result = duthost.shell(
        "sudo monit -c {} status -B '{}'".format(MONIT_INODE_TEST_CONFIG, MONIT_INODE_TEST_SERVICE),
        module_ignore_errors=True
    )
    if status_result["rc"] != 0:
        return None

    for line in status_result["stdout_lines"]:
        status_parts = line.strip().split(None, 1)
        if len(status_parts) == 2 and status_parts[0] == "status":
            return status_parts[1]
    return None


def check_monit_filesystem_status(duthost, expected_states):
    """Check whether the isolated inode test filesystem has an expected status."""
    return get_monit_filesystem_status(duthost) in expected_states


@pytest.fixture
def monit_inode_usage_test_environment(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Create an isolated filesystem and Monit instance for inode usage testing."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    filesystem_image = "{}/filesystem.img".format(MONIT_INODE_TEST_DIR)
    monit_config = """set daemon 1
set logfile {test_dir}/monit.log
set pidfile {test_dir}/monit.pid
set idfile {test_dir}/monit.id
set statefile {test_dir}/monit.state
set httpd unixsocket {test_dir}/monit.sock and
    allow localhost
check filesystem {service} with path {mount}
    {inode_alert}
""".format(test_dir=MONIT_INODE_TEST_DIR,
           service=MONIT_INODE_TEST_SERVICE,
           mount=MONIT_INODE_TEST_MOUNT,
           inode_alert=INODE_USAGE_ALERT)

    try:
        duthost.shell("sudo monit -c {} quit".format(MONIT_INODE_TEST_CONFIG), module_ignore_errors=True)
        duthost.shell("sudo umount -l {}".format(MONIT_INODE_TEST_MOUNT), module_ignore_errors=True)
        duthost.shell("sudo rm -rf {}".format(MONIT_INODE_TEST_DIR), module_ignore_errors=True)
        duthost.command("mkdir -p {}".format(MONIT_INODE_TEST_MOUNT))
        duthost.command("truncate -s 16M {}".format(filesystem_image))
        duthost.command("mkfs.ext4 -q -F -N 128 {}".format(filesystem_image))
        duthost.shell("sudo mount -o loop {} {}".format(filesystem_image, MONIT_INODE_TEST_MOUNT))
        duthost.copy(content=monit_config, dest=MONIT_INODE_TEST_CONFIG, mode="0600")
        duthost.shell("sudo chown root:root {}".format(MONIT_INODE_TEST_CONFIG))
        duthost.command("sudo monit -c {} -t".format(MONIT_INODE_TEST_CONFIG))
        duthost.command("sudo monit -c {}".format(MONIT_INODE_TEST_CONFIG))

        yield duthost
    finally:
        duthost.shell("sudo monit -c {} quit".format(MONIT_INODE_TEST_CONFIG), module_ignore_errors=True)
        duthost.shell("sudo umount -l {}".format(MONIT_INODE_TEST_MOUNT), module_ignore_errors=True)
        duthost.shell("sudo rm -rf {}".format(MONIT_INODE_TEST_DIR), module_ignore_errors=True)


def test_monit_status(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    """Checks whether the Monit service was running or not.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly picks up
        a frontend DuT from testbed.

    Returns:
        None.
    """
    logger.info("Checking the running status of Monit ...")

    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    def _monit_status():
        monit_status_result = duthost.shell("sudo monit status", module_ignore_errors=True)
        return monit_status_result["rc"] == 0
    # Monit is configured with start delay = 300s, hence we wait up to 320s here
    pytest_assert(wait_until(320, 20, 0, _monit_status),
                  "Monit is either not running or not configured correctly")

    logger.info("Checking the running status of Monit was done!")


@pytest.mark.parametrize("filesystem_name, filesystem_path", [
    ("root-overlay", "/"),
    ("var-log", "/var/log"),
    ("host-inodes", "/host"),
])
def test_monit_inode_usage_config(duthosts, enum_rand_one_per_hwsku_frontend_hostname,
                                  filesystem_name, filesystem_path):
    """Verify that Monit checks inode usage for each host filesystem."""
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    config_result = duthost.command("sudo cat {}".format(MONIT_HOST_CONFIG))
    config_lines = [line.strip() for line in config_result["stdout_lines"] if line.strip()]
    filesystem_header = "check filesystem {} with path {}".format(filesystem_name, filesystem_path)

    pytest_assert(filesystem_header in config_lines,
                  "Monit configuration is missing '{}'".format(filesystem_header))

    block_start = config_lines.index(filesystem_header)
    block_end = next((index for index, line in enumerate(config_lines[block_start + 1:], block_start + 1)
                      if line.startswith("check ")), len(config_lines))
    filesystem_config = config_lines[block_start:block_end]

    pytest_assert(filesystem_config.count(INODE_USAGE_ALERT) == 1,
                  "Monit filesystem '{}' must contain exactly one '{}' condition".format(
                      filesystem_name, INODE_USAGE_ALERT))


def test_monit_inode_usage_alert(monit_inode_usage_test_environment):
    """Verify Monit alerts above 85% inode usage and recovers below the threshold."""
    duthost = monit_inode_usage_test_environment

    pytest_assert(wait_until(30, 1, 0, check_monit_filesystem_status, duthost,
                             MONIT_FILESYSTEM_HEALTHY_STATES),
                  "Monit inode test filesystem did not reach a healthy state")

    used_inodes, total_inodes, inode_usage = get_inode_usage(duthost, MONIT_INODE_TEST_MOUNT)
    pytest_assert(inode_usage <= 85,
                  "Initial inode usage is unexpectedly {:.2f}%".format(inode_usage))

    target_used_inodes = (total_inodes * 90 + 99) // 100
    files_to_create = target_used_inodes - used_inodes
    duthost.shell(
        "sudo bash -c 'for inode in $(seq 1 {}); do touch {}/inode-${{inode}}; done'".format(
            files_to_create, MONIT_INODE_TEST_MOUNT)
    )

    _, _, inode_usage = get_inode_usage(duthost, MONIT_INODE_TEST_MOUNT)
    pytest_assert(inode_usage > 85,
                  "Failed to raise inode usage above 85%; current usage is {:.2f}%".format(inode_usage))
    pytest_assert(wait_until(30, 1, 0, check_monit_filesystem_status, duthost,
                             ("Resource limit matched",)),
                  "Monit did not alert at {:.2f}% inode usage; current status is '{}'".format(
                      inode_usage, get_monit_filesystem_status(duthost)))

    duthost.shell("sudo rm -f {}/inode-*".format(MONIT_INODE_TEST_MOUNT))
    _, _, inode_usage = get_inode_usage(duthost, MONIT_INODE_TEST_MOUNT)
    pytest_assert(inode_usage <= 85,
                  "Failed to restore inode usage below 85%; current usage is {:.2f}%".format(inode_usage))
    pytest_assert(wait_until(30, 1, 0, check_monit_filesystem_status, duthost,
                             MONIT_FILESYSTEM_HEALTHY_STATES),
                  "Monit did not recover after inode usage returned to {:.2f}%; current status is '{}'".format(
                      inode_usage, get_monit_filesystem_status(duthost)))


def test_monit_reporting_message(duthosts, enum_rand_one_per_hwsku_frontend_hostname, stop_and_start_lldpmgrd):
    """Checks whether the format of alerting message from Monit is correct or not.
       202012 and newer image version will be skipped for testing since Supervisord
       replaced Monit to do the monitoring critical processes.

    Args:
        duthosts: The fixture returns list of DuTs.
        enum_rand_one_per_hwsku_frontend_hostname: The fixture randomly pick up
        a frontend DuT from testbed.
        disable_lldp: The fixture function stops `lldpmgrd` process before testing
        and restarts `lldpmgrd` process at teardown.

    Returns:
        None.
    """
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]

    pytest_require("201811" in duthost.os_version or "201911" in duthost.os_version,
                   "Test is not supported for 202012 and newer image versions!")

    logger.info("Checking the format of Monit alerting message ...")

    pytest_assert(wait_until(180, 60, 0, check_monit_last_output, duthost),
                  "Expected Monit reporting message not found")
    pytest_assert(wait_until(180, 60, 0, check_monit_expected_container_logging, duthost),
                  "Monit logged unexpected container-not-running messages")
    logger.info("Checking the format of Monit alerting message was done!")
