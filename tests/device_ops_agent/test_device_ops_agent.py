import pytest
import logging
from tests.common.helpers.assertions import pytest_assert

pytestmark = [
    pytest.mark.disable_loganalyzer,
    pytest.mark.topology('any'),
    pytest.mark.skip_check_dut_health
]

logger = logging.getLogger(__name__)

CONTAINER_NAME = "device-ops-agent"


def test_container_running(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify device-ops-agent container is running."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    # Use -q flag to avoid Ansible/Jinja2 template conflicts with Go's {{.Status}} format
    output = duthost.shell("docker ps --filter name={} --filter status=running -q".format(CONTAINER_NAME),
                           module_ignore_errors=True)
    pytest_assert("stdout" in output, "shell command failed: {}".format(output.get("msg", "unknown error")))
    pytest_assert(output["stdout"].strip() != "", "{} container is not running".format(CONTAINER_NAME))


def test_supervisord_status(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify all supervisord processes are running."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.shell("docker exec {} supervisorctl status".format(CONTAINER_NAME),
                           module_ignore_errors=True)
    pytest_assert("stdout" in output, "shell command failed: {}".format(output.get("msg", "unknown error")))
    pytest_assert(output["rc"] == 0, "supervisorctl status command failed")
    stdout = output["stdout"]
    logger.info("supervisorctl status output: {}".format(stdout))
    for line in stdout.splitlines():
        pytest_assert("FATAL" not in line, "Process in FATAL state: {}".format(line))
        pytest_assert("EXITED" not in line, "Process in EXITED state: {}".format(line))


def test_agent_process_running(duthosts, enum_rand_one_per_hwsku_hostname):
    """Verify device-ops-agent process is running inside the container."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    output = duthost.shell("docker exec {} pgrep -f device-ops-agent".format(CONTAINER_NAME),
                           module_ignore_errors=True)
    pytest_assert("stdout" in output, "shell command failed: {}".format(output.get("msg", "unknown error")))
    pytest_assert(output["rc"] == 0, "device-ops-agent process is not running in the container")
    pytest_assert(output["stdout"].strip() != "", "No PID found for device-ops-agent process")
