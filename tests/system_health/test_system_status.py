import pytest

from tests.common.utilities import wait_until
from .test_system_health import wait_system_health_boot_up

pytestmark = [
    pytest.mark.topology('any')
]


def test_system_is_running(duthost):
    def is_system_ready(duthost):
        status = duthost.shell('sudo systemctl is-system-running', module_ignore_errors=True)['stdout']
        return status != "starting"

    if not wait_until(180, 10, 0, is_system_ready, duthost):
        pytest.fail('Failed to find routed interface in 180 s')


def test_system_health_sysready_status(duthosts, enum_rand_one_per_hwsku_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]
    wait_system_health_boot_up(duthost)

    # This gives just one line, "System is ready" or "System is not ready - <reason>"
    sysready_status_br = duthost.command("show system-health sysready-status brief")['stdout_lines']
    assert "System is ready" in sysready_status_br[0]

    # This gives a table with all the details, so we'll check the summary and that
    # all the services are "OK"
    sysready_status = duthost.command("show system-health sysready-status")['stdout_lines']
    assert "System is ready" in sysready_status[0]

    # Skip the 4 lines of summary + header
    assert len(sysready_status) > 4
    for line in sysready_status[4:]:
        columns = line.split()

        assert len(columns) == 4, f"Line {line} has {len(columns)} columns, expected 4"
        assert columns[1] == "OK" and columns[2] == "OK", f"Service {columns[0]} is not OK, reason: {columns[3]}"
