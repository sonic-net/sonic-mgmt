import pytest

from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any')
]


def test_system_is_running(duthost):
    def is_system_ready(duthost):
        status = duthost.shell('sudo systemctl is-system-running', module_ignore_errors=True)['stdout']
        return status == "running"

    if not wait_until(180, 10, 0, is_system_ready, duthost):
        status = duthost.shell('sudo systemctl is-system-running', module_ignore_errors=True)['stdout']
        pytest.fail(f'System is not in "running" state in 180 s, current state: {status}')
