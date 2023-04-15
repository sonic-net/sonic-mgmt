import pytest

from tests.common.utilities import wait_until

pytestmark = [
    pytest.mark.topology('any')
]


def test_system_is_running(duthost):
    def is_system_ready(duthost):
        status = duthost.shell('sudo systemctl is-system-running', module_ignore_errors=True)['stdout']
        return status != "starting"

    if not wait_until(180, 10, 0, is_system_ready, duthost):
        pytest.fail('Failed to find routed interface in 180 s')
